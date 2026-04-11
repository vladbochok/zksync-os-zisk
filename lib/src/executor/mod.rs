//! REVM-based block executor for ZKsync OS with merkle proof verification.
//!
//! Every storage and account read is verified against a merkle proof that
//! recovers the expected state root. Values come FROM the proofs, not from
//! a separate data path.

mod evm;
mod proven_db;
mod tx;
mod verify;

use std::collections::HashMap;

use revm::database::CacheDB;
use revm::primitives::B256;
use zksync_os_revm::ZkSpecId;

use crate::commitment;
use crate::types::*;

/// Execute a batch with full merkle proof verification and compute the
/// BatchPublicInput hash matching the server/L1 format.
pub fn execute_and_commit(input: &BatchInput) -> (BatchOutput, B256) {
    let (output, commitment, _, _, _) = execute_and_commit_inner(input);
    (output, commitment)
}

/// Same as `execute_and_commit` but also returns the three commitment
/// sub-components for debugging.
pub fn execute_and_commit_debug(input: &BatchInput) -> (BatchOutput, B256, B256, B256, B256) {
    execute_and_commit_inner(input)
}

fn execute_and_commit_inner(input: &BatchInput) -> (BatchOutput, B256, B256, B256, B256) {
    let spec_id = match input.spec_id {
        0 => ZkSpecId::AtlasV1,
        1 => ZkSpecId::AtlasV2,
        _ => panic!("unknown spec_id: {}", input.spec_id),
    };

    let meta = &input.batch_meta;
    validate_block_sequence(input);

    // Execute all blocks with merkle-verified state.
    let proven_db = proven_db::build_proven_db(input);
    let mut cache_db = CacheDB::new(proven_db);

    let mut block_results = Vec::with_capacity(input.blocks.len());
    let mut computed_block_hashes: HashMap<u64, B256> = HashMap::new();

    for block in &input.blocks {
        verify_intra_batch_hashes(block, &computed_block_hashes);

        let result = evm::execute_block_proven(
            input.chain_id, spec_id, block, &mut cache_db,
        );
        computed_block_hashes.insert(block.number, result.computed_block_header_hash);
        block_results.push(result);
    }

    let output = BatchOutput { chain_id: input.chain_id, block_results };

    // Build complete write map (storage + 0x8003 account properties) and verify.
    let revm_writes = verify::build_revm_write_map(&cache_db, &meta.account_preimages_after);
    let (tree_root_after, new_leaf_count) = verify::verify_tree_update(meta, &revm_writes);

    // State before.
    let state_before = commitment::state_commitment_hash(
        &meta.tree_root_before, meta.leaf_count_before,
        meta.block_number_before, &meta.block_hashes_blake_before,
        meta.last_block_timestamp_before,
    );

    // State after.
    let last_block = input.blocks.last().unwrap();
    let last_block_result = output.block_results.last().unwrap();
    let block_hashes_blake_after = commitment::block_hashes_blake(
        &meta.previous_block_hashes,
        &last_block_result.computed_block_header_hash,
    );
    let state_after = commitment::state_commitment_hash(
        &tree_root_after, new_leaf_count,
        last_block.number, &block_hashes_blake_after, last_block.timestamp,
    );

    // Batch output hash
    let mut l1_tx_hashes = Vec::new();
    let mut l2_to_l1_encoded_logs = Vec::new();
    let mut num_l1_txs: u64 = 0;
    let mut num_l2_txs: u64 = 0;

    for block in &input.blocks {
        for tx in &block.transactions {
            match &tx.auth {
                TxAuth::L1 { tx_hash, .. } => {
                    l1_tx_hashes.push(*tx_hash);
                    num_l1_txs += 1;
                }
                TxAuth::Upgrade { tx_hash, .. } => {
                    assert_eq!(
                        *tx_hash, meta.upgrade_tx_hash,
                        "upgrade tx hash {tx_hash} != batch_meta.upgrade_tx_hash {}",
                        meta.upgrade_tx_hash
                    );
                }
                TxAuth::L2 { .. } => {
                    num_l2_txs += 1;
                }
            }
        }
    }
    for br in &output.block_results {
        for log in &br.l2_to_l1_logs {
            l2_to_l1_encoded_logs.push(log.encode());
        }
    }

    let priority_ops_hash = commitment::priority_ops_rolling_hash(&l1_tx_hashes);
    let l2_logs_local_root = commitment::l2_to_l1_logs_root(&l2_to_l1_encoded_logs);
    // For protocol v30, multichain_root is zero in the l2_logs_root computation.
    // For v31+, use the actual multichain_root.
    let effective_multichain_root = if input.protocol_version_minor >= 31 {
        meta.multichain_root
    } else {
        B256::ZERO
    };
    let l2_logs_root_hash = commitment::keccak_two(&l2_logs_local_root, &effective_multichain_root);

    let da_commitment = match meta.da_commitment_scheme {
        0 | 1 => B256::ZERO,                                          // None / EmptyNoDA
        2 | 3 => commitment::da_commitment_calldata(&meta.pubdata),       // PubdataKeccak / BlobsAndPubdataKeccak
        4 => commitment::da_commitment_blobs(&meta.blob_versioned_hashes), // BlobsZKsyncOS
        _ => panic!("unsupported DA commitment scheme: {}", meta.da_commitment_scheme),
    };

    let batch_hash = if input.protocol_version_minor >= 31 {
        commitment::batch_output_hash_v31(
            input.chain_id,
            input.blocks.first().unwrap().timestamp,
            last_block.timestamp,
            meta.da_commitment_scheme,
            &da_commitment,
            num_l1_txs,
            num_l2_txs,
            &priority_ops_hash,
            &l2_logs_root_hash,
            &meta.upgrade_tx_hash,
            &B256::ZERO,
            meta.sl_chain_id,
        )
    } else {
        commitment::batch_output_hash_v30(
            input.chain_id,
            input.blocks.first().unwrap().timestamp,
            last_block.timestamp,
            meta.da_commitment_scheme,
            &da_commitment,
            num_l1_txs,
            &priority_ops_hash,
            &l2_logs_root_hash,
            &meta.upgrade_tx_hash,
            &B256::ZERO,
        )
    };

    let commitment = commitment::batch_public_input_hash(&state_before, &state_after, &batch_hash);
    (output, commitment, state_before, state_after, batch_hash)
}

fn validate_block_sequence(input: &BatchInput) {
    let meta = &input.batch_meta;
    assert!(!input.blocks.is_empty(), "batch must contain at least one block");
    assert!(
        input.blocks[0].number == meta.block_number_before + 1,
        "first block number {} must follow block_number_before {}",
        input.blocks[0].number, meta.block_number_before,
    );
    for w in input.blocks.windows(2) {
        assert!(w[1].number == w[0].number + 1, "block numbers must be consecutive");
        assert!(w[1].timestamp >= w[0].timestamp, "block timestamps must be non-decreasing");
    }
}

fn verify_intra_batch_hashes(block: &BlockInput, computed: &HashMap<u64, B256>) {
    for &(num, hash) in &block.block_hashes {
        if let Some(&expected) = computed.get(&num) {
            assert_eq!(hash, expected,
                "intra-batch block hash mismatch for block {num}: \
                 server={hash}, computed={expected}");
        }
    }
}

/// Execute a batch from bincode-serialized BatchInput bytes.
/// Returns the output and batch commitment hash.
/// Used by the server to compute ZiSK commitments in-process.
pub fn execute_and_commit_from_bincode(
    bincode_data: &[u8],
) -> Result<(BatchOutput, B256), String> {
    let batch_input: BatchInput =
        bincode::deserialize(bincode_data).map_err(|e| format!("deserialize: {e}"))?;
    Ok(execute_and_commit(&batch_input))
}
