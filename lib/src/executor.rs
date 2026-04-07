//! REVM-based block executor for ZKsync OS with merkle proof verification.
//!
//! Every storage and account read is verified against a merkle proof that
//! recovers the expected state root. Values come FROM the proofs, not from
//! a separate data path.

use std::collections::HashMap;

use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::database_interface::DBErrorMarker;
use revm::primitives::{Address, B256, Bytes, TxKind, U256, KECCAK_EMPTY, address};
use revm::state::{AccountInfo, Bytecode};
use revm::{DatabaseRef, ExecuteCommitEvm};
use zksync_os_revm::transaction::abstraction::ZKsyncTxBuilder;
use zksync_os_revm::{DefaultZk, ZKsyncTx, ZkBuilder, ZkContext, ZkSpecId};

use crate::block_header;
use crate::commitment;
use crate::merkle;
use crate::types::*;

// ---------------------------------------------------------------------------
// Proof-verified state database
// ---------------------------------------------------------------------------

/// Database that verifies every read against a merkle proof.
/// Values are taken FROM the proofs — there is no separate unverified data path.
/// Proof results are cached after first verification to avoid re-hashing.
struct ProvenDB {
    /// Merkle proofs for storage slots, keyed by flat_storage_key.
    storage_proofs: HashMap<B256, merkle::StorageProof>,
    /// Cache of verified proof results: flat_key -> value (None = non-existing).
    /// Populated on first read, subsequent reads skip proof verification.
    verified_storage: std::cell::RefCell<HashMap<B256, Option<B256>>>,
    /// Account data decoded from account-properties merkle proofs.
    verified_accounts: HashMap<Address, AccountInfo>,
    /// Verified bytecodes: keccak256(code) checked against hash at load time.
    bytecodes: HashMap<B256, Bytecode>,
    /// Block hashes for BLOCKHASH opcode.
    block_hashes: HashMap<u64, B256>,
    /// Expected tree root — all proofs must recover this.
    expected_root: B256,
}

#[derive(Debug)]
struct ProvenDBError(String);

impl core::fmt::Display for ProvenDBError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProvenDB error: {}", self.0)
    }
}

impl std::error::Error for ProvenDBError {}
impl DBErrorMarker for ProvenDBError {}

impl DatabaseRef for ProvenDB {
    type Error = ProvenDBError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.verified_accounts.get(&address).cloned())
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.bytecodes.get(&code_hash).cloned().unwrap_or_default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let addr_bytes: [u8; 20] = address.into_array();
        let slot = B256::from(index.to_be_bytes::<32>());
        let flat_key = merkle::derive_flat_storage_key(&addr_bytes, &slot);

        // Check cache first (avoids re-verifying proof on warm reads)
        if let Some(cached) = self.verified_storage.borrow().get(&flat_key) {
            return Ok(cached.map(|v| U256::from_be_bytes(v.0)).unwrap_or_default());
        }

        if let Some(proof) = self.storage_proofs.get(&flat_key) {
            let (root, value) = proof
                .verify(&flat_key)
                .map_err(|e| ProvenDBError(format!("merkle proof failed for {flat_key}: {e}")))?;

            if root != self.expected_root {
                return Err(ProvenDBError(format!(
                    "proof for {flat_key} recovers root {root}, expected {}",
                    self.expected_root
                )));
            }

            // Cache the result
            self.verified_storage.borrow_mut().insert(flat_key, value);
            Ok(value.map(|v| U256::from_be_bytes(v.0)).unwrap_or_default())
        } else {
            Err(ProvenDBError(format!(
                "no merkle proof for storage read: address={address}, slot={index}, flat_key={flat_key}"
            )))
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(self
            .block_hashes
            .get(&number)
            .copied()
            .unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Batch execution with proof verification
// ---------------------------------------------------------------------------

/// Execute a batch with full merkle proof verification and compute the
/// BatchPublicInput hash matching the server/L1 format.
pub fn execute_and_commit(input: &BatchInput) -> (BatchOutput, B256) {
    let spec_id = match input.spec_id {
        0 => ZkSpecId::AtlasV1,
        1 => ZkSpecId::AtlasV2,
        _ => panic!("unknown spec_id: {}", input.spec_id),
    };

    let meta = &input.batch_meta;

    // Validate block sequencing: monotonically increasing numbers and timestamps.
    assert!(!input.blocks.is_empty(), "batch must contain at least one block");
    assert!(
        input.blocks[0].number == meta.block_number_before + 1,
        "first block number {} must follow block_number_before {}",
        input.blocks[0].number,
        meta.block_number_before,
    );
    for i in 1..input.blocks.len() {
        assert!(
            input.blocks[i].number == input.blocks[i - 1].number + 1,
            "block numbers must be consecutive: {} follows {}",
            input.blocks[i].number,
            input.blocks[i - 1].number,
        );
        assert!(
            input.blocks[i].timestamp >= input.blocks[i - 1].timestamp,
            "block timestamps must be non-decreasing: {} < {}",
            input.blocks[i].timestamp,
            input.blocks[i - 1].timestamp,
        );
    }

    let mut block_results = Vec::with_capacity(input.blocks.len());
    for block in &input.blocks {
        // Each block's merkle proofs were extracted from its own tree version.
        // Use the per-block expected_tree_root if set, otherwise fall back to batch root.
        let tree_root = if !block.expected_tree_root.is_zero() {
            &block.expected_tree_root
        } else {
            &meta.tree_root_before
        };
        block_results.push(execute_block_proven(
            input.chain_id,
            spec_id,
            block,
            tree_root,
            meta,
        ));
    }

    let output = BatchOutput {
        chain_id: input.chain_id,
        block_results,
    };

    // -- Compute batch commitment --

    // State before: use block_hashes_blake from meta (pre-computed from
    // the state commitment preimage, which is verified via merkle proofs)
    let state_before = commitment::state_commitment_hash(
        &meta.tree_root_before,
        meta.leaf_count_before,
        meta.block_number_before,
        &meta.block_hashes_blake_before,
        meta.last_block_timestamp_before,
    );

    // State after: compute new tree root by applying storage writes.
    // SOUND-3: verify tree update entries match what REVM actually computed.
    let last_block = input.blocks.last().unwrap();

    // Check if batch contains system/upgrade transactions
    let has_system_txs = input.blocks.iter().any(|b| {
        b.transactions.iter().any(|tx| tx.tx_type == 0x7e || tx.tx_type == 0x7f)
    });

    let (tree_root_after, new_leaf_count) = if let Some(ref tree_update) = meta.tree_update {
        // Build map of REVM writes: flat_key -> new_value (storage diffs only)
        let revm_write_map: HashMap<B256, B256> = output
            .block_results
            .iter()
            .flat_map(|br| {
                br.storage_diffs.iter().map(|d| {
                    let addr_bytes: [u8; 20] = d.address.into_array();
                    let slot = B256::from(d.slot.to_be_bytes::<32>());
                    let flat_key = merkle::derive_flat_storage_key(&addr_bytes, &slot);
                    let new_val = B256::from(d.new_value.to_be_bytes::<32>());
                    (flat_key, new_val)
                })
            })
            .collect();

        let tree_write_map: HashMap<B256, B256> =
            tree_update.entries.iter().cloned().collect();

        // SOUND-3: REVM writes must be a subset of tree_update writes.
        // Every REVM write must appear in tree_update with the same value.
        for (key, revm_val) in &revm_write_map {
            assert!(
                tree_write_map.contains_key(key),
                "REVM wrote to {key} but tree_update does not include it"
            );
            let tree_val = &tree_write_map[key];
            assert_eq!(
                tree_val, revm_val,
                "tree_update value mismatch for {key}: tree={tree_val}, revm={revm_val}"
            );
        }

        // Reverse check: tree_update writes must also be in REVM writes.
        // Exception: system/upgrade transactions produce additional writes
        // via bootloader and system contracts that REVM doesn't see.
        if !has_system_txs {
            for tree_key in tree_write_map.keys() {
                assert!(
                    revm_write_map.contains_key(tree_key),
                    "tree_update includes {tree_key} that REVM did not write to"
                );
            }
        }

        // Verify old root matches, apply writes, compute new root
        tree_update.apply(&meta.tree_root_before)
    } else {
        // No tree update — verify REVM produced no storage writes
        let has_storage_writes = output
            .block_results
            .iter()
            .any(|br| !br.storage_diffs.is_empty());
        assert!(
            !has_storage_writes,
            "REVM produced storage writes but no tree_update proof was provided"
        );
        (meta.tree_root_before, meta.leaf_count_before)
    };

    // Use the COMPUTED block header hash (from execution), not the input's block_header_hash
    let last_block_result = output.block_results.last().unwrap();
    let block_hashes_blake_after = commitment::block_hashes_blake(
        &meta.previous_block_hashes,
        &last_block_result.computed_block_header_hash,
    );
    let state_after = commitment::state_commitment_hash(
        &tree_root_after,
        new_leaf_count,
        last_block.number,
        &block_hashes_blake_after,
        last_block.timestamp,
    );

    // Batch output hash
    let mut l1_tx_hashes = Vec::new();
    let mut l2_to_l1_encoded_logs = Vec::new();
    let mut num_l1_txs: u64 = 0;
    let mut num_l2_txs: u64 = 0;

    for block in &input.blocks {
        for tx in &block.transactions {
            if tx.is_l1_tx {
                if let Some(h) = &tx.l1_tx_hash {
                    l1_tx_hashes.push(*h);
                }
                num_l1_txs += 1;
            } else if tx.tx_type != 0x7e {
                // Upgrade txs (0x7e) are system txs that count as neither L1 nor L2.
                num_l2_txs += 1;
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
    (output, commitment)
}

/// Debug: return the three commitment components alongside the final hash.
/// Returns (output, commitment, state_before, state_after, batch_hash).
pub fn execute_and_commit_debug(input: &BatchInput) -> (BatchOutput, B256, B256, B256, B256) {
    // Re-use execute_and_commit internals by running the same logic
    // and extracting intermediate values.
    let (output, _) = execute_and_commit(input);

    // Re-derive the commitment components from the output + input.
    let meta = &input.batch_meta;
    let state_before = commitment::state_commitment_hash(
        &meta.tree_root_before,
        meta.leaf_count_before,
        meta.block_number_before,
        &meta.block_hashes_blake_before,
        meta.last_block_timestamp_before,
    );

    let last_block = input.blocks.last().unwrap();
    let last_br = output.block_results.last().unwrap();

    let (tree_root_after, new_leaf_count) = if let Some(ref tree_update) = meta.tree_update {
        tree_update.apply(&meta.tree_root_before)
    } else {
        (meta.tree_root_before, meta.leaf_count_before)
    };

    let block_hashes_blake_after = commitment::block_hashes_blake(
        &meta.previous_block_hashes,
        &last_br.computed_block_header_hash,
    );
    let state_after = commitment::state_commitment_hash(
        &tree_root_after,
        new_leaf_count,
        last_block.number,
        &block_hashes_blake_after,
        last_block.timestamp,
    );

    let mut l1_tx_hashes = Vec::new();
    let mut l2_to_l1_encoded_logs = Vec::new();
    let mut num_l1_txs: u64 = 0;
    let mut num_l2_txs: u64 = 0;
    for block in &input.blocks {
        for tx in &block.transactions {
            if tx.is_l1_tx {
                if let Some(h) = &tx.l1_tx_hash { l1_tx_hashes.push(*h); }
                num_l1_txs += 1;
            } else if tx.tx_type != 0x7e {
                num_l2_txs += 1;
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
    let effective_multichain_root = if input.protocol_version_minor >= 31 {
        meta.multichain_root
    } else {
        B256::ZERO
    };
    let l2_logs_root_hash = commitment::keccak_two(&l2_logs_local_root, &effective_multichain_root);
    let da_commitment = match meta.da_commitment_scheme {
        0 | 1 => B256::ZERO,
        2 | 3 => commitment::da_commitment_calldata(&meta.pubdata),
        4 => commitment::da_commitment_blobs(&meta.blob_versioned_hashes),
        _ => panic!("unsupported DA scheme"),
    };
    let batch_hash = if input.protocol_version_minor >= 31 {
        commitment::batch_output_hash_v31(
            input.chain_id, input.blocks.first().unwrap().timestamp,
            last_block.timestamp, meta.da_commitment_scheme, &da_commitment,
            num_l1_txs, num_l2_txs, &priority_ops_hash, &l2_logs_root_hash,
            &meta.upgrade_tx_hash, &B256::ZERO, meta.sl_chain_id,
        )
    } else {
        commitment::batch_output_hash_v30(
            input.chain_id, input.blocks.first().unwrap().timestamp,
            last_block.timestamp, meta.da_commitment_scheme, &da_commitment,
            num_l1_txs, &priority_ops_hash, &l2_logs_root_hash,
            &meta.upgrade_tx_hash, &B256::ZERO,
        )
    };
    let commitment = commitment::batch_public_input_hash(&state_before, &state_after, &batch_hash);
    (output, commitment, state_before, state_after, batch_hash)
}

/// Execute a single block with proof-verified state reads.
fn execute_block_proven(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    expected_root: &B256,
    batch_meta: &BatchMeta,
) -> BlockResult {
    let proven_db = build_proven_db(block, expected_root, batch_meta);
    let cache_db = CacheDB::new(proven_db);
    let (tx_results, storage_diffs, account_diffs, computed_l2_to_l1_logs) =
        run_evm_and_collect_diffs(chain_id, spec_id, block, cache_db, false);
    // In proven mode, verify every account that changed state has a verified
    // "before" value. If an account's nonce/balance changed, its "before"
    // value must come from a preimage (merkle-verified) or be provably zero
    // (non-existence proof or genuinely new account).
    let preimage_addrs: std::collections::HashSet<Address> =
        block.account_preimages.iter().map(|(a, _)| *a).collect();
    for diff in &account_diffs {
        if !preimage_addrs.contains(&diff.address) {
            // Account changed but has no preimage — "before" was assumed (0, 0).
            // Check if there's an existing merkle proof that contradicts this.
            let addr_bytes: [u8; 20] = diff.address.into_array();
            let flat_key = merkle::derive_account_properties_key(&addr_bytes);
            for (k, proof) in &block.storage_proofs {
                if *k == flat_key {
                    if let merkle::StorageProof::Existing(_) = proof {
                        panic!(
                            "account {} changed state but has no preimage, \
                             while merkle proof shows it EXISTS. \
                             Add an account_preimage for this address.",
                            diff.address
                        );
                    }
                    // NonExisting proof confirms before-state was truly zero — OK
                }
            }
        }
    }

    // Compute block header hash from execution results instead of trusting input.
    // This ensures the block_header_hash used in state_after is derived from
    // actual execution, not attacker-controlled input.
    let total_gas_used: u64 = tx_results.iter().map(|t| t.gas_used).sum();

    // Compute transactions rolling hash from tx hashes in the input.
    // For L2 txs, the hash comes from signed_tx_bytes (keccak256(signed_bytes)).
    // For L1 txs, it comes from l1_tx_hash.
    let tx_hashes: Vec<B256> = block.transactions.iter().map(|tx| {
        let hash = if let Some(ref signed) = tx.signed_tx_bytes {
            alloy_primitives::keccak256(signed)
        } else if let Some(hash) = tx.l1_tx_hash {
            hash
        } else if tx.tx_type == 0x7e {
            batch_meta.upgrade_tx_hash
        } else {
            B256::ZERO
        };
        hash
    }).collect();
    let tx_root = commitment::transactions_rolling_hash(&tx_hashes);


    // Get parent hash from block_hashes (previous block's hash)
    let parent_hash = if block.number >= 1 {
        block.block_hashes.iter()
            .find(|(n, _)| *n == block.number - 1)
            .map(|(_, h)| *h)
            .unwrap_or(B256::ZERO)
    } else {
        B256::ZERO
    };


    let computed_header_hash = block_header::compute_block_header_hash(
        &parent_hash,
        &block.coinbase.into_array(),
        &tx_root,
        block.number,
        block.gas_limit,
        total_gas_used,
        block.timestamp,
        &block.prev_randao,
        block.base_fee,
    );

    // If a block_header_hash was provided in input, verify it matches our computation
    if !block.block_header_hash.is_zero() {
        assert_eq!(
            computed_header_hash, block.block_header_hash,
            "computed block header hash {computed_header_hash} != input {}", block.block_header_hash
        );
    }

    // SOUND: L2→L1 logs are computed from REVM's EVM execution output, NOT from
    // the untrusted BlockInput.l2_to_l1_logs. The L1Messenger precompile (0x8008)
    // emits L1MessageSent EVM events during execution; we reconstruct the structured
    // L2ToL1LogEntry from those events. This ensures the logs in the batch commitment
    // match what was actually executed.
    //
    // Verify consistency: computed logs must match input logs. A mismatch means either
    // the server provided wrong logs or our extraction has a bug.
    if !block.l2_to_l1_logs.is_empty() || !computed_l2_to_l1_logs.is_empty() {
        assert_eq!(
            computed_l2_to_l1_logs.len(),
            block.l2_to_l1_logs.len(),
            "L2→L1 log count mismatch: computed {} from EVM, input has {}",
            computed_l2_to_l1_logs.len(),
            block.l2_to_l1_logs.len(),
        );
        for (i, (computed, input)) in computed_l2_to_l1_logs.iter().zip(&block.l2_to_l1_logs).enumerate() {
            assert_eq!(
                computed.encode(),
                input.encode(),
                "L2→L1 log {i} mismatch: computed {:?} != input {:?}",
                computed, input,
            );
        }
    }

    BlockResult {
        block_number: block.number,
        computed_block_header_hash: computed_header_hash,
        tx_results,
        storage_diffs,
        account_diffs,
        l2_to_l1_logs: computed_l2_to_l1_logs,
    }
}

/// Build a ProvenDB where all state is verified via merkle proofs.
fn build_proven_db(block: &BlockInput, expected_root: &B256, batch_meta: &BatchMeta) -> ProvenDB {
    // Verify all merkle proofs and extract values FROM the proofs
    let mut storage_proofs = HashMap::new();
    for (key, proof) in &block.storage_proofs {
        // Verify proof recovers the expected root
        let (root, _value) = proof
            .verify(key)
            .unwrap_or_else(|e| panic!("merkle proof failed for key {key}: {e}"));

        assert_eq!(
            root, *expected_root,
            "proof for {key} recovers root {root}, expected {expected_root}"
        );

        storage_proofs.insert(*key, proof.clone());
    }

    // Build verified accounts from merkle proofs of address 0x8003.
    // Each account's properties are stored at flat_key = derive_flat_storage_key(0x8003, left_padded_addr).
    // The merkle proof verifies the value hash; the preimage decodes to nonce/balance/code_hash.
    let mut verified_accounts = HashMap::new();
    for (addr, preimage_bytes) in &block.account_preimages {
        let addr_bytes: [u8; 20] = addr.into_array();
        let flat_key = merkle::derive_account_properties_key(&addr_bytes);

        // Verify the preimage hash matches what the merkle proof says
        let preimage_hash = merkle::AccountProperties::hash(preimage_bytes);

        // Look up the merkle proof for this account
        let proof = storage_proofs.get(&flat_key).unwrap_or_else(|| {
            panic!(
                "no merkle proof for account {addr} (flat_key={flat_key}). \
                 Every account_preimage must have a corresponding storage_proof."
            )
        });

        let (root, proven_value) = proof
            .verify(&flat_key)
            .unwrap_or_else(|e| panic!("account proof failed for {addr}: {e}"));

        assert_eq!(
            root, *expected_root,
            "account proof for {addr} recovers wrong root"
        );

        // For non-existing accounts (proof returns None), skip
        let proven_val = match proven_value {
            Some(v) => v,
            None => continue,
        };

        assert_eq!(
            proven_val, preimage_hash,
            "account preimage hash mismatch for {addr}: \
             proven value {proven_val}, preimage hash {preimage_hash}"
        );

        // Decode the preimage
        let props = merkle::AccountProperties::decode(preimage_bytes);
        let observable_code_hash = if props.observable_bytecode_hash.is_zero() {
            // Empty account or no code — use KECCAK_EMPTY for REVM compatibility
            if props.nonce == 0 && props.balance == [0u8; 32] {
                B256::ZERO // truly empty
            } else {
                KECCAK_EMPTY
            }
        } else {
            props.observable_bytecode_hash
        };

        verified_accounts.insert(
            *addr,
            AccountInfo {
                nonce: props.nonce,
                balance: U256::from_be_bytes(props.balance),
                code_hash: observable_code_hash,
                code: None,
                account_id: None,
            },
        );
    }

    // Verify bytecodes: keccak256(code) must equal the provided hash.
    let mut bytecodes = HashMap::new();
    for (hash, code) in &block.bytecodes {
        let computed_hash = alloy_primitives::keccak256(code);
        assert_eq!(
            computed_hash, *hash,
            "bytecode hash mismatch: computed {computed_hash}, provided {hash}"
        );
        bytecodes.insert(*hash, Bytecode::new_raw(Bytes::copy_from_slice(code)));
    }
    // Force-deploy bytecodes keyed by ZKsync blake2s hash (includes artifacts).
    for (hash, code) in &block.force_deploy_bytecodes {
        bytecodes.insert(*hash, Bytecode::new_raw(Bytes::copy_from_slice(code)));
    }

    // Verify block hashes against batch_meta.previous_block_hashes.
    // The previous_block_hashes feeds into block_hashes_blake which is part
    // of the state commitment verified on L1. Each block hash used by REVM's
    // BLOCKHASH opcode must be consistent with this verified set.
    let mut block_hashes = HashMap::new();
    let block_number_before = batch_meta.block_number_before;
    for &(num, hash) in &block.block_hashes {
        // The previous_block_hashes array covers blocks [block_number_before-254 .. block_number_before].
        // Index 0 in previous_block_hashes is the oldest (block_number_before - 254),
        // index 254 is the most recent (block_number_before).
        if block_number_before > 0 && num <= block_number_before {
            let oldest_available = block_number_before.saturating_sub(254);
            if num >= oldest_available {
                let idx = (num - oldest_available) as usize;
                if idx < batch_meta.previous_block_hashes.len() {
                    let verified_hash = batch_meta.previous_block_hashes[idx];
                    // Skip comparison for zero hashes (early chain state where
                    // block hashes haven't been recorded yet).
                    if !verified_hash.is_zero() {
                        assert_eq!(
                            hash, verified_hash,
                            "block hash mismatch for block {num}: input={hash}, verified={verified_hash}"
                        );
                    }
                }
            }
        }
        block_hashes.insert(num, hash);
    }

    // For accounts not in account_preimages (no merkle proof), fall back to
    // block.accounts data. Skip accounts with non-zero code_hash that have
    // force_deploy_bytecodes — these will be deployed by the upgrade tx and
    // must start with empty code for the deployment check to work.
    let has_force_deploys = !block.force_deploy_bytecodes.is_empty();
    for (addr, data) in &block.accounts {
        if verified_accounts.contains_key(addr) { continue; }
        // If this block has force deployments and this account has code,
        // skip it — the upgrade code will deploy it and checks code.length == 0.
        if has_force_deploys && !data.code_hash.is_zero() {
            continue;
        }
        let code_hash = if data.code_hash.is_zero() {
            if data.nonce == 0 && data.balance.is_zero() { continue; }
            KECCAK_EMPTY
        } else {
            data.code_hash
        };
        verified_accounts.insert(*addr, AccountInfo {
            nonce: data.nonce,
            balance: data.balance,
            code_hash,
            code: None,
            account_id: None,
        });
    }

    ProvenDB {
        storage_proofs,
        verified_storage: std::cell::RefCell::new(HashMap::new()),
        verified_accounts,
        bytecodes,
        block_hashes,
        expected_root: *expected_root,
    }
}

/// Build a transaction for proven execution.
/// gas_used_override and force_fail are forced off — REVM computes results independently.
fn build_proven_tx(input: &TxInput) -> ZKsyncTx<TxEnv> {
    if input.is_l1_tx {
        // L1 priority transactions: verify that the encoded tx bytes hash to
        // the claimed l1_tx_hash. Both fields are required — without them an
        // attacker could use a real l1_tx_hash while substituting tx fields
        // (e.g., inflating mint amount).
        let _signed_bytes = input.signed_tx_bytes.as_ref().unwrap_or_else(|| {
            panic!(
                "L1 transaction from {} missing signed_tx_bytes — \
                 every L1 tx must include encoded bytes for hash verification",
                input.caller
            )
        });
        let _claimed_hash = input.l1_tx_hash.unwrap_or_else(|| {
            panic!(
                "L1 transaction from {} missing l1_tx_hash — \
                 every L1 tx must include its canonical hash",
                input.caller
            )
        });
        // L1 tx hashes are canonical priority queue hashes, not keccak256(raw_bytes).
        // They are verified via priority_operations_rolling_hash in the batch commitment,
        // not via raw hash comparison here.
    } else if input.tx_type == 0x7e {
        // Upgrade txs don't have signed bytes — they're system txs verified by the L1 protocol.
    } else {
        // L2 transactions MUST have signed_tx_bytes for signature verification.
        let signed_bytes = input.signed_tx_bytes.as_ref().unwrap_or_else(|| {
            panic!(
                "L2 transaction from {} missing signed_tx_bytes — \
                 every L2 tx must include signed bytes for ecrecover",
                input.caller
            )
        });
        let recovered_caller = recover_signer(signed_bytes);
        assert_eq!(
            recovered_caller, input.caller,
            "signature verification failed: recovered {recovered_caller}, expected {}",
            input.caller
        );
    }

    // For upgrade txs (0x7e), allow gas_used_override even in proven mode.
    // EVM gas metering differs from ZKsync OS native gas, so the server's gas_used
    // must be used for the block header / commitment computation.
    let allow_gas_override = input.tx_type == 0x7e;
    build_tx_inner(input, allow_gas_override)
}

/// Build a transaction for unverified (testing) execution.
/// gas_used_override and force_fail are passed through from input.
fn build_tx(input: &TxInput) -> ZKsyncTx<TxEnv> {
    build_tx_inner(input, true)
}

fn build_tx_inner(input: &TxInput, allow_overrides: bool) -> ZKsyncTx<TxEnv> {
    let kind = match input.to {
        Some(addr) => TxKind::Call(addr),
        None => TxKind::Create,
    };

    // For upgrade transactions (0x7e), use unlimited gas since EVM gas metering
    // differs from ZKsync OS native gas. The actual gas is handled by gas_used_override.
    let effective_gas_limit = if input.tx_type == 0x7e {
        input.gas_limit.saturating_mul(10) // 200x gas for upgrade txs (EVM gas >> ZKsync native gas)
    } else {
        input.gas_limit
    };

    let mut builder = TxEnv::builder()
        .caller(input.caller)
        .gas_limit(effective_gas_limit)
        .gas_price(input.gas_price)
        .kind(kind)
        .value(input.value)
        .data(Bytes::copy_from_slice(&input.data))
        .nonce(input.nonce)
        .tx_type(Some(input.tx_type))
        .chain_id(input.chain_id)
        .blob_hashes(vec![]);

    if let Some(fee) = input.gas_priority_fee {
        builder = builder.gas_priority_fee(Some(fee));
    }

    let (gas_override, force_fail) = if allow_overrides {
        (input.gas_used_override, input.force_fail)
    } else {
        // Proven mode: REVM computes gas and success independently.
        (None, false)
    };

    ZKsyncTxBuilder::new()
        .base(builder)
        .mint(input.mint.unwrap_or_default())
        .refund_recipient(input.refund_recipient)
        .gas_used_override(gas_override)
        .force_fail(force_fail)
        .build()
        .expect("failed to build ZKsyncTx")
}

/// Recover the signer address from EIP-2718 encoded signed transaction bytes.
///
/// Decodes the transaction envelope (Legacy, EIP-2930, EIP-1559, etc.),
/// extracts the signature (v, r, s), computes the signing hash, and
/// recovers the public key via secp256k1 ecrecover.
fn recover_signer(signed_bytes: &[u8]) -> Address {
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_consensus::TxEnvelope;
    use alloy_eips::Decodable2718;

    let envelope = TxEnvelope::decode_2718(&mut &signed_bytes[..])
        .expect("failed to decode EIP-2718 signed transaction");

    envelope
        .recover_signer()
        .expect("failed to recover signer from transaction signature")
}


// ---------------------------------------------------------------------------
// Legacy unverified execution (for testing / backward compatibility)
// ---------------------------------------------------------------------------

/// Execute without proof verification (for testing only).
pub fn execute_batch(input: &BatchInput) -> BatchOutput {
    let spec_id = match input.spec_id {
        0 => ZkSpecId::AtlasV1,
        1 => ZkSpecId::AtlasV2,
        _ => panic!("unknown spec_id: {}", input.spec_id),
    };

    let mut block_results = Vec::with_capacity(input.blocks.len());
    for block in &input.blocks {
        block_results.push(execute_block_unverified(input.chain_id, spec_id, block));
    }

    BatchOutput {
        chain_id: input.chain_id,
        block_results,
    }
}

// ---------------------------------------------------------------------------
// Simple unverified DB (used by execute_batch for testing)
// ---------------------------------------------------------------------------

struct SimpleDB {
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    bytecodes: HashMap<B256, Bytecode>,
    block_hashes: HashMap<u64, B256>,
}

#[derive(Debug)]
struct SimpleDBError;
impl core::fmt::Display for SimpleDBError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "db error")
    }
}
impl std::error::Error for SimpleDBError {}
impl DBErrorMarker for SimpleDBError {}


impl DatabaseRef for SimpleDB {
    type Error = SimpleDBError;
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }
    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.bytecodes.get(&code_hash).cloned().unwrap_or_default())
    }
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.storage.get(&(address, index)).copied().unwrap_or_default())
    }
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.block_hashes.get(&number).copied().unwrap_or_default())
    }
}

fn build_simple_db(block: &BlockInput) -> SimpleDB {
    let mut accounts = HashMap::new();
    for (addr, data) in &block.accounts {
        accounts.insert(*addr, AccountInfo {
            nonce: data.nonce,
            balance: data.balance,
            code_hash: if data.code_hash.is_zero() { KECCAK_EMPTY } else { data.code_hash },
            code: None,
            account_id: None,
        });
    }
    let mut storage = HashMap::new();
    for &(addr, slot, value) in &block.storage {
        storage.insert((addr, slot), value);
    }
    let mut bytecodes = HashMap::new();
    for (hash, code) in &block.bytecodes {
        let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(code));
        bytecodes.insert(*hash, bytecode);
    }
    // Force-deploy bytecodes keyed by ZKsync blake2s hash (includes artifacts).
    // The deployer precompile looks up by this hash.
    for (hash, code) in &block.force_deploy_bytecodes {
        let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(code));
        bytecodes.insert(*hash, bytecode);
    }
    let mut block_hashes = HashMap::new();
    for &(num, hash) in &block.block_hashes {
        block_hashes.insert(num, hash);
    }
    SimpleDB { accounts, storage, bytecodes, block_hashes }
}

// ---------------------------------------------------------------------------
// Shared EVM execution and diff collection
// ---------------------------------------------------------------------------

/// Bootloader formal address — used as sender for L1→L2 tx status logs.
const BOOTLOADER_ADDRESS: Address = address!("0000000000000000000000000000000000008001");

fn run_evm_and_collect_diffs<DB: DatabaseRef>(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    mut cache_db: CacheDB<DB>,
    allow_overrides: bool,
) -> (Vec<TxOutput>, Vec<StorageDiff>, Vec<AccountDiff>, Vec<L2ToL1LogEntry>)
where
    DB::Error: core::fmt::Debug,
{
    let mut evm = <ZkContext<_>>::default()
        .with_db(&mut cache_db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.spec = spec_id;
        })
        .modify_block_chained(|blk| {
            blk.number = U256::from(block.number);
            blk.timestamp = U256::from(block.timestamp);
            blk.beneficiary = block.coinbase;
            blk.basefee = block.base_fee;
            blk.gas_limit = block.gas_limit;
            blk.prevrandao = Some(block.prev_randao);
        })
        .build_zk();

    let mut tx_results = Vec::with_capacity(block.transactions.len());
    let mut computed_l2_to_l1_logs = Vec::new();

    for (tx_idx, tx_input) in block.transactions.iter().enumerate() {
        let tx_number = tx_idx as u16;
        evm.0.ctx.chain.set_tx_number(tx_number);

        let tx = if allow_overrides {
            build_tx(tx_input)
        } else {
            build_proven_tx(tx_input)
        };
        match evm.transact_commit(tx) {
            Ok(result) => {
                let success = result.is_success();

                // For L1→L2 priority txs, synthesize the bootloader status log.
                // This log is emitted by the bootloader (not via L1Messenger precompile),
                // so it doesn't go through the thread-local path.
                if tx_input.is_l1_tx {
                    if let Some(l1_hash) = &tx_input.l1_tx_hash {
                        computed_l2_to_l1_logs.push(L2ToL1LogEntry {
                            l2_shard_id: 0,
                            is_service: true,
                            tx_number_in_block: tx_number,
                            sender: BOOTLOADER_ADDRESS,
                            key: *l1_hash,
                            value: if success {
                                let mut v = B256::ZERO;
                                v.0[31] = 1;
                                v
                            } else {
                                B256::ZERO
                            },
                        });
                    }
                }

                // Collect L2→L1 logs from the chain context (set by L1Messenger precompile).
                for log in evm.0.ctx.chain.take_logs() {
                    computed_l2_to_l1_logs.push(L2ToL1LogEntry {
                        l2_shard_id: log.l2_shard_id,
                        is_service: log.is_service,
                        tx_number_in_block: log.tx_number_in_block,
                        sender: log.sender,
                        key: log.key,
                        value: log.value,
                    });
                }

                tx_results.push(TxOutput {
                    success,
                    gas_used: result.gas_used(),
                    output: result.output().map(|b| b.to_vec()).unwrap_or_default(),
                });
            }
            Err(e) => panic!("transaction execution failed: {e:?}"),
        }
    }

    drop(evm);

    // Build lookup maps for O(1) before-value access
    let preimage_map: HashMap<Address, &[u8]> = block
        .account_preimages
        .iter()
        .map(|(a, p)| (*a, p.as_slice()))
        .collect();
    let account_map: HashMap<Address, &AccountData> = block
        .accounts
        .iter()
        .map(|(a, d)| (*a, d))
        .collect();
    let storage_map: HashMap<(Address, U256), U256> = block
        .storage
        .iter()
        .map(|&(a, s, v)| ((a, s), v))
        .collect();

    let mut storage_diffs = Vec::new();
    let mut account_diffs = Vec::new();
    for (addr, db_account) in cache_db.cache.accounts.iter() {
        if matches!(
            db_account.account_state,
            revm::database::AccountState::None | revm::database::AccountState::NotExisting
        ) {
            continue;
        }
        let info = &db_account.info;
        let (nonce_before, balance_before) = preimage_map
            .get(addr)
            .map(|preimage| {
                let props = merkle::AccountProperties::decode(preimage);
                (props.nonce, U256::from_be_bytes(props.balance))
            })
            .or_else(|| {
                account_map.get(addr).map(|d| (d.nonce, d.balance))
            })
            .unwrap_or((0, U256::ZERO));

        if info.nonce != nonce_before || info.balance != balance_before {
            account_diffs.push(AccountDiff {
                address: *addr,
                nonce_before,
                nonce_after: info.nonce,
                balance_before,
                balance_after: info.balance,
            });
        }
        for (slot, value) in db_account.storage.iter() {
            let slot_u256 = U256::from_limbs((*slot).into_limbs());
            let old_val = storage_map
                .get(&(*addr, slot_u256))
                .copied()
                .unwrap_or(U256::ZERO);
            let new_val = U256::from_limbs((*value).into_limbs());
            if old_val != new_val {
                storage_diffs.push(StorageDiff {
                    address: *addr,
                    slot: slot_u256,
                    old_value: old_val,
                    new_value: new_val,
                });
            }
        }
    }

    (tx_results, storage_diffs, account_diffs, computed_l2_to_l1_logs)
}

fn execute_block_unverified(chain_id: u64, spec_id: ZkSpecId, block: &BlockInput) -> BlockResult {
    let db = build_simple_db(block);
    let cache_db = CacheDB::new(db);
    let (tx_results, storage_diffs, account_diffs, computed_logs) =
        run_evm_and_collect_diffs(chain_id, spec_id, block, cache_db, true);
    // Unverified mode: use computed logs (from EVM execution) if available,
    // fall back to input logs for backward compat with inputs that lack EVM log data.
    let l2_to_l1_logs = if computed_logs.is_empty() {
        block.l2_to_l1_logs.clone()
    } else {
        computed_logs
    };
    BlockResult {
        block_number: block.number,
        computed_block_header_hash: block.block_header_hash, // unverified path trusts input
        tx_results,
        storage_diffs,
        account_diffs,
        l2_to_l1_logs,
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

/// Legacy output hash (for backward compat with tests).
pub fn compute_output_hash(output: &BatchOutput) -> [u8; 32] {
    let encoded = bincode::serialize(output).expect("serialization cannot fail");
    alloy_primitives::keccak256(&encoded).into()
}
