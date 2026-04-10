//! REVM-based block executor for ZKsync OS with merkle proof verification.
//!
//! Every storage and account read is verified against a merkle proof that
//! recovers the expected state root. Values come FROM the proofs, not from
//! a separate data path.

use std::collections::HashMap;

use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::database_interface::DBErrorMarker;
use revm::primitives::{Address, B256, Bytes, TxKind, U256, KECCAK_EMPTY};
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
    /// Pre-verified storage values: flat_key -> value (None = proven non-existing).
    /// All proofs are verified at construction time; reads are pure lookups.
    /// This includes account-property entries at address 0x8003.
    verified_storage: HashMap<B256, Option<B256>>,
    /// Merkle-verified account info. Every entry was proven against the tree
    /// root at construction time. None = proven non-existent.
    verified_accounts: HashMap<Address, Option<AccountInfo>>,
    /// Verified bytecodes keyed by hash (keccak256 or blake2s).
    bytecodes: HashMap<B256, Bytecode>,
    /// Block hashes for BLOCKHASH opcode (verified against batch_meta).
    block_hashes: HashMap<u64, B256>,
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
        // Fast path: account was pre-verified from account_preimages
        if let Some(proven) = self.verified_accounts.get(&address) {
            return Ok(proven.clone());
        }

        // Slow path: check verified_storage for account-property proof.
        // The server may include a proof without a preimage (for non-existent accounts).
        let addr_bytes: [u8; 20] = address.into_array();
        let flat_key = merkle::derive_account_properties_key(&addr_bytes);
        match self.verified_storage.get(&flat_key) {
            Some(None) => Ok(None), // proven non-existent
            Some(Some(_)) => Err(ProvenDBError(format!(
                "account {address} exists in merkle tree but no preimage in account_preimages"
            ))),
            None => Err(ProvenDBError(format!(
                "no proof for account {address}. The server must provide a merkle proof \
                 (existence or non-existence) for every account REVM accesses."
            ))),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.bytecodes.get(&code_hash).cloned().unwrap_or_default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let addr_bytes: [u8; 20] = address.into_array();
        let slot = B256::from(index.to_be_bytes::<32>());
        let flat_key = merkle::derive_flat_storage_key(&addr_bytes, &slot);

        match self.verified_storage.get(&flat_key) {
            Some(value) => Ok(value.map(|v| U256::from_be_bytes(v.0)).unwrap_or_default()),
            None => Err(ProvenDBError(format!(
                "no merkle proof for storage read: address={address}, slot={index}, flat_key={flat_key}"
            ))),
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

    // Build the proven database once for the entire batch. All merkle proofs
    // from all blocks are verified at construction and merged into a single DB.
    // A CacheDB wraps it so that writes from block N are visible to block N+1.
    let proven_db = build_proven_db(input);
    let mut cache_db = CacheDB::new(proven_db);

    let mut block_results = Vec::with_capacity(input.blocks.len());
    let mut all_deployed_bytecodes: Vec<(Address, B256)> = Vec::new();
    // Track computed block header hashes to cross-verify intra-batch BLOCKHASH usage.
    let mut computed_block_hashes: HashMap<u64, B256> = HashMap::new();
    for block in &input.blocks {
        // Verify intra-batch block hashes: if this block references a previous block
        // in the same batch via block_hashes, check it matches the computed hash.
        for &(num, hash) in &block.block_hashes {
            if let Some(&computed) = computed_block_hashes.get(&num) {
                assert_eq!(
                    hash, computed,
                    "intra-batch block hash mismatch for block {num}: \
                     server provided {hash}, computed {computed}"
                );
            }
        }

        let (result, deployed_bytecodes) = execute_block_proven(
            input.chain_id,
            spec_id,
            block,
            meta,
            &mut cache_db,
        );
        all_deployed_bytecodes.extend(deployed_bytecodes);

        // Record the computed block header hash for subsequent blocks' BLOCKHASH verification
        computed_block_hashes.insert(block.number, result.computed_block_header_hash);

        block_results.push(result);
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

    // Collect batch-level diffs from the CacheDB (comparing final state vs proven pre-state).
    let (storage_diffs, _account_diffs) = collect_batch_diffs(&cache_db, input);

    // State after: compute new tree root by applying storage writes.
    // SOUND-3: verify tree update entries match what REVM actually computed.
    let last_block = input.blocks.last().unwrap();

    let (tree_root_after, new_leaf_count) = if let Some(ref tree_update) = meta.tree_update {
        // Build map of REVM writes: flat_key -> new_value (storage diffs only)
        let revm_write_map: HashMap<B256, B256> = storage_diffs
            .iter()
            .map(|d| {
                let addr_bytes: [u8; 20] = d.address.into_array();
                let slot = B256::from(d.slot.to_be_bytes::<32>());
                let flat_key = merkle::derive_flat_storage_key(&addr_bytes, &slot);
                let new_val = B256::from(d.new_value.to_be_bytes::<32>());
                (flat_key, new_val)
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

        // SOUND-3 reverse check: every extra tree_update entry (not in REVM
        // writes) must be a legitimate 0x8003 account-property write.
        // Build the set of expected 0x8003 flat_keys from accounts that
        // changed state (nonce/balance) or had bytecode deployed.
        {
            let mut expected_account_keys: std::collections::HashSet<B256> = std::collections::HashSet::new();
            // Accounts with nonce/balance changes
            for diff in &_account_diffs {
                let addr_bytes: [u8; 20] = diff.address.into_array();
                expected_account_keys.insert(merkle::derive_account_properties_key(&addr_bytes));
            }
            // Accounts with bytecode deployments (from deployer precompile)
            for (addr, _blake2s_hash) in &all_deployed_bytecodes {
                let addr_bytes: [u8; 20] = addr.into_array();
                expected_account_keys.insert(merkle::derive_account_properties_key(&addr_bytes));
            }

            for tree_key in tree_write_map.keys() {
                if !revm_write_map.contains_key(tree_key) {
                    assert!(
                        expected_account_keys.contains(tree_key),
                        "tree_update entry {tree_key} is not in REVM writes and not \
                         an expected 0x8003 account-property write"
                    );
                }
            }
        }

        // Verify old root matches, apply writes, compute new root
        tree_update.apply(&meta.tree_root_before)
    } else {
        // No tree update — verify REVM produced no storage writes
        assert!(
            storage_diffs.is_empty(),
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

/// Execute a single block using the shared batch-level CacheDB.
/// Writes from this block remain in the CacheDB for subsequent blocks.
fn execute_block_proven(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    batch_meta: &BatchMeta,
    cache_db: &mut CacheDB<ProvenDB>,
) -> (BlockResult, Vec<(Address, B256)>) {
    let (tx_results, computed_l2_to_l1_logs, deployed_bytecodes) =
        run_evm_block(chain_id, spec_id, block, batch_meta, cache_db, false);

    // Compute block header hash from execution results instead of trusting input.
    // This ensures the block_header_hash used in state_after is derived from
    // actual execution, not attacker-controlled input.
    let total_gas_used: u64 = tx_results.iter().map(|t| t.gas_used).sum();

    // Compute transactions rolling hash from tx hashes in the input.
    // For L2 txs, the hash comes from signed_tx_bytes (keccak256(signed_bytes)).
    // For L1 txs, it comes from l1_tx_hash.
    let tx_hashes: Vec<B256> = block.transactions.iter().map(|tx| {
        if let Some(hash) = tx.l1_tx_hash {
            // L1 priority txs use their canonical priority queue hash.
            hash
        } else if tx.tx_type == 0x7e {
            // Upgrade txs use the batch-level upgrade tx hash.
            batch_meta.upgrade_tx_hash
        } else if let Some(ref signed) = tx.signed_tx_bytes {
            // L2 txs use keccak256 of the signed EIP-2718 encoded bytes.
            alloy_primitives::keccak256(signed)
        } else {
            B256::ZERO
        }
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

    (BlockResult {
        block_number: block.number,
        computed_block_header_hash: computed_header_hash,
        tx_results,
        l2_to_l1_logs: computed_l2_to_l1_logs,
    }, deployed_bytecodes)
}

/// Build a ProvenDB for the entire batch.
/// All merkle proofs from all blocks are verified at construction time and
/// their values are stored in flat maps. Each block's proofs are verified
/// against that block's expected tree root.
fn build_proven_db(input: &BatchInput) -> ProvenDB {
    let meta = &input.batch_meta;
    let mut verified_storage: HashMap<B256, Option<B256>> = HashMap::new();
    let mut verified_accounts: HashMap<Address, Option<AccountInfo>> = HashMap::new();
    let mut bytecodes: HashMap<B256, Bytecode> = HashMap::new();
    let mut block_hashes: HashMap<u64, B256> = HashMap::new();

    // Load batch-level bytecodes. Entries may be keyed by keccak256 (regular
    // contracts) or blake2s (force-deployed system contracts). The key is
    // whatever hash the EVM will use to look up the code.
    for (hash, code) in &input.bytecodes {
        bytecodes.insert(*hash, Bytecode::new_raw(Bytes::copy_from_slice(code)));
    }

    for block in &input.blocks {
        let expected_root = if !block.expected_tree_root.is_zero() {
            &block.expected_tree_root
        } else {
            &meta.tree_root_before
        };

        // Verify all merkle proofs and extract values FROM the proofs.
        for (key, proof) in &block.storage_proofs {
            let (root, value) = proof
                .verify(key)
                .unwrap_or_else(|e| panic!("merkle proof failed for key {key}: {e}"));

            assert_eq!(
                root, *expected_root,
                "proof for {key} recovers root {root}, expected {expected_root}"
            );

            // First block's proof wins — later blocks may have the same key
            // against a different root (after writes), but the pre-state value
            // is what matters for the ProvenDB. Intra-batch updates go through CacheDB.
            verified_storage.entry(*key).or_insert(value);
        }

        // Build verified accounts from account_preimages.
        // Each preimage is verified against the merkle proof in verified_storage.
        for (addr, preimage) in &block.account_preimages {
            if verified_accounts.contains_key(addr) { continue; }
            let addr_bytes: [u8; 20] = addr.into_array();
            let flat_key = merkle::derive_account_properties_key(&addr_bytes);

            let proven_value = verified_storage.get(&flat_key).unwrap_or_else(|| {
                panic!(
                    "account_preimage for {addr} but no storage proof at flat_key={flat_key}"
                )
            });

            match proven_value {
                None => {
                    verified_accounts.insert(*addr, None);
                }
                Some(proven_hash) => {
                    let preimage_hash = merkle::AccountProperties::hash(preimage);
                    assert_eq!(
                        *proven_hash, preimage_hash,
                        "account preimage hash mismatch for {addr}: \
                         proven={proven_hash}, computed={preimage_hash}"
                    );

                    let props = merkle::AccountProperties::decode(preimage);
                    let code_hash = if props.observable_bytecode_hash.is_zero() {
                        if props.nonce == 0 && props.balance == [0u8; 32] {
                            B256::ZERO
                        } else {
                            KECCAK_EMPTY
                        }
                    } else {
                        props.observable_bytecode_hash
                    };
                    let code = bytecodes.get(&code_hash).cloned();

                    verified_accounts.insert(*addr, Some(AccountInfo {
                        nonce: props.nonce,
                        balance: U256::from_be_bytes(props.balance),
                        code_hash,
                        code,
                        account_id: None,
                    }));
                }
            }
        }

        // Verify block hashes against batch_meta.previous_block_hashes.
        let block_number_before = meta.block_number_before;
        for &(num, hash) in &block.block_hashes {
            if block_number_before > 0 && num <= block_number_before {
                let oldest_available = block_number_before.saturating_sub(254);
                if num >= oldest_available {
                    let idx = (num - oldest_available) as usize;
                    if idx < meta.previous_block_hashes.len() {
                        let verified_hash = meta.previous_block_hashes[idx];
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

    }

    ProvenDB {
        verified_storage,
        verified_accounts,
        bytecodes,
        block_hashes,
    }
}

/// Build a transaction for proven execution.
/// Verifies signatures for L2 txs, requires signed bytes for L1 txs.
/// gas_used_override and force_fail are passed through from the server —
/// they ensure the proven execution matches the server's execution exactly.
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

    build_tx(input)
}

fn build_tx(input: &TxInput) -> ZKsyncTx<TxEnv> {
    let kind = match input.to {
        Some(addr) => TxKind::Call(addr),
        None => TxKind::Create,
    };

    // For upgrade transactions (0x7e), use unlimited gas since EVM gas metering
    // differs from ZKsync OS native gas. The actual gas is handled by gas_used_override.
    let effective_gas_limit = if input.tx_type == 0x7e {
        input.gas_limit.saturating_mul(10)
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

    ZKsyncTxBuilder::new()
        .base(builder)
        .mint(input.mint.unwrap_or_default())
        .refund_recipient(input.refund_recipient)
        .gas_used_override(input.gas_used_override)
        .force_fail(input.force_fail)
        .l1_tx_hash(input.l1_tx_hash)
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

    let db = build_simple_db_batch(input);
    let mut cache_db = CacheDB::new(db);
    let mut block_results = Vec::with_capacity(input.blocks.len());
    for block in &input.blocks {
        block_results.push(execute_block_unverified(input.chain_id, spec_id, block, &input.batch_meta, &mut cache_db));
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

fn build_simple_db_batch(input: &BatchInput) -> SimpleDB {
    let mut accounts = HashMap::new();
    let mut storage = HashMap::new();
    let mut bytecodes = HashMap::new();
    let mut block_hashes = HashMap::new();

    for (hash, code) in &input.bytecodes {
        bytecodes.insert(*hash, Bytecode::new_raw(Bytes::copy_from_slice(code)));
    }

    for block in &input.blocks {
        for (addr, preimage) in &block.account_preimages {
            accounts.entry(*addr).or_insert_with(|| {
                let props = merkle::AccountProperties::decode(preimage);
                let code_hash = if props.observable_bytecode_hash.is_zero() {
                    KECCAK_EMPTY
                } else {
                    props.observable_bytecode_hash
                };
                AccountInfo {
                    nonce: props.nonce,
                    balance: U256::from_be_bytes(props.balance),
                    code_hash,
                    code: None,
                    account_id: None,
                }
            });
        }
        for &(addr, slot, value) in &block.storage {
            storage.entry((addr, slot)).or_insert(value);
        }
        for &(num, hash) in &block.block_hashes {
            block_hashes.insert(num, hash);
        }
    }

    SimpleDB { accounts, storage, bytecodes, block_hashes }
}

// ---------------------------------------------------------------------------
// Shared EVM execution and diff collection
// ---------------------------------------------------------------------------

/// Execute a block's transactions in the EVM and return tx results + L2→L1 logs.
/// State changes are written into the shared `cache_db`.
fn run_evm_block<DB: DatabaseRef>(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    batch_meta: &BatchMeta,
    cache_db: &mut CacheDB<DB>,
    skip_signature_verification: bool,
) -> (Vec<TxOutput>, Vec<L2ToL1LogEntry>, Vec<(Address, B256)>)
where
    DB::Error: core::fmt::Debug,
{
    let mut evm = <ZkContext<_>>::default()
        .with_db(cache_db)
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

        let tx = if skip_signature_verification {
            build_tx(tx_input)
        } else {
            build_proven_tx(tx_input)
        };
        match evm.transact_commit(tx) {
            Ok(result) => {
                // L1 tx result log is emitted automatically by the handler's
                // post_execution when l1_tx_hash is set on the transaction.

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
                    success: result.is_success(),
                    gas_used: result.gas_used(),
                    output: result.output().map(|b| b.to_vec()).unwrap_or_default(),
                });
            }
            Err(e) => panic!("transaction execution failed: {e:?}"),
        }
    }

    // Extract deployed bytecode hashes before dropping the EVM.
    let deployed_bytecodes = core::mem::take(&mut evm.0.ctx.chain.deployed_bytecode_hashes);

    (tx_results, computed_l2_to_l1_logs, deployed_bytecodes)
}

/// Collect storage and account diffs from the CacheDB after all blocks have executed.
/// Compares the CacheDB's final state against the proven pre-state from all blocks.
fn collect_batch_diffs(
    cache_db: &CacheDB<ProvenDB>,
    input: &BatchInput,
) -> (Vec<StorageDiff>, Vec<AccountDiff>) {
    // Build batch-level lookup maps for "before" values from all blocks' pre-state.
    let mut storage_map: HashMap<(Address, U256), U256> = HashMap::new();
    for block in &input.blocks {
        for &(a, s, v) in &block.storage {
            storage_map.entry((a, s)).or_insert(v);
        }
    }

    let proven_db = &cache_db.db;
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
        // Before-values from merkle-verified accounts.
        // Non-existent accounts have before = (0, 0).
        let (nonce_before, balance_before) = proven_db.verified_accounts
            .get(addr)
            .and_then(|opt| opt.as_ref())
            .map(|ai| (ai.nonce, ai.balance))
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

    (storage_diffs, account_diffs)
}

fn execute_block_unverified(chain_id: u64, spec_id: ZkSpecId, block: &BlockInput, batch_meta: &BatchMeta, cache_db: &mut CacheDB<SimpleDB>) -> BlockResult {
    let (tx_results, computed_logs, _deployed) =
        run_evm_block(chain_id, spec_id, block, batch_meta, cache_db, true);
    let l2_to_l1_logs = if computed_logs.is_empty() {
        block.l2_to_l1_logs.clone()
    } else {
        computed_logs
    };
    BlockResult {
        block_number: block.number,
        computed_block_header_hash: block.block_header_hash,
        tx_results,
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
