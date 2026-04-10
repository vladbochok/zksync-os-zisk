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
        if code_hash.is_zero() || code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        self.bytecodes.get(&code_hash).cloned().ok_or_else(|| {
            ProvenDBError(format!(
                "no bytecode for code_hash {code_hash}. The server must include \
                 all contract bytecodes in the batch."
            ))
        })
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
    let proven_db = build_proven_db(input);
    let mut cache_db = CacheDB::new(proven_db);

    let mut block_results = Vec::with_capacity(input.blocks.len());
    let mut computed_block_hashes: HashMap<u64, B256> = HashMap::new();

    for block in &input.blocks {
        verify_intra_batch_hashes(block, &computed_block_hashes);

        let result = execute_block_proven(
            input.chain_id, spec_id, block, &mut cache_db,
        );
        computed_block_hashes.insert(block.number, result.computed_block_header_hash);
        block_results.push(result);
    }

    let output = BatchOutput { chain_id: input.chain_id, block_results };

    // Build complete write map (storage + 0x8003 account properties) and verify.
    let revm_writes = build_revm_write_map(&cache_db, &meta.account_preimages_after);
    let (tree_root_after, new_leaf_count) = verify_tree_update(meta, &revm_writes);

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

/// Execute a single block using the shared batch-level CacheDB.
/// Writes from this block remain in the CacheDB for subsequent blocks.
fn execute_block_proven(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    cache_db: &mut CacheDB<ProvenDB>,
) -> BlockResult {
    let (tx_results, tx_hashes, computed_l2_to_l1_logs) =
        run_evm_block(chain_id, spec_id, block, cache_db);

    let total_gas_used: u64 = tx_results.iter().map(|t| t.gas_used).sum();
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
        l2_to_l1_logs: computed_l2_to_l1_logs,
    }
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

// L2CanonicalTransaction ABI layout (after the 32-byte outer offset word).
// See zksync-era/contracts/l1-contracts/contracts/common/Messaging.sol
mod abi_layout {
    pub const OUTER_OFFSET: usize = 32;
    pub const FROM: usize = 1;
    pub const TO: usize = 2;
    pub const VALUE: usize = 9;
    pub const MINT: usize = 10;      // reserved[0]
    pub const REFUND: usize = 11;    // reserved[1]

    pub fn word(abi: &[u8], field: usize) -> alloy_primitives::U256 {
        let off = OUTER_OFFSET + field * 32;
        alloy_primitives::U256::from_be_slice(&abi[off..off + 32])
    }

    pub fn addr(abi: &[u8], field: usize) -> alloy_primitives::Address {
        alloy_primitives::Address::from_slice(&word(abi, field).to_be_bytes::<32>()[12..])
    }
}

/// Verify the transaction's authenticity, compute its hash, and build
/// the REVM transaction. Returns (ZKsyncTx, tx_hash).
fn build_proven_tx(input: &TxInput) -> (ZKsyncTx<TxEnv>, B256) {
    let tx_hash = match &input.auth {
        TxAuth::L1 { tx_hash, abi_encoded } | TxAuth::Upgrade { tx_hash, abi_encoded } => {
            // Verify keccak256(abi_encoded) == tx_hash.
            let computed = alloy_primitives::keccak256(abi_encoded);
            assert_eq!(computed, *tx_hash,
                "tx hash mismatch: keccak256(abi)={computed}, claimed={tx_hash}");

            // Verify execution-critical ABI fields match TxInput.
            assert_eq!(abi_layout::word(abi_encoded, abi_layout::VALUE), input.value,
                "ABI value != TxInput.value");
            if let Some(mint) = input.mint {
                assert_eq!(abi_layout::word(abi_encoded, abi_layout::MINT), mint,
                    "ABI mint != TxInput.mint");
            }
            if let Some(refund) = input.refund_recipient {
                assert_eq!(abi_layout::addr(abi_encoded, abi_layout::REFUND), refund,
                    "ABI refund_recipient != TxInput.refund_recipient");
            }
            // For L1 priority txs, also verify caller/to (upgrade txs have
            // different L2 caller vs L1 initiator).
            if matches!(input.auth, TxAuth::L1 { .. }) {
                assert_eq!(abi_layout::addr(abi_encoded, abi_layout::FROM), input.caller,
                    "ABI from != TxInput.caller");
                if let Some(to) = input.to {
                    assert_eq!(abi_layout::addr(abi_encoded, abi_layout::TO), to,
                        "ABI to != TxInput.to");
                }
            }
            *tx_hash
        }
        TxAuth::L2 { signed_bytes } => {
            let recovered = recover_signer(signed_bytes);
            assert_eq!(recovered, input.caller,
                "ecrecover: recovered {recovered}, expected {}", input.caller);
            alloy_primitives::keccak256(signed_bytes)
        }
    };

    let revm_kind = match input.to {
        Some(addr) => revm::primitives::TxKind::Call(addr),
        None => revm::primitives::TxKind::Create,
    };

    // Upgrade txs get extra gas headroom (EVM gas >> native gas).
    let gas_limit = if input.tx_type == 0x7e {
        input.gas_limit.saturating_mul(10)
    } else {
        input.gas_limit
    };

    let mut builder = TxEnv::builder()
        .caller(input.caller)
        .gas_limit(gas_limit)
        .gas_price(input.gas_price)
        .kind(revm_kind)
        .value(input.value)
        .data(Bytes::copy_from_slice(&input.data))
        .nonce(input.nonce)
        .tx_type(Some(input.tx_type))
        .chain_id(input.chain_id)
        .blob_hashes(vec![]);

    if let Some(fee) = input.gas_priority_fee {
        builder = builder.gas_priority_fee(Some(fee));
    }

    let tx = ZKsyncTxBuilder::new()
        .base(builder)
        .mint(input.mint.unwrap_or_default())
        .refund_recipient(input.refund_recipient)
        .gas_used_override(input.gas_used_override)
        .force_fail(input.force_fail)
        .tx_hash(tx_hash)
        .build()
        .expect("failed to build ZKsyncTx");

    (tx, tx_hash)
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
// Shared EVM execution and diff collection
// ---------------------------------------------------------------------------

/// Execute a block's transactions in the EVM and return tx results + L2→L1 logs.
/// State changes are written into the shared `cache_db`.
fn run_evm_block<DB: DatabaseRef>(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    cache_db: &mut CacheDB<DB>,
) -> (Vec<TxOutput>, Vec<B256>, Vec<L2ToL1LogEntry>)
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
    let mut tx_hashes = Vec::with_capacity(block.transactions.len());
    let mut l2_to_l1_logs = Vec::new();

    for (tx_idx, tx_input) in block.transactions.iter().enumerate() {
        evm.0.ctx.chain.set_tx_number(tx_idx as u16);

        let (tx, tx_hash) = build_proven_tx(tx_input);
        tx_hashes.push(tx_hash);

        match evm.transact_commit(tx) {
            Ok(result) => {
                for log in evm.0.ctx.chain.take_logs() {
                    l2_to_l1_logs.push(L2ToL1LogEntry {
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

    (tx_results, tx_hashes, l2_to_l1_logs)
}

/// Build the complete write map: flat_key → new_value for both regular storage
/// writes and 0x8003 account-property writes. For 0x8003, the server provides
/// after-state preimages; we verify nonce/balance match REVM output, then use
/// blake2s(preimage) as the value.
fn build_revm_write_map(
    cache_db: &CacheDB<ProvenDB>,
    after_preimages: &[(Address, Vec<u8>)],
) -> HashMap<B256, B256> {
    let proven_db = &cache_db.db;
    let after_map: HashMap<&Address, &Vec<u8>> = after_preimages.iter()
        .map(|(a, p)| (a, p)).collect();

    let mut writes = HashMap::new();

    for (addr, db_account) in cache_db.cache.accounts.iter() {
        if matches!(
            db_account.account_state,
            revm::database::AccountState::None | revm::database::AccountState::NotExisting
        ) {
            continue;
        }

        // Regular storage writes.
        let addr_bytes: [u8; 20] = addr.into_array();
        for (slot, value) in db_account.storage.iter() {
            let slot_u256 = U256::from_limbs((*slot).into_limbs());
            let slot_b256 = B256::from(slot_u256.to_be_bytes::<32>());
            let flat_key = merkle::derive_flat_storage_key(&addr_bytes, &slot_b256);
            let old_val = proven_db.verified_storage
                .get(&flat_key)
                .and_then(|v| *v)
                .map(|v| U256::from_be_bytes(v.0))
                .unwrap_or(U256::ZERO);
            let new_val = U256::from_limbs((*value).into_limbs());
            if old_val != new_val {
                writes.insert(flat_key, B256::from(new_val.to_be_bytes::<32>()));
            }
        }

        // 0x8003 account-property write: use server-provided after-preimage.
        if let Some(after_preimage) = after_map.get(addr) {
            let props = merkle::AccountProperties::decode(after_preimage);
            let info = &db_account.info;

            // Verify nonce and balance match REVM's execution.
            assert_eq!(props.nonce, info.nonce,
                "after-preimage nonce mismatch for {addr}: preimage={}, revm={}",
                props.nonce, info.nonce);
            assert_eq!(U256::from_be_bytes(props.balance), info.balance,
                "after-preimage balance mismatch for {addr}");

            let flat_key = merkle::derive_account_properties_key(&addr_bytes);
            writes.insert(flat_key, merkle::AccountProperties::hash(after_preimage));
        }
    }

    writes
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

/// Verify tree_update entries match computed writes.
/// Uses the set-theoretic identity: |A| == |B| ∧ A ⊆ B ⟹ A == B.
/// One length check + one forward pass — no reverse iteration needed.
fn verify_tree_update(
    meta: &BatchMeta,
    revm_writes: &HashMap<B256, B256>,
) -> (B256, u64) {
    match meta.tree_update {
        Some(ref tree_update) => {
            assert_eq!(
                revm_writes.len(), tree_update.entries.len(),
                "write count mismatch: computed {} writes, tree_update has {}",
                revm_writes.len(), tree_update.entries.len(),
            );
            for (key, tree_val) in &tree_update.entries {
                let computed_val = revm_writes.get(key).unwrap_or_else(||
                    panic!("tree_update has {key} not in computed writes"));
                assert_eq!(tree_val, computed_val,
                    "tree_update value mismatch for {key}: tree={tree_val}, computed={computed_val}");
            }
            tree_update.apply(&meta.tree_root_before)
        }
        None => {
            assert!(revm_writes.is_empty(), "writes exist but no tree_update provided");
            (meta.tree_root_before, meta.leaf_count_before)
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

