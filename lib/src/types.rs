//! Shared types for ZiSK guest/host communication.

use revm::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::merkle::{BatchTreeUpdate, StorageProof};

/// Complete batch input for the ZiSK guest.
#[derive(Serialize, Deserialize, Clone)]
pub struct BatchInput {
    pub chain_id: u64,
    /// ZKsync spec version (AtlasV1 = 0, AtlasV2 = 1).
    pub spec_id: u8,
    /// Protocol version minor (30 or 31) — determines batch hash format.
    pub protocol_version_minor: u32,
    pub blocks: Vec<BlockInput>,
    /// Batch-level metadata for commitment computation.
    pub batch_meta: BatchMeta,
    /// Contract bytecodes keyed by code hash (keccak256).
    /// Shared across all blocks in the batch.
    #[serde(default)]
    pub bytecodes: Vec<(B256, Vec<u8>)>,
}

/// Batch-level metadata needed for the commitment hash.
#[derive(Serialize, Deserialize, Clone)]
pub struct BatchMeta {
    /// Merkle tree root hash before this batch.
    pub tree_root_before: B256,
    /// Leaf count before this batch (includes 2 guard entries).
    pub leaf_count_before: u64,
    /// Block number before this batch.
    pub block_number_before: u64,
    /// Last block timestamp before batch.
    pub last_block_timestamp_before: u64,
    /// Blake2s hash of last 256 block hashes before this batch.
    /// This is part of the state commitment preimage and should be taken
    /// from the verified state commitment (e.g. via zks_getProof).
    pub block_hashes_blake_before: B256,
    /// Previous 255 block hashes (index 1..255 of the block_hashes array).
    pub previous_block_hashes: Vec<B256>,
    /// Upgrade tx hash if present (zero otherwise).
    pub upgrade_tx_hash: B256,
    /// DA commitment scheme (0=None, 1=EmptyNoDA, 2=PubdataKeccak, 3=BlobsAndPubdataKeccak, 4=BlobsZKsyncOS).
    pub da_commitment_scheme: u8,
    /// Raw pubdata bytes for DA commitment computation.
    pub pubdata: Vec<u8>,
    /// Multichain root for L2 logs tree (zero for v30).
    pub multichain_root: B256,
    /// Settlement layer chain ID (for v31+).
    pub sl_chain_id: u64,
    /// Blob versioned hashes for BlobsZKsyncOS DA mode (scheme=4).
    /// The host computes KZG commitments of the pubdata blobs and derives
    /// versioned hashes. The guest uses these to compute da_commitment =
    /// keccak256(versioned_hashes). KZG correctness is verified by L1 (EIP-4844).
    pub blob_versioned_hashes: Vec<B256>,
    /// Merkle tree update proof for computing state_after root.
    /// Contains old leaves, intermediate hashes, and write operations.
    /// If None, state_after root = state_before root (no writes — incomplete).
    pub tree_update: Option<BatchTreeUpdate>,
}

/// Single block input with pre-state and transactions.
#[derive(Serialize, Deserialize, Clone)]
pub struct BlockInput {
    pub number: u64,
    pub timestamp: u64,
    pub base_fee: u64,
    pub gas_limit: u64,
    pub coinbase: Address,
    pub prev_randao: B256,
    pub transactions: Vec<TxInput>,
    /// Account property preimages (124-byte encoded AccountProperties).
    /// Keyed by address. Used to decode nonce/balance/code_hash from the
    /// merkle-verified value at (0x8003, left_padded_address).
    pub account_preimages: Vec<(Address, Vec<u8>)>,
    /// Pre-state storage slots.
    pub storage: Vec<(Address, U256, U256)>,
    /// Block hashes for BLOCKHASH opcode.
    pub block_hashes: Vec<(u64, B256)>,
    /// Merkle proofs for every storage slot accessed. Key = flat_storage_key.
    pub storage_proofs: Vec<(B256, StorageProof)>,
    /// Block header hash (for block_hashes_blake computation).
    pub block_header_hash: B256,
    /// L2→L1 logs produced by this block's execution (from server's BlockOutput).
    /// These are included in the batch commitment's l2_to_l1_logs merkle tree.
    /// The guest verifies consistency by checking that L1Messenger EVM log events
    /// in the REVM execution match these L2→L1 log entries.
    pub l2_to_l1_logs: Vec<L2ToL1LogEntry>,
    /// Per-block tree root that this block's merkle proofs were extracted from.
    /// For the first block in a batch this equals batch_meta.tree_root_before.
    /// For subsequent blocks this is the tree root after prior blocks' writes.
    /// Defaults to B256::ZERO for backward compat (executor falls back to batch root).
    #[serde(default)]
    pub expected_tree_root: B256,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TxInput {
    pub caller: Address,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub gas_priority_fee: Option<u128>,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub chain_id: Option<u64>,
    pub tx_type: u8,
    /// Gas used override from the server's execution.
    /// When set, REVM uses this instead of its own gas computation.
    pub gas_used_override: Option<u64>,
    /// When true, REVM synthesizes a REVERT without executing the transaction.
    pub force_fail: bool,
    pub mint: Option<U256>,
    pub refund_recipient: Option<Address>,
    /// Is this an L1 priority transaction?
    pub is_l1_tx: bool,
    /// L1 tx hash for priority ops rolling hash.
    pub l1_tx_hash: Option<B256>,
    /// Raw RLP-encoded signed transaction bytes for signature verification.
    /// If present, the guest verifies ecrecover(signature) == caller.
    /// If absent, caller is trusted (only acceptable in unverified mode).
    pub signed_tx_bytes: Option<Vec<u8>>,
}

/// L2->L1 log entry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct L2ToL1LogEntry {
    pub l2_shard_id: u8,
    pub is_service: bool,
    pub tx_number_in_block: u16,
    pub sender: Address,
    pub key: B256,
    pub value: B256,
}

impl L2ToL1LogEntry {
    /// Encode to 88 bytes matching server's L2ToL1Log::encode.
    pub fn encode(&self) -> [u8; 88] {
        let mut buf = [0u8; 88];
        buf[0] = self.l2_shard_id;
        buf[1] = if self.is_service { 1 } else { 0 };
        buf[2..4].copy_from_slice(&self.tx_number_in_block.to_be_bytes());
        buf[4..24].copy_from_slice(self.sender.as_slice());
        buf[24..56].copy_from_slice(self.key.as_slice());
        buf[56..88].copy_from_slice(self.value.as_slice());
        buf
    }
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct BatchOutput {
    pub chain_id: u64,
    pub block_results: Vec<BlockResult>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockResult {
    pub block_number: u64,
    /// Block header hash computed from execution results.
    /// keccak256(RLP(parent_hash, ommers_hash, beneficiary, state_root=0,
    ///   transactions_root, receipts_root=0, logs_bloom=0, difficulty=0,
    ///   number, gas_limit, gas_used, timestamp, extra_data=[], mix_hash,
    ///   nonce=0, base_fee_per_gas))
    pub computed_block_header_hash: B256,
    pub tx_results: Vec<TxOutput>,
    pub l2_to_l1_logs: Vec<L2ToL1LogEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct TxOutput {
    pub success: bool,
    pub gas_used: u64,
    pub output: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct StorageDiff {
    pub address: Address,
    pub slot: U256,
    pub old_value: U256,
    pub new_value: U256,
}

#[derive(Serialize, Deserialize)]
pub struct AccountDiff {
    pub address: Address,
    pub nonce_before: u64,
    pub nonce_after: u64,
    pub balance_before: U256,
    pub balance_after: U256,
}
