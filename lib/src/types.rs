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
    /// After-state account property preimages (124 bytes each).
    /// For each account whose 0x8003 value changed, the server provides the
    /// full after-state preimage. The executor verifies nonce/balance match
    /// REVM's output, then checks blake2s(preimage) == tree_update value.
    #[serde(default)]
    pub account_preimages_after: Vec<(Address, Vec<u8>)>,
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

/// Transaction authentication and hash binding.
///
/// Each variant carries the raw bytes from which all execution fields are
/// derived. The executor verifies and extracts:
/// - L1/Upgrade: `keccak256(abi_encoded) == tx_hash`, then decodes all fields from ABI
/// - L2: `ecrecover(signed_bytes)` recovers caller, all fields decoded from RLP
#[derive(Serialize, Deserialize, Clone)]
pub enum TxAuth {
    /// L1 priority deposit. `abi_encoded` is the ABI-encoded L2CanonicalTransaction
    /// whose `keccak256` equals `tx_hash`. All execution fields are extracted from it.
    L1 { tx_hash: B256, abi_encoded: Vec<u8> },
    /// Protocol upgrade transaction. Same ABI encoding as L1.
    Upgrade { tx_hash: B256, abi_encoded: Vec<u8> },
    /// L2 transaction. `signed_bytes` is EIP-2718 encoded; all execution fields
    /// are decoded from the RLP envelope, caller recovered via ecrecover.
    L2 { signed_bytes: Vec<u8> },
}

/// Transaction input for the ZiSK executor.
///
/// Execution-critical fields (caller, to, value, data, nonce, gas_limit,
/// gas_price) are derived from the authenticated `auth` data — NOT from
/// this struct. Only `chain_id` (for L1/upgrade, not in ABI),
/// `gas_used_override`, and `force_fail` are used from here.
#[derive(Serialize, Deserialize, Clone)]
pub struct TxInput {
    /// L2 chain ID. Used for L1/upgrade txs (not present in ABI encoding)
    /// and as fallback for L2 txs without chain_id in the envelope.
    pub chain_id: Option<u64>,
    /// Gas used override from the server's execution.
    /// When set, REVM uses this instead of its own gas computation.
    pub gas_used_override: Option<u64>,
    /// When true, REVM synthesizes a REVERT without executing the transaction.
    pub force_fail: bool,
    /// Transaction authentication and hash binding.
    /// All execution fields are derived from this.
    pub auth: TxAuth,
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

