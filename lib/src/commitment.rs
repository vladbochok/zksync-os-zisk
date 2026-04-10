//! Batch commitment computation: Keccak-based hashing for state commitments,
//! batch output hashes, L2→L1 log merkle trees, DA commitments, and priority ops.

use alloy_primitives::B256;
use blake2::digest::FixedOutput;
use blake2::{Blake2s256, Digest};

// Re-export the accelerated keccak256.
pub(crate) use crate::hash::keccak256;

fn keccak_compress(lhs: &B256, rhs: &B256) -> B256 {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(lhs.as_slice());
    data[32..64].copy_from_slice(rhs.as_slice());
    keccak256(&data)
}

/// Keccak256 of two concatenated B256 values.
pub fn keccak_two(a: &B256, b: &B256) -> B256 {
    keccak_compress(a, b)
}

// ---------------------------------------------------------------------------
// State commitment (Blake2s)
// ---------------------------------------------------------------------------

/// Compute the state commitment hash:
/// Blake2s256(tree_root || leaf_count_be8 || block_number_be8 || block_hashes_blake || timestamp_be8)
pub fn state_commitment_hash(
    tree_root: &B256,
    leaf_count: u64,
    block_number: u64,
    block_hashes_blake: &B256,
    last_block_timestamp: u64,
) -> B256 {
    let mut h = Blake2s256::new();
    h.update(tree_root.as_slice());
    h.update(leaf_count.to_be_bytes());
    h.update(block_number.to_be_bytes());
    h.update(block_hashes_blake.as_slice());
    h.update(last_block_timestamp.to_be_bytes());
    B256::from_slice(&h.finalize_fixed())
}

/// Compute the last_256_block_hashes_blake:
/// Blake2s256(block_hash[1] || block_hash[2] || ... || block_hash[255] || current_block_hash)
/// where block_hash[i] are the previous 255 block hashes (index 1..=255 of the 256-entry array).
pub fn block_hashes_blake(previous_255_hashes: &[B256], current_block_hash: &B256) -> B256 {
    // Match Airbender: block_hashes.0.iter().skip(1) then current.
    // Order: [block_hashes[1], ..., block_hashes[255], current_block_hash]
    let mut h = Blake2s256::new();
    for hash in previous_255_hashes {
        h.update(hash.as_slice());
    }
    h.update(current_block_hash.as_slice());
    B256::from_slice(&h.finalize_fixed())
}

// ---------------------------------------------------------------------------
// L2→L1 logs Keccak merkle tree (height 14)
// ---------------------------------------------------------------------------

pub const L2_TO_L1_LOG_SIZE: usize = 88;
const L2_TO_L1_TREE_HEIGHT: usize = 14;

/// Compute the L2→L1 logs merkle root (Keccak binary tree, height 14).
/// Each leaf is keccak256 of an 88-byte encoded L2ToL1Log.
/// Empty leaves are keccak256([0u8; 88]).
pub fn l2_to_l1_logs_root(encoded_logs: &[[u8; L2_TO_L1_LOG_SIZE]]) -> B256 {
    let empty_leaf = keccak256(&[0u8; L2_TO_L1_LOG_SIZE]);
    let mut empty_hashes = vec![empty_leaf];
    for _ in 0..L2_TO_L1_TREE_HEIGHT {
        let prev = *empty_hashes.last().unwrap();
        empty_hashes.push(keccak_compress(&prev, &prev));
    }

    if encoded_logs.is_empty() {
        return empty_hashes[L2_TO_L1_TREE_HEIGHT];
    }

    let mut hashes: Vec<B256> = encoded_logs.iter().map(|log| keccak256(log)).collect();
    let mut non_default_count = hashes.len();

    for level in 0..L2_TO_L1_TREE_HEIGHT {
        let pairs = (non_default_count + 1) / 2;
        for i in 0..pairs {
            let left = hashes[i * 2];
            let right = if i * 2 + 1 < non_default_count {
                hashes[i * 2 + 1]
            } else {
                empty_hashes[level]
            };
            hashes[i] = keccak_compress(&left, &right);
        }
        non_default_count = pairs;
    }

    if non_default_count > 0 {
        hashes[0]
    } else {
        empty_hashes[L2_TO_L1_TREE_HEIGHT]
    }
}

// ---------------------------------------------------------------------------
// Batch output hash
// ---------------------------------------------------------------------------

/// Compute the batch output hash (protocol v30).
pub fn batch_output_hash_v30(
    chain_id: u64,
    first_block_timestamp: u64,
    last_block_timestamp: u64,
    da_commitment_scheme: u8,
    da_commitment: &B256,
    number_of_layer1_txs: u64,
    priority_operations_hash: &B256,
    l2_to_l1_logs_root_hash: &B256,
    upgrade_tx_hash: &B256,
    dependency_roots_rolling_hash: &B256,
) -> B256 {
    let mut data = Vec::with_capacity(320);
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&chain_id.to_be_bytes());
    data.extend_from_slice(&first_block_timestamp.to_be_bytes());
    data.extend_from_slice(&last_block_timestamp.to_be_bytes());
    data.extend_from_slice(&[0u8; 31]);
    data.push(da_commitment_scheme);
    data.extend_from_slice(da_commitment.as_slice());
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&number_of_layer1_txs.to_be_bytes());
    data.extend_from_slice(priority_operations_hash.as_slice());
    data.extend_from_slice(l2_to_l1_logs_root_hash.as_slice());
    data.extend_from_slice(upgrade_tx_hash.as_slice());
    data.extend_from_slice(dependency_roots_rolling_hash.as_slice());
    keccak256(&data)
}

/// Compute the batch output hash (protocol v31+).
pub fn batch_output_hash_v31(
    chain_id: u64,
    first_block_timestamp: u64,
    last_block_timestamp: u64,
    da_commitment_scheme: u8,
    da_commitment: &B256,
    number_of_layer1_txs: u64,
    number_of_layer2_txs: u64,
    priority_operations_hash: &B256,
    l2_to_l1_logs_root_hash: &B256,
    upgrade_tx_hash: &B256,
    dependency_roots_rolling_hash: &B256,
    sl_chain_id: u64,
) -> B256 {
    let mut data = Vec::with_capacity(384);
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&chain_id.to_be_bytes());
    data.extend_from_slice(&first_block_timestamp.to_be_bytes());
    data.extend_from_slice(&last_block_timestamp.to_be_bytes());
    data.extend_from_slice(&[0u8; 31]);
    data.push(da_commitment_scheme);
    data.extend_from_slice(da_commitment.as_slice());
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&number_of_layer1_txs.to_be_bytes());
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&number_of_layer2_txs.to_be_bytes());
    data.extend_from_slice(priority_operations_hash.as_slice());
    data.extend_from_slice(l2_to_l1_logs_root_hash.as_slice());
    data.extend_from_slice(upgrade_tx_hash.as_slice());
    data.extend_from_slice(dependency_roots_rolling_hash.as_slice());
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&sl_chain_id.to_be_bytes());
    keccak256(&data)
}

/// Priority operations rolling hash.
/// Initial: keccak256([]) = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
/// For each L1 tx: hash = keccak256(prev_hash || tx_hash)
pub fn priority_ops_rolling_hash(l1_tx_hashes: &[B256]) -> B256 {
    let mut hash = keccak256(&[]);
    for tx_hash in l1_tx_hashes {
        hash = keccak_compress(&hash, tx_hash);
    }
    hash
}

/// DA commitment for calldata mode:
/// keccak256(0x00*32 || keccak256(pubdata) || 0x01 || 0x00*32)
pub fn da_commitment_calldata(pubdata: &[u8]) -> B256 {
    let mut data = Vec::with_capacity(97);
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(keccak256(pubdata).as_slice());
    data.push(1u8);
    data.extend_from_slice(&[0u8; 32]);
    keccak256(&data)
}

/// DA commitment for blob mode (BlobsZKsyncOS, scheme=4):
/// keccak256(versioned_hash_0 || versioned_hash_1 || ...)
pub fn da_commitment_blobs(versioned_hashes: &[B256]) -> B256 {
    let mut data = Vec::with_capacity(versioned_hashes.len() * 32);
    for hash in versioned_hashes {
        data.extend_from_slice(hash.as_slice());
    }
    keccak256(&data)
}

/// Transactions rolling hash (used as transactions_root in block header).
/// Start with 0x00...00, then for each tx: hash = keccak256(prev_hash || tx_hash)
pub fn transactions_rolling_hash(tx_hashes: &[B256]) -> B256 {
    let mut hash = B256::ZERO;
    for tx_hash in tx_hashes {
        hash = keccak_compress(&hash, tx_hash);
    }
    hash
}

/// Full batch public input hash:
/// Keccak256(state_before || state_after || batch_output_hash)
pub fn batch_public_input_hash(
    state_before: &B256,
    state_after: &B256,
    batch_output_hash: &B256,
) -> B256 {
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(state_before.as_slice());
    data[32..64].copy_from_slice(state_after.as_slice());
    data[64..96].copy_from_slice(batch_output_hash.as_slice());
    keccak256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ops_hash_empty() {
        let expected: B256 =
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                .parse()
                .unwrap();
        assert_eq!(priority_ops_rolling_hash(&[]), expected);
    }

    #[test]
    fn l2_logs_root_empty() {
        let root = l2_to_l1_logs_root(&[]);
        let empty_leaf = keccak256(&[0u8; L2_TO_L1_LOG_SIZE]);
        let mut h = empty_leaf;
        for _ in 0..L2_TO_L1_TREE_HEIGHT {
            h = keccak_compress(&h, &h);
        }
        assert_eq!(root, h);
    }
}
