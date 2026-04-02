//! Block header hash computation (RLP encoding + Keccak256).
//!
//! Computes the ZKsync OS block header hash using the same Ethereum block
//! header format as zksync-os's `basic_bootloader::block_header::BlockHeader`.
//! Several fields are fixed (post-merge constants, zero state/receipts roots).

use alloy_primitives::B256;

use crate::commitment::keccak256;

/// Keccak256(RLP([])) — the empty ommers hash (post-merge constant).
const EMPTY_OMMER_HASH: B256 = B256::new([
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67,
    0xb6, 0xcc, 0xd4, 0x1a, 0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13,
    0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
]);

/// Compute the ZKsync OS block header hash.
///
/// This is `keccak256(RLP([parent_hash, ommers_hash, beneficiary, state_root,
///   transactions_root, receipts_root, logs_bloom, difficulty, number,
///   gas_limit, gas_used, timestamp, extra_data, mix_hash, nonce, base_fee_per_gas]))`.
///
/// Fixed fields: `ommers_hash` = EMPTY_OMMER_HASH, `state_root` = 0, `receipts_root` = 0,
/// `logs_bloom` = 0, `difficulty` = 0, `extra_data` = empty, `nonce` = 0.
pub fn compute_block_header_hash(
    parent_hash: &B256,
    beneficiary: &[u8; 20],
    transactions_root: &B256,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    mix_hash: &B256,
    base_fee_per_gas: u64,
) -> B256 {
    let mut inner = Vec::with_capacity(650);

    rlp_encode_bytes(&mut inner, parent_hash.as_slice());
    rlp_encode_bytes(&mut inner, EMPTY_OMMER_HASH.as_slice());
    rlp_encode_bytes(&mut inner, beneficiary);
    rlp_encode_bytes(&mut inner, B256::ZERO.as_slice()); // state_root
    rlp_encode_bytes(&mut inner, transactions_root.as_slice());
    rlp_encode_bytes(&mut inner, B256::ZERO.as_slice()); // receipts_root
    rlp_encode_bytes(&mut inner, &[0u8; 256]); // logs_bloom
    rlp_encode_number(&mut inner, &[0u8; 32]); // difficulty
    rlp_encode_number(&mut inner, &number.to_be_bytes());
    rlp_encode_number(&mut inner, &gas_limit.to_be_bytes());
    rlp_encode_number(&mut inner, &gas_used.to_be_bytes());
    rlp_encode_number(&mut inner, &timestamp.to_be_bytes());
    rlp_encode_bytes(&mut inner, &[]); // extra_data
    rlp_encode_bytes(&mut inner, mix_hash.as_slice());
    rlp_encode_bytes(&mut inner, &[0u8; 8]); // nonce
    rlp_encode_number(&mut inner, &base_fee_per_gas.to_be_bytes());

    let mut buf = Vec::with_capacity(inner.len() + 5);
    rlp_encode_list_header(&mut buf, inner.len());
    buf.extend_from_slice(&inner);

    keccak256(&buf)
}

// ---------------------------------------------------------------------------
// Minimal RLP encoding (matching zksync-os's rlp module)
// ---------------------------------------------------------------------------

fn rlp_encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    if data.len() == 1 && data[0] < 0x80 {
        buf.push(data[0]);
    } else if data.len() < 56 {
        buf.push(0x80 + data.len() as u8);
        buf.extend_from_slice(data);
    } else {
        let len_bytes = be_bytes_trimmed(data.len());
        buf.push(0xb7 + len_bytes.len() as u8);
        buf.extend_from_slice(&len_bytes);
        buf.extend_from_slice(data);
    }
}

fn rlp_encode_number(buf: &mut Vec<u8>, be_bytes: &[u8]) {
    let stripped = strip_leading_zeros(be_bytes);
    if stripped.is_empty() {
        buf.push(0x80); // RLP encoding of zero = empty byte string
    } else {
        rlp_encode_bytes(buf, stripped);
    }
}

fn rlp_encode_list_header(buf: &mut Vec<u8>, content_len: usize) {
    if content_len < 56 {
        buf.push(0xc0 + content_len as u8);
    } else {
        let len_bytes = be_bytes_trimmed(content_len);
        buf.push(0xf7 + len_bytes.len() as u8);
        buf.extend_from_slice(&len_bytes);
    }
}

fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let first_nonzero = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[first_nonzero..]
}

/// Encode a usize as minimal big-endian bytes.
fn be_bytes_trimmed(val: usize) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}
