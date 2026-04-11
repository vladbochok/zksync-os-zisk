//! Transaction authentication and construction.
//!
//! All execution-critical fields are derived from cryptographically
//! authenticated data: RLP-encoded signed bytes for L2, ABI encoding
//! for L1/Upgrade. Only ZiSK-specific hints (gas_used_override, force_fail)
//! come from the untrusted TxInput.

use revm::context::TxEnv;
use revm::primitives::{Address, B256, Bytes, U256};
use zksync_os_revm::transaction::abstraction::ZKsyncTxBuilder;
use zksync_os_revm::ZKsyncTx;

use crate::types::*;

// L2CanonicalTransaction ABI layout (after the 32-byte outer offset word).
// See zksync-era/contracts/l1-contracts/contracts/common/Messaging.sol
mod abi_layout {
    pub const OUTER_OFFSET: usize = 32;
    pub const TX_TYPE: usize = 0;
    pub const FROM: usize = 1;
    pub const TO: usize = 2;
    pub const GAS_LIMIT: usize = 3;
    pub const MAX_FEE_PER_GAS: usize = 5;
    pub const NONCE: usize = 8;
    pub const VALUE: usize = 9;
    pub const MINT: usize = 10;      // reserved[0]
    pub const REFUND: usize = 11;    // reserved[1]
    pub const DATA_OFFSET: usize = 14;

    pub fn word(abi: &[u8], field: usize) -> alloy_primitives::U256 {
        let off = OUTER_OFFSET + field * 32;
        alloy_primitives::U256::from_be_slice(&abi[off..off + 32])
    }

    pub fn addr(abi: &[u8], field: usize) -> alloy_primitives::Address {
        alloy_primitives::Address::from_slice(&word(abi, field).to_be_bytes::<32>()[12..])
    }

    /// Extract the dynamic `data` (calldata) field from the ABI encoding.
    pub fn data(abi: &[u8]) -> Vec<u8> {
        let rel_offset: usize = word(abi, DATA_OFFSET).to();
        let abs_offset = OUTER_OFFSET + rel_offset;
        let len: usize = alloy_primitives::U256::from_be_slice(
            &abi[abs_offset..abs_offset + 32],
        ).to();
        abi[abs_offset + 32..abs_offset + 32 + len].to_vec()
    }
}

/// Verify the transaction's authenticity, compute its hash, and build
/// the REVM transaction.
///
/// All execution fields are derived from the authenticated source:
/// - L1/Upgrade: from the ABI encoding (hash-verified against tx_hash)
/// - L2: from the RLP-encoded signed bytes (signature-verified via ecrecover)
///
/// Only `gas_used_override` and `force_fail` are taken from TxInput.
pub(super) fn build_proven_tx(input: &TxInput) -> (ZKsyncTx<TxEnv>, B256) {
    match &input.auth {
        TxAuth::L1 { tx_hash, abi_encoded } | TxAuth::Upgrade { tx_hash, abi_encoded } => {
            build_l1_upgrade_tx(input, tx_hash, abi_encoded)
        }
        TxAuth::L2 { signed_bytes } => build_l2_tx(input, signed_bytes),
    }
}

/// Build a transaction from ABI-encoded L2CanonicalTransaction data.
/// All execution fields are extracted from the ABI encoding, which is
/// hash-verified: keccak256(abi_encoded) == tx_hash.
fn build_l1_upgrade_tx(
    input: &TxInput,
    tx_hash: &B256,
    abi_encoded: &[u8],
) -> (ZKsyncTx<TxEnv>, B256) {
    // Verify the ABI encoding hashes to the claimed tx_hash.
    let computed = crate::hash::keccak256(abi_encoded);
    assert_eq!(
        computed, *tx_hash,
        "tx hash mismatch: keccak256(abi)={computed}, claimed={tx_hash}"
    );

    // Extract all execution fields from the ABI encoding.
    let tx_type: u8 = abi_layout::word(abi_encoded, abi_layout::TX_TYPE).to();
    let caller = abi_layout::addr(abi_encoded, abi_layout::FROM);
    let to = abi_layout::addr(abi_encoded, abi_layout::TO);
    let value = abi_layout::word(abi_encoded, abi_layout::VALUE);
    let raw_gas_limit: u64 = abi_layout::word(abi_encoded, abi_layout::GAS_LIMIT).to();
    let gas_price = abi_layout::word(abi_encoded, abi_layout::MAX_FEE_PER_GAS);
    let nonce: u64 = abi_layout::word(abi_encoded, abi_layout::NONCE).to();
    let mint = abi_layout::word(abi_encoded, abi_layout::MINT);
    let refund_recipient = abi_layout::addr(abi_encoded, abi_layout::REFUND);
    let data = abi_layout::data(abi_encoded);

    // Upgrade txs get extra gas headroom (EVM gas >> native gas).
    let gas_limit = if tx_type == 0x7e {
        raw_gas_limit.saturating_mul(10)
    } else {
        raw_gas_limit
    };

    let revm_kind = revm::primitives::TxKind::Call(to);

    let builder = TxEnv::builder()
        .caller(caller)
        .gas_limit(gas_limit)
        .gas_price(gas_price.to::<u128>())
        .kind(revm_kind)
        .value(value)
        .data(Bytes::from(data))
        .nonce(nonce)
        .tx_type(Some(tx_type))
        .chain_id(input.chain_id)
        .blob_hashes(vec![]);

    let refund = if refund_recipient.is_zero() {
        None
    } else {
        Some(refund_recipient)
    };

    let tx = ZKsyncTxBuilder::new()
        .base(builder)
        .mint(mint)
        .refund_recipient(refund)
        .gas_used_override(input.gas_used_override)
        .force_fail(input.force_fail)
        .tx_hash(*tx_hash)
        .build()
        .expect("failed to build ZKsyncTx");

    (tx, *tx_hash)
}

/// Build a transaction from EIP-2718 RLP-encoded signed bytes.
/// All execution fields are decoded from the signed envelope. The signature
/// is verified via ecrecover to authenticate the caller.
fn build_l2_tx(input: &TxInput, signed_bytes: &[u8]) -> (ZKsyncTx<TxEnv>, B256) {
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_consensus::TxEnvelope;
    use alloy_eips::Decodable2718;
    use alloy_consensus::Transaction;

    let envelope = TxEnvelope::decode_2718(&mut &signed_bytes[..])
        .expect("failed to decode EIP-2718 signed transaction");

    let caller = envelope
        .recover_signer()
        .expect("failed to recover signer from transaction signature");

    let tx_hash = crate::hash::keccak256(signed_bytes);

    // Extract all execution fields from the decoded envelope.
    let revm_kind = match envelope.to() {
        Some(addr) => revm::primitives::TxKind::Call(addr),
        None => revm::primitives::TxKind::Create,
    };
    let value = envelope.value();
    let data = envelope.input().clone();
    let nonce = envelope.nonce();
    let gas_limit = envelope.gas_limit();
    let gas_price = envelope.max_fee_per_gas();
    let gas_priority_fee = envelope.max_priority_fee_per_gas();
    let chain_id = envelope.chain_id().or(input.chain_id);
    let tx_type = envelope.tx_type() as u8;

    let mut builder = TxEnv::builder()
        .caller(caller)
        .gas_limit(gas_limit)
        .gas_price(gas_price)
        .kind(revm_kind)
        .value(value)
        .data(data)
        .nonce(nonce)
        .tx_type(Some(tx_type))
        .chain_id(chain_id)
        .blob_hashes(vec![]);

    if let Some(fee) = gas_priority_fee {
        builder = builder.gas_priority_fee(Some(fee));
    }

    let tx = ZKsyncTxBuilder::new()
        .base(builder)
        .mint(U256::ZERO)
        .refund_recipient(None)
        .gas_used_override(input.gas_used_override)
        .force_fail(input.force_fail)
        .tx_hash(tx_hash)
        .build()
        .expect("failed to build ZKsyncTx");

    (tx, tx_hash)
}
