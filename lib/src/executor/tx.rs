//! Transaction authentication and construction.
//!
//! Verifies tx hashes (keccak of ABI encoding for L1, ecrecover for L2),
//! checks execution-critical ABI fields, and builds REVM transactions.

use revm::context::TxEnv;
use revm::primitives::{Address, B256, Bytes};
use zksync_os_revm::transaction::abstraction::ZKsyncTxBuilder;
use zksync_os_revm::ZKsyncTx;

use crate::types::*;

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
pub(super) fn build_proven_tx(input: &TxInput) -> (ZKsyncTx<TxEnv>, B256) {
    let tx_hash = match &input.auth {
        TxAuth::L1 { tx_hash, abi_encoded } | TxAuth::Upgrade { tx_hash, abi_encoded } => {
            // Verify keccak256(abi_encoded) == tx_hash.
            let computed = crate::hash::keccak256(abi_encoded);
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
            crate::hash::keccak256(signed_bytes)
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
