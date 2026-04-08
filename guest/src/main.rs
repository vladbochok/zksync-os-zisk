//! ZiSK guest: proves ZKsync OS block execution using REVM.
//!
//! Every storage read is verified against a merkle proof.
//! The committed output is the BatchPublicInput hash matching the L1 format.
//! There is no unverified path — the guest always runs proven execution.

#![no_main]

use zksync_os_zisk_lib::{crypto::CustomEvmCrypto, executor, types::BatchInput};

ziskos::entrypoint!(main);

fn main() {
    // Install ZiSK-native crypto (keccak, secp256k1, bn254, etc.)
    // before any REVM execution. On the ZiSK target this uses hardware-
    // accelerated circuits; on native it falls back to software.
    revm::install_crypto(CustomEvmCrypto::default());

    let batch_input: BatchInput = ziskos::io::read();
    let (_output, commitment) = executor::execute_and_commit(&batch_input);
    let hash_bytes: [u8; 32] = commitment.into();

    // ziskos::io::commit() writes bytes as u32 LE chunks, which swaps each
    // 4-byte group. Pre-swap so the public values contain the raw keccak256
    // output that the L1 verifier and Airbender both expect.
    let mut swapped = [0u8; 32];
    for i in 0..8 {
        let o = i * 4;
        swapped[o] = hash_bytes[o + 3];
        swapped[o + 1] = hash_bytes[o + 2];
        swapped[o + 2] = hash_bytes[o + 1];
        swapped[o + 3] = hash_bytes[o];
    }
    ziskos::io::commit(&swapped);
}
