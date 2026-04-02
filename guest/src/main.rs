//! ZiSK guest: proves ZKsync OS block execution using REVM.
//!
//! Every storage read is verified against a merkle proof.
//! The committed output is the BatchPublicInput hash matching the L1 format.
//! There is no unverified path — the guest always runs proven execution.

#![no_main]

use zksync_os_zisk_lib::{executor, types::BatchInput};

ziskos::entrypoint!(main);

fn main() {
    let batch_input: BatchInput = ziskos::io::read();
    let (_output, commitment) = executor::execute_and_commit(&batch_input);
    let hash_bytes: [u8; 32] = commitment.into();
    ziskos::io::commit(&hash_bytes);
}
