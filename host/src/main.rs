//! Host program for ZiSK proof generation of ZKsync OS blocks.

use std::fs;
use std::path::PathBuf;

use alloy_primitives::{Address, B256, U256};
use clap::{Parser, Subcommand};

use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::types::*;

#[derive(Parser)]
#[command(name = "zksync-os-zisk-host")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a sample batch input JSON.
    Sample { #[arg(short, long)] output: PathBuf },
    /// Execute natively via REVM (no proof).
    Execute { #[arg(short, long)] input: PathBuf },
    /// Prepare ZiSK input binary from JSON.
    Prepare { #[arg(short, long)] input: PathBuf, #[arg(short, long)] output: PathBuf },
}

/// Write a value in ZiSK stdin format: [len:u64_LE][bincode_data][zero_padding_to_8_boundary]
fn zisk_write_value<T: serde::Serialize>(buf: &mut Vec<u8>, value: &T) {
    let data = bincode::serialize(value).expect("serialize");
    let len = data.len() as u64;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&data);
    let total = 8 + data.len();
    let padding = (8 - (total % 8)) % 8;
    buf.extend(std::iter::repeat(0u8).take(padding));
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sample { output } => {
            let sample = make_sample_batch();
            let json = serde_json::to_string_pretty(&sample)?;
            fs::write(&output, &json)?;
            eprintln!("Wrote sample batch input to {}", output.display());
        }

        Commands::Execute { input } => {
            let json_str = fs::read_to_string(&input)?;
            let batch_input: BatchInput = serde_json::from_str(&json_str)?;
            eprintln!(
                "Executing: chain_id={}, blocks={}, txs={}",
                batch_input.chain_id, batch_input.blocks.len(),
                batch_input.blocks.iter().map(|b| b.transactions.len()).sum::<usize>()
            );
            let output = executor::execute_batch(&batch_input);
            for br in &output.block_results {
                eprintln!("\n--- Block {} ---", br.block_number);
                for (i, tx) in br.tx_results.iter().enumerate() {
                    eprintln!("  tx[{i}]: success={}, gas={}", tx.success, tx.gas_used);
                }
                eprintln!("  account_diffs: {}, storage_diffs: {}", br.account_diffs.len(), br.storage_diffs.len());
            }
            let hash = executor::compute_output_hash(&output);
            eprintln!("\nOutput hash: 0x{}", hex::encode(hash));
        }

        Commands::Prepare { input, output } => {
            let json_str = fs::read_to_string(&input)?;
            let batch_input: BatchInput = serde_json::from_str(&json_str)?;
            // Serialize in ZiSK stdin format
            let mut buf = Vec::new();
            zisk_write_value(&mut buf, &batch_input);
            fs::write(&output, &buf)?;
            eprintln!("Wrote {} bytes of ZiSK input to {}", buf.len(), output.display());
        }
    }

    Ok(())
}

fn make_sample_batch() -> BatchInput {
    let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
    let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
    let coinbase: Address = Address::ZERO;
    BatchInput {
        chain_id: 270, spec_id: 1, protocol_version_minor: 30,
        batch_meta: BatchMeta {
            tree_root_before: B256::ZERO, leaf_count_before: 2,
            block_number_before: 0, last_block_timestamp_before: 0,
            block_hashes_blake_before: B256::ZERO,
            previous_block_hashes: vec![], upgrade_tx_hash: B256::ZERO,
            da_commitment_scheme: 2, pubdata: vec![], multichain_root: B256::ZERO, sl_chain_id: 0,
            blob_versioned_hashes: vec![], tree_update: None,
        },
        blocks: vec![BlockInput {
            number: 1, timestamp: 1700000000, base_fee: 250_000_000,
            gas_limit: 80_000_000, coinbase,
            prev_randao: B256::from([1u8; 32]),
            block_header_hash: B256::ZERO, storage_proofs: vec![],
            transactions: vec![TxInput {
                caller: sender, gas_limit: 21_000, gas_price: 250_000_000,
                gas_priority_fee: Some(0), to: Some(recipient),
                value: U256::from(1_000_000_000_000_000_000u128),
                data: vec![], nonce: 0, chain_id: Some(270), tx_type: 2,
                gas_used_override: Some(21_000), force_fail: false,
                mint: None, refund_recipient: None, is_l1_tx: false, l1_tx_hash: None, signed_tx_bytes: None,
            }],
            accounts: vec![
                (sender, AccountData { nonce: 0, balance: U256::from(10_000_000_000_000_000_000u128), code_hash: B256::ZERO }),
                (recipient, AccountData { nonce: 0, balance: U256::ZERO, code_hash: B256::ZERO }),
                (coinbase, AccountData { nonce: 0, balance: U256::ZERO, code_hash: B256::ZERO }),
            ],
            account_preimages: vec![],
            storage: vec![], bytecodes: vec![], block_hashes: vec![],
            l2_to_l1_logs: vec![],
        }],
    }
}
