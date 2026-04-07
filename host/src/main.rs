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
    /// Debug: execute and decompose the batch commitment into its three components.
    /// Input is a bincode file (ZiSK stdin format: [len:u64_LE][bincode][padding]).
    DebugCommitment { #[arg(short, long)] input: PathBuf },
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

        Commands::DebugCommitment { input } => {
            let data = fs::read(&input)?;
            // Parse ZiSK stdin format: [len:u64_LE][bincode][padding]
            let len = u64::from_le_bytes(data[..8].try_into()?) as usize;
            let bincode_data = &data[8..8 + len];
            let batch_input: BatchInput = bincode::deserialize(bincode_data)?;
            eprintln!(
                "Batch: chain_id={}, protocol_v_minor={}, blocks={}, spec_id={}",
                batch_input.chain_id, batch_input.protocol_version_minor,
                batch_input.blocks.len(),
                batch_input.spec_id,
            );
            eprintln!("  tree_root_before:    {}", batch_input.batch_meta.tree_root_before);
            eprintln!("  leaf_count_before:   {}", batch_input.batch_meta.leaf_count_before);
            eprintln!("  block_number_before: {}", batch_input.batch_meta.block_number_before);
            eprintln!("  hashes_blake_before: {}", batch_input.batch_meta.block_hashes_blake_before);
            eprintln!("  last_ts_before:      {}", batch_input.batch_meta.last_block_timestamp_before);
            eprintln!("  da_scheme:           {}", batch_input.batch_meta.da_commitment_scheme);
            eprintln!("  sl_chain_id:         {}", batch_input.batch_meta.sl_chain_id);
            eprintln!("  upgrade_tx_hash:     {}", batch_input.batch_meta.upgrade_tx_hash);
            eprintln!("  has tree_update:     {}", batch_input.batch_meta.tree_update.is_some());
            if let Some(ref tu) = batch_input.batch_meta.tree_update {
                eprintln!("  tree_update entries: {}", tu.entries.len());
            }

            // Dump input details for debugging
            for (bi, block) in batch_input.blocks.iter().enumerate() {
                eprintln!("\n--- Block {} (number={}) ---", bi, block.number);
                eprintln!("  base_fee={}, gas_limit={}, timestamp={}, coinbase={}", block.base_fee, block.gas_limit, block.timestamp, block.coinbase);
                eprintln!("  accounts: {}", block.accounts.len());
                for (addr, data) in &block.accounts {
                    eprintln!("    {addr}: nonce={}, balance={}, code_hash={}", data.nonce, data.balance, data.code_hash);
                }
                eprintln!("  bytecodes: {}", block.bytecodes.len());
                for (hash, code) in &block.bytecodes {
                    eprintln!("    {hash}: {} bytes", code.len());
                }
                eprintln!("  storage slots: {}", block.storage.len());
                for (addr, slot, val) in &block.storage {
                    if format!("{addr}").contains("800f") {
                        eprintln!("    STORAGE {addr} slot={slot} val={val}");
                    }
                }
                eprintln!("  account_preimages: {}", block.account_preimages.len());
                for (addr, _) in &block.account_preimages {
                    eprintln!("    {addr}");
                }
                eprintln!("  force_deploy_bytecodes: {}", block.force_deploy_bytecodes.len());
                for (hash, code) in &block.force_deploy_bytecodes {
                    if format!("{hash}").contains("380faebb") || format!("{hash}").contains("828bb5b1") {
                        eprintln!("    FOUND: {hash} ({} bytes)", code.len());
                    }
                }
                eprintln!("  storage_proofs: {}", block.storage_proofs.len());
                eprintln!("  transactions: {}", block.transactions.len());
                for (ti, tx) in block.transactions.iter().enumerate() {
                    eprintln!("    tx[{ti}]: type=0x{:02x}, caller={}, to={:?}, gas_limit={}, is_l1={}, value={}, data_len={}",
                        tx.tx_type, tx.caller, tx.to, tx.gas_limit, tx.is_l1_tx, tx.value, tx.data.len());
                    if tx.mint.is_some() { eprintln!("      mint={:?}", tx.mint); }
                    eprintln!("      gas_used_override={:?}, force_fail={}", tx.gas_used_override, tx.force_fail);
                    if tx.data.len() >= 4 {
                        eprintln!("      selector=0x{:02x}{:02x}{:02x}{:02x}", tx.data[0], tx.data[1], tx.data[2], tx.data[3]);
                    }
                    // For upgrade(address,bytes): first param is _delegateTo at offset 4..36
                    if tx.data.len() >= 36 && tx.tx_type == 0x7e {
                        let addr_bytes = &tx.data[16..36]; // last 20 bytes of first param
                        let delegate_to = Address::from_slice(addr_bytes);
                        eprintln!("      _delegateTo={delegate_to}");
                    }
                }
            }

            eprintln!("\n--- Running execution ---");
            let (output, commitment, state_before, state_after, batch_hash) =
                executor::execute_and_commit_debug(&batch_input);

            let br = &output.block_results[0];

            // Print structured table for comparison
            eprintln!("\n╔══════════════════════════════════════════════════════════════");
            eprintln!("║ COMPARISON TABLE: Server vs ZiSK REVM (batch 1)");
            eprintln!("╠══════════════════════════════════════════════════════════════");
            eprintln!("║ Field                    │ ZiSK Value");
            eprintln!("╠──────────────────────────┼───────────────────────────────────");
            eprintln!("║ state_before             │ {state_before}");
            eprintln!("║ state_after              │ {state_after}");
            eprintln!("║ batch_output_hash        │ {batch_hash}");
            eprintln!("║ COMMITMENT               │ {commitment}");
            eprintln!("╠──────────────────────────┼───────────────────────────────────");
            eprintln!("║ tx[0] success             │ {}", br.tx_results[0].success);
            eprintln!("║ tx[0] gas_used            │ {}", br.tx_results[0].gas_used);
            eprintln!("║ storage_diffs count       │ {}", br.storage_diffs.len());
            eprintln!("║ account_diffs count       │ {}", br.account_diffs.len());
            eprintln!("║ l2_to_l1_logs count       │ {}", br.l2_to_l1_logs.len());
            eprintln!("║ block_header_hash         │ {}", br.computed_block_header_hash);
            eprintln!("╠──────────────────────────┼───────────────────────────────────");

            // L2→L1 logs details
            for (i, log) in br.l2_to_l1_logs.iter().enumerate() {
                let encoded = log.encode();
                let log_hash = alloy_primitives::keccak256(&encoded);
                eprintln!("║ l2_to_l1_log[{i}] hash     │ {log_hash}");
            }

            // Storage diffs (first 10)
            for (i, diff) in br.storage_diffs.iter().enumerate() {
                eprintln!("║ SD[{i}] addr={} slot={} new={}",
                    diff.address, diff.slot, diff.new_value);
            }

            // Account diffs
            for diff in &br.account_diffs {
                eprintln!("║ account_diff              │ addr={} nonce_before={} balance_before={} nonce_after={} balance_after={}",
                    diff.address, diff.nonce_before, diff.balance_before, diff.nonce_after, diff.balance_after);
            }

            eprintln!("╚══════════════════════════════════════════════════════════════");

            // Now print the commitment sub-components for deeper comparison
            let meta = &batch_input.batch_meta;
            let last_block = batch_input.blocks.last().unwrap();

            // Recompute intermediate values
            use zksync_os_zisk_lib::commitment;
            let (tree_root_after, new_leaf_count) = if let Some(ref tree_update) = meta.tree_update {
                tree_update.apply(&meta.tree_root_before)
            } else {
                (meta.tree_root_before, meta.leaf_count_before)
            };
            let block_hashes_blake_after = commitment::block_hashes_blake(
                &meta.previous_block_hashes,
                &br.computed_block_header_hash,
            );

            eprintln!("\n=== State commitment sub-components ===");
            eprintln!("  tree_root_before:       {}", meta.tree_root_before);
            eprintln!("  leaf_count_before:      {}", meta.leaf_count_before);
            eprintln!("  tree_root_after:        {tree_root_after}");
            eprintln!("  new_leaf_count:         {new_leaf_count}");
            eprintln!("  block_hashes_blake_after: {block_hashes_blake_after}");
            eprintln!("  last_block_number:      {}", last_block.number);
            eprintln!("  last_block_timestamp:   {}", last_block.timestamp);

            // Batch hash sub-components
            let mut num_l1_txs: u64 = 0;
            let mut num_l2_txs: u64 = 0;
            let mut l1_tx_hashes = Vec::new();
            let mut l2_to_l1_encoded_logs = Vec::new();
            for block in &batch_input.blocks {
                for tx in &block.transactions {
                    if tx.is_l1_tx {
                        if let Some(h) = &tx.l1_tx_hash { l1_tx_hashes.push(*h); }
                        num_l1_txs += 1;
                    } else if tx.tx_type != 0x7e { num_l2_txs += 1; }
                }
            }
            for obr in &output.block_results {
                for log in &obr.l2_to_l1_logs {
                    l2_to_l1_encoded_logs.push(log.encode());
                }
            }
            let priority_ops_hash = commitment::priority_ops_rolling_hash(&l1_tx_hashes);
            let l2_logs_local_root = commitment::l2_to_l1_logs_root(&l2_to_l1_encoded_logs);
            let effective_multichain_root = if batch_input.protocol_version_minor >= 31 {
                meta.multichain_root
            } else {
                B256::ZERO
            };
            let l2_logs_root_hash = commitment::keccak_two(&l2_logs_local_root, &effective_multichain_root);
            let da_commitment = match meta.da_commitment_scheme {
                0 | 1 => B256::ZERO,
                2 | 3 => commitment::da_commitment_calldata(&meta.pubdata),
                4 => commitment::da_commitment_blobs(&meta.blob_versioned_hashes),
                _ => B256::ZERO,
            };

            eprintln!("\n=== Batch hash sub-components ===");
            eprintln!("  chain_id:               {}", batch_input.chain_id);
            eprintln!("  first_block_timestamp:  {}", batch_input.blocks.first().unwrap().timestamp);
            eprintln!("  last_block_timestamp:   {}", last_block.timestamp);
            eprintln!("  da_commitment_scheme:   {}", meta.da_commitment_scheme);
            eprintln!("  da_commitment:          {da_commitment}");
            eprintln!("  num_l1_txs:             {num_l1_txs}");
            eprintln!("  num_l2_txs:             {num_l2_txs}");
            eprintln!("  priority_ops_hash:      {priority_ops_hash}");
            eprintln!("  l2_logs_local_root:     {l2_logs_local_root}");
            eprintln!("  l2_logs_root_hash:      {l2_logs_root_hash}");
            eprintln!("  upgrade_tx_hash:        {}", meta.upgrade_tx_hash);
            eprintln!("  multichain_root:        {}", meta.multichain_root);

            for br in &output.block_results {
                for (i, tx) in br.tx_results.iter().enumerate() {
                    eprintln!("    tx[{i}]: success={}, gas={}", tx.success, tx.gas_used);
                }
            }
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
            expected_tree_root: B256::ZERO,
            force_deploy_bytecodes: vec![],
        }],
    }
}
