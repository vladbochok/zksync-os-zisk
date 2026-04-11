//! EVM block execution.
//!
//! Runs a block's transactions through REVM, collects results and L2→L1 logs,
//! and verifies the computed block header hash.

use revm::database::CacheDB;
use revm::primitives::{B256, U256};
use revm::{DatabaseRef, ExecuteCommitEvm};
use zksync_os_revm::{DefaultZk, ZkBuilder, ZkContext, ZkSpecId};

use crate::block_header;
use crate::commitment;
use crate::types::*;
use super::proven_db::ProvenDB;
use super::tx::build_proven_tx;

/// Execute a single block using the shared batch-level CacheDB.
/// Writes from this block remain in the CacheDB for subsequent blocks.
pub(super) fn execute_block_proven(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    cache_db: &mut CacheDB<ProvenDB>,
) -> BlockResult {
    let (tx_results, tx_hashes, computed_l2_to_l1_logs) =
        run_evm_block(chain_id, spec_id, block, cache_db);

    let total_gas_used: u64 = tx_results.iter().map(|t| t.gas_used).sum();
    let tx_root = commitment::transactions_rolling_hash(&tx_hashes);


    // Get parent hash from block_hashes (previous block's hash)
    let parent_hash = if block.number >= 1 {
        block.block_hashes.iter()
            .find(|(n, _)| *n == block.number - 1)
            .map(|(_, h)| *h)
            .unwrap_or(B256::ZERO)
    } else {
        B256::ZERO
    };


    let computed_header_hash = block_header::compute_block_header_hash(
        &parent_hash,
        &block.coinbase.into_array(),
        &tx_root,
        block.number,
        block.gas_limit,
        total_gas_used,
        block.timestamp,
        &block.prev_randao,
        block.base_fee,
    );

    // If a block_header_hash was provided in input, verify it matches our computation
    if !block.block_header_hash.is_zero() {
        assert_eq!(
            computed_header_hash, block.block_header_hash,
            "computed block header hash {computed_header_hash} != input {}", block.block_header_hash
        );
    }

    // SOUND: L2→L1 logs are computed from REVM's EVM execution output, NOT from
    // the untrusted BlockInput.l2_to_l1_logs. The L1Messenger precompile (0x8008)
    // emits L1MessageSent EVM events during execution; we reconstruct the structured
    // L2ToL1LogEntry from those events. This ensures the logs in the batch commitment
    // match what was actually executed.
    //
    // Verify consistency: computed logs must match input logs. A mismatch means either
    // the server provided wrong logs or our extraction has a bug.
    if !block.l2_to_l1_logs.is_empty() || !computed_l2_to_l1_logs.is_empty() {
        assert_eq!(
            computed_l2_to_l1_logs.len(),
            block.l2_to_l1_logs.len(),
            "L2→L1 log count mismatch: computed {} from EVM, input has {}",
            computed_l2_to_l1_logs.len(),
            block.l2_to_l1_logs.len(),
        );
        for (i, (computed, input)) in computed_l2_to_l1_logs.iter().zip(&block.l2_to_l1_logs).enumerate() {
            assert_eq!(
                computed.encode(),
                input.encode(),
                "L2→L1 log {i} mismatch: computed {:?} != input {:?}",
                computed, input,
            );
        }
    }

    BlockResult {
        block_number: block.number,
        computed_block_header_hash: computed_header_hash,
        tx_results,
        l2_to_l1_logs: computed_l2_to_l1_logs,
    }
}

/// Execute a block's transactions in the EVM and return tx results + L2→L1 logs.
/// State changes are written into the shared `cache_db`.
fn run_evm_block<DB: DatabaseRef>(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    cache_db: &mut CacheDB<DB>,
) -> (Vec<TxOutput>, Vec<B256>, Vec<L2ToL1LogEntry>)
where
    DB::Error: core::fmt::Debug,
{
    let mut evm = <ZkContext<_>>::default()
        .with_db(cache_db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.spec = spec_id;
        })
        .modify_block_chained(|blk| {
            blk.number = U256::from(block.number);
            blk.timestamp = U256::from(block.timestamp);
            blk.beneficiary = block.coinbase;
            blk.basefee = block.base_fee;
            blk.gas_limit = block.gas_limit;
            blk.prevrandao = Some(block.prev_randao);
        })
        .build_zk();

    let mut tx_results = Vec::with_capacity(block.transactions.len());
    let mut tx_hashes = Vec::with_capacity(block.transactions.len());
    let mut l2_to_l1_logs = Vec::new();

    for (tx_idx, tx_input) in block.transactions.iter().enumerate() {
        evm.0.ctx.chain.set_tx_number(tx_idx as u16);

        let (tx, tx_hash) = build_proven_tx(tx_input);
        tx_hashes.push(tx_hash);

        match evm.transact_commit(tx) {
            Ok(result) => {
                for log in evm.0.ctx.chain.take_logs() {
                    l2_to_l1_logs.push(L2ToL1LogEntry {
                        l2_shard_id: log.l2_shard_id,
                        is_service: log.is_service,
                        tx_number_in_block: log.tx_number_in_block,
                        sender: log.sender,
                        key: log.key,
                        value: log.value,
                    });
                }
                tx_results.push(TxOutput {
                    success: result.is_success(),
                    gas_used: result.gas_used(),
                    output: result.output().map(|b| b.to_vec()).unwrap_or_default(),
                });
            }
            Err(e) => panic!("transaction execution failed: {e:?}"),
        }
    }

    (tx_results, tx_hashes, l2_to_l1_logs)
}
