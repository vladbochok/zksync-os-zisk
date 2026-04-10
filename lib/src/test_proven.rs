//! Test that the proven execution path works end-to-end with real merkle proofs.

#[cfg(test)]
mod tests {
    use crate::executor;
    use crate::merkle::*;
    use crate::types::*;
    use alloy_primitives::{Address, B256, U256};

    /// Build a minimal merkle tree with MIN_GUARD (idx 0), MAX_GUARD (idx 1),
    /// and one data leaf (idx 2). Returns (root_hash, leaf_count, sibling_hashes_for_leaf2).
    fn build_minimal_tree(data_key: &B256, data_value: &B256) -> (B256, u64, Vec<B256>) {
        let empty = empty_subtree_hashes_vec();

        // Leaf 0: MIN_GUARD (key=0, value=0, next_index=2 -> points to data leaf)
        let leaf0 = hash_leaf(&B256::ZERO, &B256::ZERO, 2);
        // Leaf 1: MAX_GUARD (key=0xff..ff, value=0, next_index=1 -> self-loop)
        let leaf1 = hash_leaf(&B256::repeat_byte(0xff), &B256::ZERO, 1);
        // Leaf 2: data leaf (key=data_key, value=data_value, next_index=1 -> MAX_GUARD)
        let leaf2 = hash_leaf(data_key, data_value, 1);

        let leaf_count: u64 = 3;

        // Build the tree bottom-up. We need to compute the root and collect siblings for leaf 2.
        // Tree structure at depth 0 (leaves):
        //   idx 0: leaf0, idx 1: leaf1, idx 2: leaf2, idx 3...: empty
        //
        // For proof of leaf at index 2:
        //   depth 0: sibling is idx 3 (empty[0])
        //   depth 1: sibling is hash(leaf0, leaf1) at idx 0 on level 1
        //   depth 2..63: empty subtree hashes

        // Level 0 -> Level 1
        let node_01 = blake2s_compress_pub(&leaf0, &leaf1);  // index 0 on level 1
        let node_23 = blake2s_compress_pub(&leaf2, &empty[0]); // index 1 on level 1

        // Level 1 -> Level 2
        let node_0123 = blake2s_compress_pub(&node_01, &node_23); // index 0 on level 2

        // Level 2..63: pair with empty subtrees
        let mut current = node_0123;
        for d in 2..TREE_DEPTH {
            current = blake2s_compress_pub(&current, &empty[d as usize]);
        }
        let root = current;

        // Siblings for leaf at index 2:
        // depth 0: sibling at idx 3 = empty[0]
        // depth 1: sibling at idx 0 = node_01
        // depth 2..63: empty[depth]
        let mut siblings = vec![empty[0], node_01];
        for d in 2..TREE_DEPTH {
            siblings.push(empty[d as usize]);
        }

        (root, leaf_count, siblings)
    }

    // Expose the compress function for test
    fn blake2s_compress_pub(lhs: &B256, rhs: &B256) -> B256 {
        use blake2::Digest;
        let mut h = blake2::Blake2s256::new();
        h.update(lhs.as_slice());
        h.update(rhs.as_slice());
        B256::from_slice(&h.finalize())
    }

    fn empty_subtree_hashes_vec() -> Vec<B256> {
        let mut hashes = vec![empty_subtree_hash(0)];
        for d in 1..=TREE_DEPTH {
            hashes.push(empty_subtree_hash(d));
        }
        hashes
    }

    /// Encode account properties into 124-byte blob.
    fn encode_account_props(nonce: u64, balance: U256) -> Vec<u8> {
        let mut data = vec![0u8; 124];
        // bytes 0-7: versioning (all zero = not deployed)
        // bytes 8-15: nonce BE
        data[8..16].copy_from_slice(&nonce.to_be_bytes());
        // bytes 16-47: balance BE
        data[16..48].copy_from_slice(&balance.to_be_bytes::<32>());
        // bytes 48-79: bytecode_hash (zero = no code)
        // bytes 80-83: unpadded_code_len (zero)
        // bytes 84-87: artifacts_len (zero)
        // bytes 88-119: observable_bytecode_hash (zero)
        // bytes 120-123: observable_bytecode_len (zero)
        data
    }

    #[test]
    fn test_proven_path_with_real_merkle_proofs() {
        // Setup: a sender with 10 ETH, nonce 0
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002"
            .parse()
            .unwrap();

        // Encode sender account properties
        let sender_balance = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
        let sender_props = encode_account_props(0, sender_balance);
        let sender_props_hash = AccountProperties::hash(&sender_props);

        // Compute the flat key for the sender's account properties
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        // Build a minimal merkle tree with this one data leaf
        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        // Verify our proof works
        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2, // data leaf is at index 2
            value: sender_props_hash,
            next_index: 1, // points to MAX_GUARD
            siblings: siblings.clone(),
        });
        let (recovered_root, value) = proof.verify(&sender_flat_key).unwrap();
        assert_eq!(recovered_root, tree_root, "proof should recover tree root");
        assert_eq!(value.unwrap(), sender_props_hash, "proof should return correct value");

        // Build proper ABI-encoded L2CanonicalTransaction for the L1 tx.
        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20; // outer offset
            abi[32 + 31] = 0x7f; // txType
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice()); // from
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice()); // to
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes()); // gasLimit
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes()); // maxFeePerGas
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice()); // reserved[1]=refund
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        // Now build a BatchInput with this proof
        let batch_input = BatchInput {
            chain_id: 270,
            spec_id: 1, // AtlasV2
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: leaf_count,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender,  // use sender as coinbase so no extra proof needed
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                // The merkle proof for the sender's account properties
                storage_proofs: vec![(sender_flat_key, proof)],
                // Account preimage for decoding
                account_preimages: vec![(sender, sender_props)],
                // Use force_fail to avoid full execution (which would access
                // accounts we don't have proofs for in this minimal tree).
                // This test focuses on verifying proof + preimage decoding.
                transactions: vec![TxInput {
                    caller: sender,
                    gas_limit: 21_000,
                    gas_price: 250_000_000,
                    gas_priority_fee: Some(0),
                    to: Some(recipient),
                    value: U256::ZERO,
                    data: vec![],
                    nonce: 0,
                    chain_id: Some(270),
                    tx_type: 0x7f,
                    gas_used_override: Some(0),
                    force_fail: true,
                    mint: None,
                    refund_recipient: Some(sender),
                    auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![L2ToL1LogEntry {
                    l2_shard_id: 0,
                    is_service: true,
                    tx_number_in_block: 0,
                    sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                    key: l1_tx_hash,  // tx_hash from the ABI encoding
                    value: B256::ZERO,  // force_fail → success=false → value=0
                }],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // Run the proven execution path
        let (output, commitment) = executor::execute_and_commit(&batch_input);

        // Verify execution produced results
        assert_eq!(output.block_results.len(), 1);
        let br = &output.block_results[0];
        assert!(!br.tx_results.is_empty(), "should have tx results");

        let tx = &br.tx_results[0];
        assert!(!tx.success, "force_fail tx should fail");
        println!("tx[0]: success={}, gas_used={}", tx.success, tx.gas_used);

        // Commitment should be non-zero
        assert_ne!(commitment, B256::ZERO, "commitment should be non-zero");
        println!("BatchPublicInput commitment: {commitment}");
    }

    #[test]
    fn export_proven_input_for_emulator() {
        // Same setup as test_proven_path_with_real_merkle_proofs
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002"
            .parse()
            .unwrap();

        let sender_balance = U256::from(10_000_000_000_000_000_000u128);
        let sender_props = encode_account_props(0, sender_balance);
        let sender_props_hash = AccountProperties::hash(&sender_props);
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2,
            value: sender_props_hash,
            next_index: 1,
            siblings,
        });

        let batch_input = BatchInput {
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: leaf_count,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: Address::ZERO,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(sender_flat_key, proof)],
                account_preimages: vec![(sender, sender_props)],
                transactions: vec![TxInput {
                    caller: sender,
                    gas_limit: 21_000,
                    gas_price: 250_000_000,
                    gas_priority_fee: Some(0),
                    to: Some(recipient),
                    value: U256::from(1_000_000_000_000_000_000u128),
                    data: vec![],
                    nonce: 0,
                    chain_id: Some(270),
                    tx_type: 2,
                    gas_used_override: None,
                    force_fail: false,
                    mint: None,
                    refund_recipient: None,
                    auth: TxAuth::L1 {
                        tx_hash: alloy_primitives::keccak256(b"dummy-l1-tx"),
                        abi_encoded: b"dummy-l1-tx".to_vec(),
                    },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // Serialize in ZiSK stdin format
        let data = bincode::serialize(&batch_input).unwrap();
        let len = data.len() as u64;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&data);
        let total = 8 + data.len();
        let padding = (8 - (total % 8)) % 8;
        buf.extend(std::iter::repeat(0u8).take(padding));

        std::fs::write("/tmp/proven_input.bin", &buf).unwrap();
        println!("Wrote proven input to /tmp/proven_input.bin ({} bytes)", buf.len());
    }

    #[test]
    fn test_proof_verification_catches_wrong_value() {
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        // Real account: 10 ETH
        let real_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let real_hash = AccountProperties::hash(&real_props);

        // Build tree with real value
        let (tree_root, _leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &real_hash);

        // Try to use a FAKE preimage (1000 ETH instead of 10 ETH)
        let fake_props = encode_account_props(0, U256::from(1_000_000_000_000_000_000_000u128));

        // The proof is valid for the real_hash, but the fake preimage has a different hash
        let fake_hash = AccountProperties::hash(&fake_props);
        assert_ne!(real_hash, fake_hash, "hashes should differ");

        // Constructing a BatchInput with mismatched preimage should be caught
        // by build_proven_db which asserts preimage_hash == proven_value
        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2,
            value: real_hash, // tree has real_hash
            next_index: 1,
            siblings,
        });

        // Verify the proof works with the real key
        let (root, _) = proof.verify(&sender_flat_key).unwrap();
        assert_eq!(root, tree_root);

        // Now build BatchInput with the fake preimage — this should panic
        let batch_input = BatchInput {
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: 3,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: Address::ZERO,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(sender_flat_key, proof)],
                account_preimages: vec![(sender, fake_props)], // FAKE
                transactions: vec![],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // This should panic because preimage hash != proven value
        let result = std::panic::catch_unwind(|| {
            executor::execute_and_commit(&batch_input);
        });
        assert!(result.is_err(), "should panic on fake preimage");
        println!("Correctly caught fake account preimage!");
    }

    /// Inspect genesis batch: compare REVM writes vs tree_update writes.
    #[test]
    fn inspect_genesis_batch() {
        use std::collections::HashMap as HMap;
        let path = "/tmp/zisk_dump/batch_1_zisk.bin";
        if !std::path::Path::new(path).exists() {
            println!("Skipping: {path} not found.");
            return;
        }
        let data = std::fs::read(path).unwrap();
        let length = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let bincode_data = &data[8..8 + length];
        let batch: BatchInput = bincode::deserialize(bincode_data).unwrap();

        println!("Genesis batch: chain_id={}, blocks={}", batch.chain_id, batch.blocks.len());
        for (i, b) in batch.blocks.iter().enumerate() {
            println!("  Block {}: {} txs, types: {:?}, {} account_preimages",
                b.number, b.transactions.len(),
                b.transactions.iter().map(|t| format!("0x{:02x}", t.tx_type)).collect::<Vec<_>>(),
                b.account_preimages.len(),
            );
            for tx in &b.transactions {
                println!("    tx: caller={}, to={:?}, data_len={}, gas_limit={}, value={}",
                    tx.caller, tx.to, tx.data.len(), tx.gas_limit, tx.value);
            }
        }

        if let Some(ref tu) = batch.batch_meta.tree_update {
            println!("tree_update: {} operations, {} entries, {} sorted_leaves, {} intermediate_hashes_old, {} intermediate_hashes_new, leaf_count_before={}",
                tu.operations.len(), tu.entries.len(), tu.sorted_leaves.len(),
                tu.intermediate_hashes.len(), tu.intermediate_hashes_new.len(), tu.leaf_count_before);

            let inserts = tu.operations.iter().filter(|o| matches!(o, crate::merkle::WriteOp::Insert { .. })).count();
            let updates = tu.operations.iter().filter(|o| matches!(o, crate::merkle::WriteOp::Update { .. })).count();
            println!("  inserts: {inserts}, updates: {updates}");

            // Check storage for proxy implementation slot
            // Run proven executor and compare writes
            let result = std::panic::catch_unwind(|| {
                executor::execute_and_commit(&batch)
            });
            match result {
                Ok((output, commitment)) => {
                    println!("  Execution succeeded, commitment={commitment}");
                    for br in &output.block_results {
                        println!("  Block {}: {} tx_results", br.block_number, br.tx_results.len());
                    }
                }
                Err(_) => println!("  Execution panicked (expected for genesis without full proofs)"),
            }
            let tree_writes: HMap<B256, B256> = tu.entries.iter().cloned().collect();
            println!("\n  tree_update writes: {}", tree_writes.len());
        } else {
            println!("No tree_update!");
        }
    }

    /// Test that server-generated ZiSK batch data can be deserialized and executed.
    /// Reads from /tmp/zisk_dump/batch_2_zisk.bin if it exists (generated by integration tests).
    #[test]
    fn test_server_batch_execution() {
        let path: String = std::env::var("ZISK_BATCH_PATH")
            .unwrap_or_else(|_| "/tmp/zisk_dump/batch_2_zisk.bin".into());
        if !std::path::Path::new(&path).exists() {
            println!("Skipping: {path} not found. Run integration tests with ZISK_DUMP_DIR=/tmp/zisk_dump first.");
            return;
        }

        let data = std::fs::read(&path).unwrap();
        // ZiSK stdin format: [len:u64_LE][bincode][padding]
        let length = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let bincode_data = &data[8..8 + length];

        let batch_input: BatchInput = bincode::deserialize(bincode_data).unwrap();
        println!(
            "Server batch: chain_id={}, blocks={}, txs={}, storage_proofs={}",
            batch_input.chain_id,
            batch_input.blocks.len(),
            batch_input.blocks.iter().map(|b| b.transactions.len()).sum::<usize>(),
            batch_input.blocks.iter().map(|b| b.storage_proofs.len()).sum::<usize>(),
        );
        println!(
            "  tree_root_before: {:?}",
            batch_input.batch_meta.tree_root_before,
        );
        for block in &batch_input.blocks {
            for (i, tx) in block.transactions.iter().enumerate() {
                println!("  tx[{i}]: type=0x{:02x} caller={} force_fail={} gas_override={:?} is_l1={}",
                    tx.tx_type, tx.caller, tx.force_fail, tx.gas_used_override,
                    matches!(tx.auth, TxAuth::L1 { .. }));
            }
        }
        println!(
            "  bytecodes: {}",
            batch_input.bytecodes.len(),
        );

        // Show account preimages
        for block in &batch_input.blocks {
            println!("  account_preimages ({}):", block.account_preimages.len());
            for (addr, _) in &block.account_preimages {
                println!("    {addr}");
            }
        }

        // Check if 0x8007 has a proof
        let target: Address = "0x0000000000000000000000000000000000008007".parse().unwrap();
        let target_key = crate::merkle::derive_account_properties_key(&target.into_array());
        for block in &batch_input.blocks {
            let has_proof = block.storage_proofs.iter().any(|(k, _)| *k == target_key);
            println!("  0x8007 proof exists: {has_proof} (flat_key={target_key})");
        }

        // Verify individual proof recovery against per-block expected_tree_root
        for block in &batch_input.blocks {
            let expected = if !block.expected_tree_root.is_zero() {
                block.expected_tree_root
            } else {
                batch_input.batch_meta.tree_root_before
            };
            println!("  Block {} expected_tree_root: {}", block.number, expected);
            let mut mismatches = 0;
            for (key, proof) in &block.storage_proofs {
                match proof.verify(key) {
                    Ok((root, _)) => {
                        if root != expected {
                            mismatches += 1;
                            if mismatches <= 3 {
                                println!("  MISMATCH: proof key {} root {}, expected {}", key, root, expected);
                            }
                        }
                    }
                    Err(e) => println!("  PROOF ERROR for key {}: {}", key, e),
                }
            }
            if mismatches > 0 {
                println!("  {} total mismatches out of {} proofs", mismatches, block.storage_proofs.len());
            } else {
                println!("  All {} proofs verify correctly ✓", block.storage_proofs.len());
            }
        }

        // Try native execution (this doesn't use the ZiSK VM, just the Rust executor)
        let (output, commitment) = executor::execute_and_commit(&batch_input);
        println!(
            "Execution succeeded! blocks={}, commitment={}",
            output.block_results.len(),
            commitment,
        );
        for br in &output.block_results {
            println!(
                "  Block {}: {} txs",
                br.block_number,
                br.tx_results.len(),
            );
        }
    }
}
