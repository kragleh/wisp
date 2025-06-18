use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use log::{debug, error, info, warn};
use std::io::ErrorKind;
use tokio::net::TcpStream;
use uuid::Uuid;
use wisp_core::{
    blockchain::{AddBlockResult, Block},
    currency::Amount,
    network::Message,
    sha256::Hash,
    transactions::{Transaction, TransactionOutput},
    utils::{calculate_block_reward, MerkleRoot},
};

use crate::{TEST_PRIVATE_KEY, TEST_PUBLIC_KEY};

pub async fn handle_connection(mut socket: TcpStream) -> Result<(), anyhow::Error> {
    loop {
        let message_result = Message::receive_async(&mut socket).await;
        let message = match message_result {
            Ok(message) => message,
            Err(e) => {
                if e.kind() == ErrorKind::UnexpectedEof {
                    println!("Peer disconnected.");

                    return Ok(());
                } else {
                    println!("Error receiving message from peer: {e}, closing connection.");

                    return Err(anyhow::Error::new(e).context("Error receiving message"));
                }
            }
        };

        use wisp_core::network::Message::*;
        match message {
            UTXOs(_)
            | Template(_)
            | Difference(_)
            | TemplateValidity(_)
            | NodeList(_)
            | TransactionAcceptedConfirmation
            | BlockSubmittedConfirmation
            | BlockRejected(_) => {
                println!("Received unexpected message, closing connection. Goodbye");
                return Ok(());
            }
            FetchBlock(index_requested) => {
                let blockchain = crate::BLOCKCHAIN.read().await;
                let blocks_guard = blockchain.blocks();
                let Some(block) = blocks_guard.get(index_requested as usize).cloned() else {
                    warn!("Requested block index {} not found.", index_requested);
                    return Ok(());
                };

                let message = NewBlock(block);
                message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send NewBlock")?;
            }
            DiscoverNodes => {
                let nodes = crate::NODES
                    .iter()
                    .map(|x| x.key().clone())
                    .collect::<Vec<_>>();
                let message = NodeList(nodes);
                message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send NodeList")?;
            }
            AskDifference(height) => {
                let blockchain = crate::BLOCKCHAIN.read().await;
                let count = blockchain.block_height() as i32 - height as i32;
                println!(
                    "Node at {} received AskDifference for height {}, responding with count: {}",
                    socket
                        .local_addr()
                        .context("Failed to get local address for log")?,
                    height,
                    count
                );
                let message = Difference(count);
                message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send Difference")?;
            }
            FetchUTXOs(key) => {
                println!("received request to fetch UTXOs for pubkey: {:?}", key);
                let blockchain = crate::BLOCKCHAIN.read().await;

                let utxos = blockchain
                    .utxos()
                    .iter()
                    .filter(|(_, (_, txout))| txout.pubkey == key)
                    .map(|(tx_hash, (marked, txout))| (*tx_hash, txout.clone(), *marked))
                    .collect::<Vec<_>>();

                let message = UTXOs(utxos.clone());
                message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send UTXOs")?;

                println!("Sent {} UTXOs.", utxos.len());
            }
            NewBlock(block) => {
                let received_block_hash = block
                    .hash_with_signatures()
                    .expect("Failed to hash received block for log");
                info!(
                    "Received NewBlock message for index: {} (hash: {})",
                    block.index, received_block_hash
                );

                let mut blockchain = crate::BLOCKCHAIN.write().await;

                let add_result = blockchain.add_block(block.clone());

                match add_result {
                    AddBlockResult::Added => {
                        info!("Block {} accepted and added to chain.", received_block_hash);

                        let nodes = crate::NODES
                            .iter()
                            .map(|x| x.key().clone())
                            .collect::<Vec<_>>();
                        info!(
                            "Broadcasting accepted block to {} known nodes...",
                            nodes.len()
                        );

                        let block_to_broadcast = block;
                        tokio::spawn(async move {
                            for node in nodes {
                                if let Some(mut stream_ref) = crate::NODES.get_mut(&node) {
                                    let stream = &mut *stream_ref;
                                    let message = Message::NewBlock(block_to_broadcast.clone());
                                    if message.send_async(stream).await.is_err() {
                                        warn!(
                                            "Failed to send block {} to node {}",
                                            block_to_broadcast
                                                .hash_with_signatures()
                                                .unwrap_or_default(),
                                            node
                                        );
                                    }
                                }
                            }
                            debug!("Finished broadcasting accepted block.");
                        });
                    }
                    AddBlockResult::PotentialLongerForkDetected {
                        common_ancestor_index,
                        new_block_index,
                        new_block_hash: _,
                    } => {
                        warn!(
                                        "Potential longer fork detected for block {} (index {}). Common ancestor at index {}. Initiating chain synchronization.",
                                        received_block_hash, new_block_index, common_ancestor_index
                                    );

                        let peer_addr = match socket.peer_addr() {
                            Ok(addr) => addr.to_string(),
                            Err(_) => {
                                error!("Could not get peer address for fork resolution logging.");
                                return Ok(());
                            }
                        };

                        drop(blockchain);

                        tokio::spawn(async move {
                            info!("Attempting to download entire longer chain from peer {} for reorg.", peer_addr);

                            let target_height = (new_block_index + 1) as u32;
                            if let Err(e) =
                                crate::utils::download_blockchain(&peer_addr, target_height).await
                            {
                                error!("Failed to download longer chain from {} during reorg attempt: {}", peer_addr, e);
                            } else {
                                info!(
                                    "Successfully downloaded longer chain from {} for reorg.",
                                    peer_addr
                                );
                            }
                        });
                    }
                    AddBlockResult::Rejected(reason) => {
                        warn!(
                            "Block {} rejected due to invalidity: {}",
                            received_block_hash, reason
                        );
                        let rejection_message = Message::BlockRejected(reason);
                        if rejection_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send BlockRejected message back to peer.");
                        }
                    }
                    AddBlockResult::ShorterForkRejected(reason) => {
                        warn!(
                            "Block {} rejected because it's part of a shorter or equal fork: {}",
                            received_block_hash, reason
                        );
                        let rejection_message = Message::BlockRejected(reason);
                        if rejection_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send BlockRejected message back to peer.");
                        }
                    }
                    AddBlockResult::OrphanedOrDisconnected(reason) => {
                        warn!(
                            "Block {} rejected because it's orphaned or disconnected: {}",
                            received_block_hash, reason
                        );
                        let rejection_message = Message::BlockRejected(reason);
                        if rejection_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send BlockRejected message back to peer.");
                        }
                    }
                }
            }
            NewTransaction(transaction) => {
                let tx_hash = transaction
                    .hash_with_signatures()
                    .expect("Failed to hash received transaction for log");
                info!("Received NewTransaction message for hash: {}", tx_hash);
                let mut blockchain = crate::BLOCKCHAIN.write().await;

                match blockchain.add_to_mempool(transaction.clone()) {
                    Ok(_) => {
                        info!("Transaction {} added to mempool.", tx_hash);
                        drop(blockchain);
                        let nodes_to_broadcast_to: Vec<String> = crate::NODES
                            .iter()
                            .filter(|_peer_ref| true)
                            .map(|peer_ref| peer_ref.key().clone())
                            .collect();

                        let tx_to_broadcast = transaction;
                        info!(
                            "Broadcasting accepted transaction {} to {} known nodes...",
                            tx_hash,
                            nodes_to_broadcast_to.len()
                        );
                        tokio::spawn(async move {
                            for node_addr in nodes_to_broadcast_to {
                                if let Some(mut stream_ref) = crate::NODES.get_mut(&node_addr) {
                                    let stream = &mut *stream_ref;
                                    let message = Message::NewTransaction(tx_to_broadcast.clone());
                                    if message.send_async(stream).await.is_err() {
                                        warn!(
                                            "Failed to send transaction {} to node {}",
                                            tx_hash, node_addr
                                        );
                                    }
                                } else {
                                    debug!("Node {} disappeared from map during transaction broadcast.", node_addr);
                                }
                            }
                            debug!("Finished broadcasting transaction {}.", tx_hash);
                        });
                    }
                    Err(e) => {
                        warn!("Transaction {} rejected: {}", tx_hash, e);

                        let rejection_message = Message::TransactionRejected(
                            tx_hash,
                            format!("Transaction Rejected: {}", e),
                        );
                        if rejection_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send TransactionRejected message back to peer.");
                        }
                    }
                }
            }
            TransactionRejected(tx_hash, reason) => {
                warn!(
                    "Received TransactionRejected for tx {}: {}",
                    tx_hash, reason
                );
            }
            ValidateTemplate(block_template) => {
                let blockchain = crate::BLOCKCHAIN.read().await;
                let actual_previous_hash = match blockchain.blocks().last() {
                    Some(last_block) => last_block
                        .hash_with_signatures()
                        .context("Failed to hash last block for template validation")?,
                    None => Hash::zero(),
                };

                let status = block_template.previous_hash == actual_previous_hash;
                let message = TemplateValidity(status);
                message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send TemplateValidity")?;
                println!("Sent template validity status: {}.", status);
            }
            SubmitTemplate(block) => {
                let submitted_block_hash = block
                    .hash_with_signatures()
                    .expect("Failed to hash received mined block for log");
                info!(
                    "Received allegedly mined block with hash: {} at index {}",
                    submitted_block_hash, block.index
                );

                let mut blockchain = crate::BLOCKCHAIN.write().await;
                let add_result = blockchain.add_block(block.clone());

                match add_result {
                    AddBlockResult::Added => {
                        info!(
                            "Mined block {} accepted and added to chain.",
                            submitted_block_hash
                        );

                        let confirmation_message = Message::BlockSubmittedConfirmation;
                        if confirmation_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send BlockSubmittedConfirmation back to miner.");
                        } else {
                            info!("Sent BlockSubmittedConfirmation to miner.");
                        }

                        let nodes = crate::NODES
                            .iter()
                            .map(|x| x.key().clone())
                            .collect::<Vec<_>>();
                        info!("Broadcasting mined block to {} known nodes...", nodes.len());
                        let block_to_broadcast = block.clone();

                        tokio::spawn(async move {
                            for node in nodes {
                                if let Some(mut stream_ref) = crate::NODES.get_mut(&node) {
                                    let stream = &mut *stream_ref;
                                    let message = Message::NewBlock(block_to_broadcast.clone());
                                    if message.send_async(stream).await.is_err() {
                                        warn!(
                                            "Failed to send block {} to node {}",
                                            block_to_broadcast
                                                .hash_with_signatures()
                                                .unwrap_or_default(),
                                            node
                                        );
                                    }
                                }
                            }
                            info!("Finished broadcasting block.");
                        });
                    }

                    AddBlockResult::Rejected(reason) => {
                        warn!(
                            "Mined block {} rejected due to invalidity: {}",
                            submitted_block_hash, reason
                        );

                        let rejection_message = Message::BlockRejected(reason);
                        if rejection_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send BlockRejected message back to miner.");
                        } else {
                            info!("Sent BlockRejected message to miner.");
                        }
                    }
                    AddBlockResult::PotentialLongerForkDetected {
                        common_ancestor_index,
                        new_block_index,
                        new_block_hash: _,
                    } => {
                        warn!("Mined block {} (index {}) is part of a potential longer fork. Common ancestor at index {}. Signalling for full re-sync from self to other nodes.",
                        submitted_block_hash, new_block_index, common_ancestor_index
                        );

                        let confirmation_message = Message::BlockSubmittedConfirmation;
                        if confirmation_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send BlockSubmittedConfirmation back to miner after fork detection.");
                        } else {
                            info!("Sent BlockSubmittedConfirmation to miner after fork detection.");
                        }

                        let nodes = crate::NODES
                            .iter()
                            .map(|x| x.key().clone())
                            .collect::<Vec<_>>();
                        info!(
                            "Broadcasting newly mined (forking) block to {} known nodes...",
                            nodes.len()
                        );

                        let block_to_broadcast = block.clone();
                        tokio::spawn(async move {
                            for node in nodes {
                                if let Some(mut stream_ref) = crate::NODES.get_mut(&node) {
                                    let stream = &mut *stream_ref;
                                    let message = Message::NewBlock(block_to_broadcast.clone());
                                    if message.send_async(stream).await.is_err() {
                                        warn!(
                                            "Failed to send block {} to node {}",
                                            block_to_broadcast
                                                .hash_with_signatures()
                                                .unwrap_or_default(),
                                            node
                                        );
                                    }
                                }
                            }
                            info!("Finished broadcasting newly mined (forking) block.");
                        });
                    }
                    AddBlockResult::ShorterForkRejected(reason) => {
                        warn!("Mined block {} rejected because it's part of a shorter or equal fork: {}", submitted_block_hash, reason);
                        let rejection_message = Message::BlockRejected(reason);
                        if rejection_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send BlockRejected message back to miner.");
                        } else {
                            info!("Sent BlockRejected message to miner.");
                        }
                    }
                    AddBlockResult::OrphanedOrDisconnected(reason) => {
                        warn!(
                            "Mined block {} rejected because it's orphaned or disconnected: {}",
                            submitted_block_hash, reason
                        );
                        let rejection_message = Message::BlockRejected(reason);
                        if rejection_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send BlockRejected message back to miner.");
                        } else {
                            info!("Sent BlockRejected message to miner.");
                        }
                    }
                }
                info!("Finished processing SubmitTemplate.");
            }
            SubmitTransaction(tx) => {
                let tx_hash = tx
                    .hash_with_signatures()
                    .expect("Failed to hash received submitted transaction for log");
                info!("Received submitted transaction with hash: {}", tx_hash);
                let mut blockchain = crate::BLOCKCHAIN.write().await;
                let result = blockchain.add_to_mempool(tx.clone());

                match result {
                    Ok(_) => {
                        info!("Transaction {} accepted and added to mempool.", tx_hash);
                        info!(
                            "Mempool size after adding transaction: {}",
                            blockchain.mempool().len()
                        );

                        let confirmation_message = Message::TransactionAcceptedConfirmation;
                        if confirmation_message.send_async(&mut socket).await.is_err() {
                            eprintln!(
                                "Failed to send TransactionAcceptedConfirmation back to peer."
                            );
                        } else {
                            info!("Sent TransactionAcceptedConfirmation to peer.");
                        }

                        drop(blockchain);
                        let nodes_to_broadcast_to: Vec<String> = crate::NODES
                            .iter()
                            .map(|peer_ref| peer_ref.key().clone())
                            .collect();

                        let tx_to_broadcast = tx;
                        info!(
                            "Broadcasting accepted transaction {} to {} known nodes...",
                            tx_hash,
                            nodes_to_broadcast_to.len()
                        );
                        tokio::spawn(async move {
                            for node_addr in nodes_to_broadcast_to {
                                if let Some(mut stream_ref) = crate::NODES.get_mut(&node_addr) {
                                    let stream = &mut *stream_ref;
                                    let message = Message::NewTransaction(tx_to_broadcast.clone());
                                    if message.send_async(stream).await.is_err() {
                                        warn!(
                                            "Failed to send transaction {} to node {}",
                                            tx_hash, node_addr
                                        );
                                    }
                                } else {
                                    debug!("Node {} disappeared from map during transaction broadcast.", node_addr);
                                }
                            }
                            debug!("Finished broadcasting transaction {}.", tx_hash);
                        });
                    }
                    Err(e) => {
                        warn!("Transaction {} rejected: {}", tx_hash, e);
                        let rejection_message = Message::TransactionRejected(
                            tx_hash,
                            format!("Transaction Rejected: {}", e),
                        );
                        if rejection_message.send_async(&mut socket).await.is_err() {
                            eprintln!("Failed to send TransactionRejected message back to peer.");
                        } else {
                            info!("Sent TransactionRejected message to peer.");
                        }
                    }
                }
                info!(
                    "Finished processing SubmitTransaction for hash {}.",
                    tx_hash
                );
            }
            FetchTemplate(pubkey) => {
                let pubkey_clone_for_tx = pubkey.clone();
                let pubkey_clone_for_log = pubkey.clone();

                let blockchain = crate::BLOCKCHAIN.read().await;
                info!(
                    "Fetching new template for pubkey: {:?}. Current mempool size: {}",
                    pubkey_clone_for_log,
                    blockchain.mempool().len()
                );
                let mempool_size = blockchain.mempool().len();

                if mempool_size == 0 {
                    info!("Mempool is empty, sending NoNewTemplate.");
                    let message = Message::NoNewTemplate;
                    message
                        .send_async(&mut socket)
                        .await
                        .context("Failed to send NoNewTemplate")?;
                } else {
                    let mut transactions: Vec<Transaction> = blockchain
                        .mempool()
                        .iter()
                        .take(wisp_core::MAX_BLOCK_TRANSACTIONS)
                        .map(|(_timestamp, tx, _amount)| tx.clone())
                        .collect();

                    let next_block_index = blockchain.blocks().len() as u64;

                    let coinbase_tx_output = TransactionOutput {
                        pubkey: pubkey_clone_for_tx,
                        unique_id: Uuid::new_v4(),
                        value: Amount::zero(),
                    };
                    let coinbase_tx = Transaction {
                        inputs: vec![],
                        outputs: vec![coinbase_tx_output],
                    };
                    transactions.insert(0, coinbase_tx);

                    info!(
                        "Created block template with {} transactions (including coinbase).",
                        transactions.len()
                    );

                    let merkle_root = MerkleRoot::calculate(&transactions)
                        .context("Failed to calculate Merkle root for template")?;

                    let previous_hash = match blockchain.blocks().last() {
                        Some(last_block) => last_block
                            .hash_with_signatures()
                            .context("Failed to hash last block for template previous_hash")?,
                        None => Hash::zero(),
                    };

                    let mut block = Block::new(
                        Utc::now(),
                        0,
                        previous_hash,
                        merkle_root,
                        blockchain.target,
                        next_block_index,
                        transactions,
                    );

                    let miner_fees = block
                        .calculate_total_fees(blockchain.utxos())
                        .context("Failed to calculate miner fees for template")?;

                    let reward = calculate_block_reward(next_block_index);
                    if let Some(coinbase_output) = block.transactions[0].outputs.first_mut() {
                        coinbase_output.value = reward.saturating_add(miner_fees);
                    } else {
                        return Err(anyhow!("Coinbase transaction in template has no outputs"));
                    }

                    block.merkle_root = MerkleRoot::calculate(&block.transactions)
                        .context("Failed to recalculate Merkle root after updating coinbase")?;

                    let message = Template(block);
                    message
                        .send_async(&mut socket)
                        .await
                        .context("Failed to send Template")?;
                    info!("Sent block template.");
                }
            }
            NoNewTemplate => {
                println!("Warning: Node received a NoNewTemplate message unexpectedly.");
            }
            FetchTransactionHistory(pubkey) => {
                println!(
                    "Received request to fetch transaction history for {:?}",
                    pubkey
                );

                let blockchain = crate::BLOCKCHAIN.read().await;
                let history = blockchain.get_transactions_for_pubkey(&pubkey).await;
                let message = TransactionHistory(history.clone());

                message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send TransactionHistory")?;

                println!(
                    "Sent transaction history with {} transactions.",
                    history.len()
                );
            }
            TransactionHistory(history) => {
                println!(
                    "Received transaction history with {} transactions",
                    history.len()
                );
            }
            BlockInfo(block) => {
                println!(
                    "Warning: Node received a BlockInfo message unexpectedly: {:?}",
                    block
                );
            }
            FetchBlockInfo(index) => {
                let blockchain_read = crate::BLOCKCHAIN.read().await;
                let block = blockchain_read.blocks().get(index as usize).cloned();
                let message = Message::BlockInfo(block);
                message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send BlockInfo")?;
                info!("Sent block info for index {}.", index);
            }
            FetchLatestBlock => {
                let blockchain_read = crate::BLOCKCHAIN.read().await;
                let latest_block = blockchain_read.blocks().last().cloned();
                let index = blockchain_read.blocks().len() as u64;
                let response = Message::LatestBlock(latest_block.map(|b| (b, index)));
                response
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send LatestBlock")?;
                info!("Sent latest block info (index: {}).", index);
            }
            LatestBlock(block_and_index) => {
                info!(
                    "Received a LatestBlock message unexpectedly: {:?}",
                    block_and_index
                );
            }
            Ping => {
                let pong_message = Message::Pong;

                pong_message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send Pong")?;
                println!("Received Ping, sent Pong.");
            }
            Pong => {
                println!("Warning: Node received a Pong message unexpectedly.");
            }
            FetchTransactionStatus(hash) => {
                let blockchain = crate::BLOCKCHAIN.read().await;
                let status_message = blockchain.get_transaction_status(&hash).await;
                let message = Message::TransactionStatus {
                    hash,
                    status: status_message,
                };
                message.send_async(&mut socket).await.context(format!(
                    "Failed to send TransactionStatus for hash {}",
                    hash
                ))?;
                info!("Sent transaction status for hash {}.", hash);
            }
            TransactionStatus { hash, status } => {
                info!("Received TransactionStatus for hash {}: {:?}", hash, status);
            }
            GenerateTestTransaction(recipient_public_key) => {
                info!(
                    "Received GenerateTestTransaction for recipient: {}",
                    recipient_public_key.fingerprint()
                );

                let mut blockchain = crate::BLOCKCHAIN.write().await;
                let utxos_snapshot = blockchain.utxos().clone();

                let mut transaction_creation_result: Result<Transaction, anyhow::Error> =
                    Err(anyhow!("No spendable UTXO found for test transaction."));

                for (tx_hash, (is_in_mempool, tx_output)) in utxos_snapshot.iter() {
                    if tx_output.pubkey == *TEST_PUBLIC_KEY && !*is_in_mempool {
                        let prev_tx_hash = *tx_hash;
                        let input_value = tx_output.value;

                        let send_amount = Amount::from_smallest_unit(1000);
                        let fee = Amount::from_smallest_unit(100);
                        let required_amount = send_amount.saturating_add(fee);

                        if input_value < required_amount {
                            warn!(
                                "TEST_PUBLIC_KEY UTXO {} has insufficient funds ({}). Needs at least {}.",
                                prev_tx_hash, input_value, required_amount
                            );

                            continue;
                        } else {
                            let mut outputs = vec![TransactionOutput {
                                pubkey: recipient_public_key.clone(),
                                unique_id: Uuid::new_v4(),
                                value: send_amount,
                            }];

                            let change_amount = input_value.saturating_sub(required_amount);

                            if change_amount > Amount::zero() {
                                outputs.push(TransactionOutput {
                                    pubkey: TEST_PUBLIC_KEY.clone(),
                                    unique_id: Uuid::new_v4(),
                                    value: change_amount,
                                });
                            }

                            transaction_creation_result = Transaction::new_signed(
                                prev_tx_hash,
                                outputs,
                                &TEST_PRIVATE_KEY,
                            )
                            .context(
                                "Failed to create signed test transaction from TEST_PRIVATE_KEY",
                            );
                            break;
                        }
                    }
                }

                let response_message = match transaction_creation_result {
                    Ok(transaction) => {
                        let tx_hash = transaction
                            .hash_with_signatures()
                            .expect("Failed to hash generated test transaction");

                        match blockchain.add_to_mempool(transaction.clone()) {
                            Ok(_) => {
                                info!("Generated test transaction {} added to mempool and will be broadcasted.", tx_hash);
                                drop(blockchain);

                                let nodes_to_broadcast_to: Vec<String> = crate::NODES
                                    .iter()
                                    .map(|peer_ref| peer_ref.key().clone())
                                    .collect();

                                tokio::spawn(async move {
                                    for node_addr in nodes_to_broadcast_to {
                                        if let Some(mut stream_ref) =
                                            crate::NODES.get_mut(&node_addr)
                                        {
                                            let stream = &mut *stream_ref;
                                            let message =
                                                Message::NewTransaction(transaction.clone());
                                            if message.send_async(stream).await.is_err() {
                                                warn!("Failed to send generated test transaction {} to node {}", tx_hash, node_addr);
                                            }
                                        }
                                    }
                                });
                                Message::TransactionAcceptedConfirmation
                            }
                            Err(e) => {
                                warn!(
                                    "Generated test transaction {} rejected by mempool: {}",
                                    tx_hash, e
                                );
                                Message::TransactionRejected(
                                    tx_hash,
                                    format!("Test transaction rejected by mempool: {}", e),
                                )
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to generate test transaction: {}", e);
                        Message::TransactionRejected(
                            Hash::zero(),
                            format!("Failed to generate test transaction: {}", e),
                        )
                    }
                };

                response_message
                    .send_async(&mut socket)
                    .await
                    .context("Failed to send response for GenerateTestTransaction")?;
                info!("Sent response for GenerateTestTransaction.");
            }
        }
    }
}
