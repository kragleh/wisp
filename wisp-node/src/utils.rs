//utils.rs
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use tokio::net::TcpStream;
use tokio::time;
use wisp_core::network::Message;
use wisp_core::utils::Saveable;
// Ensure AddBlockResult is in scope for download_blockchain
use wisp_core::blockchain::AddBlockResult;

pub async fn populate_connections(nodes: &[String]) -> Result<()> {
    info!("Attempting to connect to nodes: {:?}", nodes);
    for node in nodes {
        info!("Connecting to node: {}", node);
        match time::timeout(Duration::from_secs(5), TcpStream::connect(&node)).await {
            Ok(Ok(mut stream)) => {
                info!("Successfully connected to {}", node);
                let message = Message::DiscoverNodes;
                if let Err(e) = message.send_async(&mut stream).await {
                    warn!("Failed to send DiscoverNodes to {}: {}", node, e);
                    continue;
                }
                info!("Sent DiscoverNodes to {}", node);

                match time::timeout(Duration::from_secs(5), Message::receive_async(&mut stream))
                    .await
                {
                    Ok(Ok(Message::NodeList(child_nodes))) => {
                        info!("Received NodeList from {}: {:?}", node, child_nodes);
                        for child_node in child_nodes {
                            debug!("Adding node {}", child_node);
                            match time::timeout(
                                Duration::from_secs(5),
                                TcpStream::connect(&child_node),
                            )
                            .await
                            {
                                Ok(Ok(new_stream)) => {
                                    // FIX: Clone `child_node` before inserting to allow further use
                                    if !crate::NODES.contains_key(&child_node) {
                                        let node_name_for_map = child_node.clone(); // Clone here
                                        crate::NODES.insert(node_name_for_map, new_stream);
                                        debug!("Added new child node: {}", child_node);
                                    // `child_node` is still available
                                    } else {
                                        debug!(
                                            "Child node {} already known, skipping connection.",
                                            child_node
                                        );
                                    }
                                }
                                Ok(Err(e)) => {
                                    warn!("Failed to connect to child node {}: {}", child_node, e);
                                }
                                Err(_) => {
                                    warn!("Timeout connecting to child node: {}", child_node);
                                }
                            }
                        }
                    }
                    Ok(Ok(message)) => {
                        warn!("Unexpected message from {}: {:?}", node, message);
                    }
                    Ok(Err(e)) => {
                        warn!("Error receiving message from {}: {}", node, e);
                    }
                    Err(_) => {
                        warn!("Timeout receiving message from {}", node);
                    }
                }
                // FIX: Prevent duplicate insertion for the initial connected node
                // (This one already handles the clone correctly if you applied the previous fix
                // because `node.clone()` is used when inserting)
                if !crate::NODES.contains_key(node) {
                    crate::NODES.insert(node.clone(), stream);
                    info!("Added initial node: {}", node);
                } else {
                    debug!(
                        "Initial node {} already known, skipping re-insertion.",
                        node
                    );
                }
            }
            Ok(Err(e)) => {
                warn!("Failed to connect to {}: {}", node, e);
            }
            Err(_) => {
                warn!("Timeout connecting to node: {}", node);
            }
        }
    }
    Ok(())
}

pub async fn find_longest_chain_node() -> Result<(String, u32)> {
    info!("Finding node with the longest blockchain...");
    let mut longest_name = String::new();
    let mut longest_count = 0;

    let all_nodes = crate::NODES
        .iter()
        .map(|x| x.key().clone())
        .collect::<Vec<_>>();

    debug!("Known nodes: {:?}", all_nodes);

    if let Some(first_node) = all_nodes.first() {
        longest_name = first_node.clone();
    }

    for node in &all_nodes {
        debug!("Querying {} for blockchain length", node);
        let mut stream = crate::NODES
            .get_mut(node)
            .with_context(|| format!("No node found: {}", node))?;

        let message = Message::AskDifference(0);
        message
            .send_async(&mut *stream)
            .await
            .with_context(|| format!("Failed to send AskDifference to {}", node))?;

        debug!("Sent AskDifference to {}", node);

        match time::timeout(Duration::from_secs(5), Message::receive_async(&mut *stream)).await {
            Ok(Ok(Message::Difference(count))) => {
                debug!("Received Difference({}) from {}", count, node);
                if count > longest_count {
                    info!("New longest blockchain: {} blocks from {}", count, node);
                    longest_count = count;
                    longest_name = node.clone();
                }
            }
            Ok(Ok(message)) => {
                warn!("Unexpected message from {}: {:?}", node, message);
            }
            Ok(Err(e)) => {
                warn!("Error from {} : {:?}", node, e);
            }
            Err(_) => {
                warn!("Timeout waiting for Difference from {}", node);
            }
        }
    }

    info!(
        "Longest chain found on node: {} with length: {}",
        longest_name, longest_count
    );
    Ok((longest_name, longest_count as u32))
}

pub async fn download_blockchain(node: &str, count: u32) -> Result<()> {
    info!(
        "DEBUG: download_blockchain called for node: {} with {} blocks. Local chain length is initially {}.",
        node, count, crate::BLOCKCHAIN.read().await.blocks().len()
    );

    let mut stream_guard = crate::NODES.get_mut(node).with_context(|| {
        let err_msg = format!(
            "DEBUG: Error: Connection to node {} lost or not found in NODES during blockchain download",
            node
        );
        error!("{}", err_msg); // Log this explicitly
        err_msg // Return this for the anyhow context
    })?;

    let stream = &mut *stream_guard; // Dereference the MutGuard to get &mut TcpStream

    let local_chain_length = crate::BLOCKCHAIN.read().await.blocks().len();

    if local_chain_length >= count as usize {
        info!("DEBUG: Local chain length ({}) is already >= target count ({}). No blocks to download. Exiting.", local_chain_length, count);
        return Ok(());
    }

    info!(
        "DEBUG: Starting block download loop from index {} to {}.",
        local_chain_length,
        count - 1
    );

    for i in local_chain_length..count as usize {
        info!("DEBUG: Attempting to fetch block index {} from {}", i, node);
        let message = Message::FetchBlock(i as u64);

        if let Err(e) = message.send_async(stream).await {
            // Use 'stream' here
            error!("DEBUG: Failed to send FetchBlock({}) to {}: {}", i, node, e);
            return Err(anyhow!(
                "Failed to send FetchBlock({}) to {}: {}",
                i,
                node,
                e
            ));
        }
        info!("DEBUG: Sent FetchBlock({}) to {}", i, node);

        match time::timeout(Duration::from_secs(5), Message::receive_async(stream)).await {
            // Use 'stream' here
            Ok(Ok(Message::NewBlock(block))) => {
                info!(
                    "DEBUG: Received NewBlock for index {} from {}",
                    block.index, node
                );
                let mut blockchain = crate::BLOCKCHAIN.write().await;

                if block.index != i as u64 {
                    error!(
                        "DEBUG: Received block with unexpected index. Expected {}, got {}. Block Hash: {}",
                        i,
                        block.index,
                        block.hash_with_signatures().unwrap_or_default()
                    );
                    return Err(anyhow!(
                        "Received block with unexpected index. Expected {}, got {}. Block Hash: {}",
                        i,
                        block.index,
                        block.hash_with_signatures().unwrap_or_default()
                    ));
                }

                let add_result = blockchain.add_block(block);

                match add_result {
                    AddBlockResult::Added => {
                        info!(
                            "DEBUG: Block {} (index {}) successfully added during download. Current chain length: {}",
                            i,
                            blockchain.blocks().len() -1, // Use len() - 1 for 0-indexed current top block index
                            blockchain.blocks().len() // Total blocks in chain
                        );
                    }
                    AddBlockResult::PotentialLongerForkDetected { .. } => {
                        error!("DEBUG: Unexpected longer fork detected while downloading block {} during reorg itself. Aborting download.", i);
                        return Err(anyhow!(
                            "Unexpected longer fork detected while downloading block {} during reorg itself. Aborting download.",
                            i
                        ));
                    }
                    AddBlockResult::Rejected(reason)
                    | AddBlockResult::ShorterForkRejected(reason)
                    | AddBlockResult::OrphanedOrDisconnected(reason) => {
                        error!(
                            "DEBUG: Failed to add block {} received from {}: {}. Aborting blockchain download.",
                            i, node, reason
                        );
                        return Err(anyhow!(
                            "Failed to add block {} received from {}: {}. Aborting blockchain download.",
                            i, node, reason
                        ));
                    }
                }
            }
            Ok(Ok(message)) => {
                error!(
                    "DEBUG: Unexpected message {:?} from {} while downloading block {}",
                    message, node, i
                );
                return Err(anyhow!(
                    "Unexpected message {:?} from {} while downloading block {}",
                    message,
                    node,
                    i
                ));
            }
            Ok(Err(e)) => {
                error!("DEBUG: Error receiving block {} from {}: {}", i, node, e);
                return Err(anyhow!("Error receiving block {} from {}: {}", i, node, e));
            }
            Err(_) => {
                error!("DEBUG: Timeout downloading block {} from {}", node, i);
                return Err(anyhow!("Timeout downloading block {} from {}", node, i));
            }
        }
    }
    info!("DEBUG: Blockchain downloaded successfully from {}", node);
    Ok(())
}

pub async fn cleanup() {
    let mut interval = time::interval(time::Duration::from_secs(30));
    info!("Cleanup task started");
    loop {
        interval.tick().await;
        debug!("Cleaning the mempool from old transactions");
        let mut blockchain = crate::BLOCKCHAIN.write().await;
        blockchain.clear_mempool();
    }
}

pub async fn save(name: String) {
    let mut interval = time::interval(time::Duration::from_secs(15));
    info!("Save task started. Saving blockchain every 15 seconds");
    loop {
        interval.tick().await;
        debug!("Saving blockchain to drive... (filename: {})", name.clone());
        let blockchain = crate::BLOCKCHAIN.read().await;
        if let Err(e) = blockchain.save_to_file(name.clone()) {
            error!("Error saving blockchain to {}: {}", name, e);
        } else {
            debug!("Blockchain saved successfully to {}", name);
        }
    }
}
