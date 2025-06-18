// wisp-node main.rs
mod connection_handler;
mod utils;

use anyhow::{Context, Result};
use argh::FromArgs;
use dashmap::DashMap;
use static_init::dynamic;
use std::path::Path;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use wisp_core::blockchain::Blockchain;
use wisp_core::signatures::{PrivateKey, PublicKey};

#[macro_use]
extern crate lazy_static;
lazy_static! {
    pub static ref TEST_PRIVATE_KEY: PrivateKey =
        "497b0bf6e94b0bafed325187869d6c9655963dbfbe2e3a260942f08a6a14a8f0"
            .parse()
            .expect("Failed to parse test private key");
    pub static ref TEST_PUBLIC_KEY: PublicKey = TEST_PRIVATE_KEY.public_key();
}

#[derive(FromArgs)]
/// A toy blockchain node
struct Args {
    #[argh(option, default = "9000")]
    /// port number
    port: u16,

    #[argh(option, default = "String::from(\"./blockchain.json\")")]
    /// blockchain file location
    blockchain_file: String,

    #[argh(positional)]
    /// addresses of initial nodes
    nodes: Vec<String>,
}

#[dynamic]
pub static BLOCKCHAIN: RwLock<Blockchain> = RwLock::new({
    let args: Args = argh::from_env(); // Get args in the static block
    let blockchain_path = Path::new(&args.blockchain_file);

    if blockchain_path.exists() {
        println!("Loading blockchain from {}.", args.blockchain_file);
        // Use load_from_file if the file exists
        Blockchain::load_from_file(&args.blockchain_file)
            .expect("Failed to load blockchain from file")
    } else {
        println!(
            "Blockchain file not found at {}. Creating new genesis blockchain.",
            args.blockchain_file
        );
        // Otherwise, create a new genesis blockchain
        Blockchain::new_genesis().expect("Failed to create new genesis blockchain")
    }
});

// Node pool
#[dynamic]
pub static NODES: DashMap<String, TcpStream> = DashMap::new();

#[tokio::main]
async fn main() -> Result<()> {
    // main returns Result, can use ?
    // Parse command line arguments
    let args: Args = argh::from_env();

    // Access the parsed arguments
    let port = args.port;
    let blockchain_file = args.blockchain_file.clone();
    let nodes = args.nodes;

    utils::populate_connections(&nodes).await?;
    println!("total amount of known nodes: {}", NODES.len());

    // The blockchain is already initialized by the `#[dynamic]` block
    // We only need to potentially synchronize it with peers if initial nodes are provided.

    if !nodes.is_empty() {
        println!("Checking for longer chain against initial nodes...");
        let (longest_name, longest_count) = utils::find_longest_chain_node().await?;
        let blockchain_read = BLOCKCHAIN.read().await;

        let local_chain_length = blockchain_read.blocks().len() as u32;

        if longest_count > local_chain_length {
            println!(
                "Peer {} has a longer chain ({} blocks), downloading...",
                longest_name, longest_count
            );
            utils::download_blockchain(&longest_name, longest_count).await?;
            // After downloading, we need to rebuild UTXOs and recalculate target
            {
                let mut blockchain = BLOCKCHAIN.write().await;
                blockchain.rebuild_utxos()?; // rebuild_utxos returns Result now, needs ?
                blockchain.target = blockchain
                    .calculate_next_target()
                    .context("Failed to adjust target after finding longer chain")?;
            }
        } else {
            println!("Local blockchain is up-to-date or longer.");
        }
    } else {
        println!("No initial nodes provided. Starting with local blockchain state.");
    }

    // Print genesis block hash
    {
        let blockchain_read = BLOCKCHAIN.read().await;
        if let Some(genesis_block) = blockchain_read.blocks().first() {
            println!(
                "Node Genesis Block Hash: {}",
                genesis_block
                    .hash_with_signatures()
                    .expect("Failed to hash genesis block for printing")
            );
        } else {
            println!("Error: Genesis block not found in the blockchain.");
        }
    }

    // Start the TCP listener on 0.0.0.0:port
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on {}", addr);

    // start a task to periodically cleanup the mempool
    tokio::spawn(utils::cleanup()); // Assuming cleanup handles its own errors

    // and a task to periodically save the blockchain
    tokio::spawn(utils::save(blockchain_file.clone())); // Assuming save handles its own errors

    loop {
        let result = listener.accept().await;
        match result {
            Ok((socket, _addr)) => {
                tokio::spawn(async move {
                    let handler_result = connection_handler::handle_connection(socket).await;
                    if let Err(e) = handler_result {
                        eprintln!("Error in connection handler: {:?}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
}
