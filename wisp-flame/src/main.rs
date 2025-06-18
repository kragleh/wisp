//wisp-flame main.rs
use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::Parser;
use hex;
use k256::ecdsa::VerifyingKey;
use log::{error, info, warn};
use num_cpus;
use rodio::{Decoder, Sink};
use std::fs::File;
use std::io::BufReader;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{interval, Duration};
use wisp_core::{blockchain::Block, network::Message, signatures::PublicKey}; // Add this import

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    node_address: String,

    #[arg(short, long)]
    reward_address: String,
}

struct Miner {
    public_key: PublicKey,
    stream: AsyncMutex<TcpStream>,
    current_template: Arc<AsyncMutex<Option<Block>>>,
    mining: Arc<AtomicBool>,
    mined_block_sender: flume::Sender<Block>,
    mined_block_receiver: flume::Receiver<Block>,
}

impl Miner {
    async fn new(address: String, public_key: PublicKey) -> Result<Self> {
        let serialized_public_key = PublicKey(public_key.0.clone());
        info!("Connecting to node at {}", address);
        let stream = AsyncMutex::new(
            TcpStream::connect(&address)
                .await
                .map_err(|e| anyhow!("Failed to connect to node {}: {}", address, e))?,
        );
        info!("Successfully connected to node at {}", address);
        let (mined_block_sender, mined_block_receiver) = flume::unbounded();
        Ok(Self {
            public_key: serialized_public_key,
            stream,
            current_template: Arc::new(AsyncMutex::new(None)),
            mining: Arc::new(AtomicBool::new(false)),
            mined_block_sender,
            mined_block_receiver,
        })
    }

    async fn run(&self) -> Result<()> {
        // We will store join handles if we need to explicitly join threads later (e.g., on shutdown).
        // For a continuously running miner, this isn't strictly necessary unless graceful shutdown is required.
        // For this example, we simply spawn and let them run.
        let _mining_handles = self.spawn_mining_thread();

        let mut template_interval = interval(Duration::from_secs(5));

        self.fetch_and_validate_template().await?;
        let (_stream, stream_handle) =
            rodio::OutputStream::try_default().expect("Failed to create output stream");
        let sink = Sink::try_new(&stream_handle).expect("Failed to create audio playback sink");
        info!("Audio playback sink created.");

        loop {
            let receiver_clone = self.mined_block_receiver.clone();

            tokio::select! {
                _ = template_interval.tick() => {
                    // Only fetch a new template if mining is currently paused or inactive.
                    // If mining is active, a new block might be found soon, and fetching a template
                    // would interrupt the current mining work.
                    if !self.mining.load(Ordering::Relaxed) {
                         self.fetch_and_validate_template().await?;
                    } else {
                        info!("Miner is active, validating current template.");
                        self.validate_template().await?;
                    }
                }
                Ok(mined_block) = receiver_clone.recv_async() => {
                    info!("Received mined block from mining thread.");
                    let file_path = "notification.mp3";
                    match File::open(file_path) {
                        Ok(file) => {
                            let decoder = Decoder::new(BufReader::new(file));
                            match decoder {
                                Ok(source) => {
                                     sink.append(source);
                                },
                                Err(e) => error!("Failed to decode sound file {}: {}", file_path, e),
                            }
                        },
                        Err(e) => error!("Failed to open sound file {}: {}", file_path, e),
                    }
                    self.submit_block(mined_block).await?;
                    // After submitting a block, immediately fetch a new template
                    // as the chain head might have advanced.
                    self.fetch_and_validate_template().await?;
                }
            }
        }
    }

    // This function now returns a Vec of JoinHandles so they can be optionally managed.
    fn spawn_mining_thread(&self) -> Vec<thread::JoinHandle<()>> {
        let num_cores = num_cpus::get();
        info!("Spawning {} mining threads.", num_cores);

        let mut handles = Vec::new();

        for i in 0..num_cores {
            let template_clone = self.current_template.clone();
            let mining_clone = self.mining.clone();
            let sender_clone = self.mined_block_sender.clone();
            let thread_id = i; // Assign a unique ID to each thread for logging

            let handle = thread::spawn(move || {
                info!("Mining thread {} started.", thread_id);
                loop {
                    // Check if mining is enabled globally
                    if !mining_clone.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(100)); // Sleep briefly if not mining
                        continue;
                    }

                    // Attempt to acquire a lock on the current template.
                    // If another thread holds it (e.g., main thread updating it),
                    // we'll wait briefly and try again.
                    let template_guard = match template_clone.try_lock() {
                        Ok(guard) => guard,
                        Err(_) => {
                            // warn!("Mining thread {} could not acquire template lock, retrying.", thread_id);
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    };

                    let mut block = match template_guard.clone() {
                        Some(block) => block,
                        None => {
                            warn!("Mining flag is true but no template found for thread {}, pausing mining.", thread_id);
                            mining_clone.store(false, Ordering::Relaxed); // This will pause all threads
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                    };

                    // Release the lock on the template as soon as we have a copy.
                    // This is crucial to avoid contention and allow other threads
                    // (including the main loop for template updates) to acquire the lock.
                    drop(template_guard);

                    info!(
                        "Thread {} mining block with target: {:?}",
                        thread_id, block.target
                    );

                    let mining_start_time = std::time::Instant::now();
                    let max_attempts_per_call = 1_000_000; // Define how many nonces each thread tries per batch

                    // Call the parallel mining function from wisp_core
                    match block.mine_block_parallel(
                        thread_id as u64,      // Start nonce unique to this thread
                        num_cores as u64,      // Step (total number of threads)
                        max_attempts_per_call, // Attempts before checking active flag
                        &mining_clone,         // Shared mining active flag
                    ) {
                        Ok(true) => {
                            let mining_duration = mining_start_time.elapsed();
                            let nonce_discovery_wall_time = Utc::now();

                            info!("Thread {} mined block successfully!", thread_id);
                            info!(
                                "Time taken to mine by thread {}: {:?}",
                                thread_id, mining_duration
                            );
                            info!("Mined block index: {}", block.index);
                            info!(
                                "Nonce discovery time: {}",
                                nonce_discovery_wall_time.to_rfc3339()
                            );
                            info!("Nonce: {}", block.nonce);
                            if let Ok(block_hash) = block.hash_with_signatures() {
                                info!("Block Hash: {}", hex::encode(block_hash.as_bytes()));
                            } else {
                                error!(
                                    "Failed to calculate hash for mined block by thread {}.",
                                    thread_id
                                );
                            }

                            // Signal other threads to stop mining current template
                            mining_clone.store(false, Ordering::Relaxed);
                            info!(
                                "Mining paused by thread {} after finding a block.",
                                thread_id
                            );

                            // Send the found block to the main miner loop
                            if let Err(e) = sender_clone.send(block) {
                                error!(
                                    "Thread {} failed to send mined block through channel: {}",
                                    thread_id, e
                                );
                            }
                        }
                        Ok(false) => {
                            // If `mine_block_parallel` returns `Ok(false)`, it means:
                            // 1. It exhausted `max_attempts_per_call` without finding a solution.
                            // 2. Or, `mining_active` was set to `false` by another thread (or main loop).
                            // In either case, this thread will loop and re-evaluate `mining_clone` and template.
                            // No need to log a warning here for exhausted attempts unless it's repeatedly failing
                            // over a long period.
                        }
                        Err(e) => {
                            error!("Error during mining in thread {}: {}", thread_id, e);
                            mining_clone.store(false, Ordering::Relaxed); // Stop mining due to error
                        }
                    }
                }
            });
            handles.push(handle);
        }
        handles // Return all handles
    }

    async fn fetch_and_validate_template(&self) -> Result<()> {
        match self.fetch_template().await {
            Ok(Some(template)) => {
                info!("Received new template with target: {:?}", template.target);

                let is_new_template = {
                    let current_template_guard = self.current_template.lock().await;
                    match current_template_guard.as_ref() {
                        Some(current) => {
                            current.hash_with_signatures()? != template.hash_with_signatures()?
                        }
                        None => true, // No current template, so this is new
                    }
                };

                if is_new_template {
                    match self.validate_template().await {
                        Ok(_) => {
                            info!("Template validated successfully.");
                            let mut current_template_guard = self.current_template.lock().await;
                            *current_template_guard = Some(template);
                            self.mining.store(true, Ordering::Relaxed); // Start/restart mining
                            info!("Mining started with new template.");
                        }
                        Err(e) => {
                            error!("Template validation failed: {}", e);
                            self.mining.store(false, Ordering::Relaxed); // Pause mining if template is invalid
                        }
                    }
                } else {
                    info!("Received the same template, no need to restart mining.");
                    // If it's the same template, and mining was off, re-enable it.
                    // If it was already on, keep it on.
                    if !self.mining.load(Ordering::Relaxed) {
                        self.mining.store(true, Ordering::Relaxed);
                        info!("Re-enabled mining for existing template.");
                    }
                }
            }
            Ok(None) => {
                // No new template available, ensure mining is paused if there's no template to work on
                info!("No new template available from node.");
                self.mining.store(false, Ordering::Relaxed);
            }
            Err(e) => {
                error!("Failed to fetch template: {}", e);
                self.mining.store(false, Ordering::Relaxed); // Pause mining on fetch error
            }
        }
        Ok(())
    }

    async fn fetch_template(&self) -> Result<Option<Block>> {
        let message = Message::FetchTemplate(self.public_key.clone());

        let mut stream_lock = self.stream.lock().await;
        message
            .send_async(&mut *stream_lock)
            .await
            .map_err(|e| anyhow!("Failed to send FetchTemplate message: {}", e))?;

        match Message::receive_async(&mut *stream_lock)
            .await
            .map_err(|e| anyhow!("Failed to receive response for FetchTemplate: {}", e))?
        {
            Message::Template(template) => Ok(Some(template)),
            Message::NoNewTemplate => Ok(None),
            response => Err(anyhow!(
                "Unexpected message received when fetching template: {:?}",
                response
            )),
        }
    }

    async fn validate_template(&self) -> Result<()> {
        let current_template_guard = self.current_template.lock().await;
        if let Some(template) = current_template_guard.clone() {
            drop(current_template_guard); // Release the lock before sending over network

            let message = Message::ValidateTemplate(template);
            let mut stream_lock = self.stream.lock().await;
            message
                .send_async(&mut *stream_lock)
                .await
                .map_err(|e| anyhow!("Failed to send ValidateTemplate message: {}", e))?;

            match Message::receive_async(&mut *stream_lock)
                .await
                .map_err(|e| anyhow!("Failed to receive response for ValidateTemplate: {}", e))?
            {
                Message::TemplateValidity(valid) => {
                    if !valid {
                        info!("Current template is no longer valid according to the node.");
                        self.mining.store(false, Ordering::Relaxed); // Pause mining if invalid
                    } else {
                        info!("Current template is still valid.");
                    }
                    Ok(())
                }
                response => Err(anyhow!(
                    "Unexpected message received when validating template: {:?}",
                    response
                )),
            }
        } else {
            // If there's no template to validate, it's not an error, but mining should be off.
            info!("No current template to validate.");
            self.mining.store(false, Ordering::Relaxed);
            Ok(())
        }
    }

    async fn submit_block(&self, block: Block) -> Result<()> {
        info!(
            "Submitting mined block: {}",
            block
                .hash_with_signatures()
                .expect("Failed to hash mined block for logging")
        );
        let message = Message::SubmitTemplate(block);

        let mut stream_lock = self.stream.lock().await;
        message
            .send_async(&mut *stream_lock)
            .await
            .map_err(|e| anyhow!("Failed to send SubmitTemplate message: {}", e))?;

        info!("Mined block submitted, waiting for confirmation...");

        match tokio::time::timeout(
            Duration::from_secs(5), // Timeout for confirmation
            Message::receive_async(&mut *stream_lock),
        )
        .await
        {
            Ok(Ok(Message::BlockSubmittedConfirmation)) => {
                info!("Block submission confirmed by node.");
                Ok(())
            }
            Ok(Ok(Message::BlockRejected(reason))) => {
                warn!("Block submission rejected by node: {}", reason);
                Err(anyhow!("Block submission rejected by node: {}", reason))
            }
            Ok(Ok(other)) => {
                warn!(
                    "Unexpected message received after submitting block: {:?}",
                    other
                );
                Err(anyhow!(
                    "Unexpected message received after submitting block: {:?}",
                    other
                ))
            }
            Ok(Err(e)) => {
                error!("Failed to receive confirmation response from node: {}", e);
                Err(anyhow!("Failed to receive confirmation response: {}", e))
            }
            Err(_) => {
                error!("Timeout waiting for block submission confirmation from node.");
                Err(anyhow!("Timeout waiting for block submission confirmation"))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize env_logger to output INFO level messages by default
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_module("symphonia_core::probe", log::LevelFilter::Warn)
        .filter_module("symphonia_bundle_mp3::demuxer", log::LevelFilter::Warn)
        .init();

    let args = Args::parse();

    info!("Starting Wisp Miner (wisp-flame)");
    info!("Node Address: {}", args.node_address);
    info!("Reward Address: {}", args.reward_address);

    let public_key_bytes = hex::decode(&args.reward_address)
        .map_err(|e| anyhow!("Invalid reward public key format (must be hex): {}", e))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|e| anyhow!("Invalid public key bytes: {}", e))?;
    let public_key = PublicKey(verifying_key);
    info!("Parsed Public Key: {}", public_key.fingerprint());

    let miner = Miner::new(args.node_address, public_key).await?;
    miner.run().await?;

    Ok(())
}
