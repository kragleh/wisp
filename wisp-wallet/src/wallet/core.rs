// wisp-wallet/src/core.rs
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use std::{fs, sync::Arc};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key as AesKey, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine};
use k256::ecdsa::signature::Signer;
use k256::ecdsa::Signature as ECDSASignature;
use k256::ecdsa::SigningKey;
use log::{debug, error, info, warn};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
use uuid::Uuid;

use wisp_core::{
    blockchain::Block,
    currency::Amount,
    network::{Message, TransactionStatus},
    sha256::Hash,
    signatures::{PrivateKey, PublicKey},
    transactions::{Transaction, TransactionInput, TransactionOutput},
};

use crate::wallet::{config::Config, constants::*, storage::SavedWallet};

// Define FeeType enum for transaction sending logic
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeType {
    Fixed,
    Percent,
}

impl std::fmt::Display for FeeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeeType::Fixed => write!(f, "Fixed Amount"),
            FeeType::Percent => write!(f, "Percentage of Amount Sent"),
        }
    }
}

pub struct Core {
    pub config: Arc<AsyncMutex<Config>>,
    pub wallets: Arc<AsyncMutex<Vec<SavedWallet>>>,
    pub discovered_nodes: Arc<AsyncMutex<HashMap<String, Option<Duration>>>>,
    // Available UTXOs known to THIS WALLET for the CURRENTLY LOADED WALLET's keys
    // Hash is the TransactionOutput unique_id
    pub available_utxos: Arc<AsyncMutex<HashMap<Hash, TransactionOutput>>>,
    // Transactions submitted by this wallet that are pending confirmation
    pub pending_transactions: Arc<AsyncMutex<HashMap<Hash, Transaction>>>,
    // Actively connected node stream (optional)
    connected_node_stream: Arc<AsyncMutex<Option<TcpStream>>>,
}

impl Core {
    pub async fn load(config_path: PathBuf) -> Result<Self> {
        let config = match fs::read_to_string(&config_path) {
            Ok(content) => toml::from_str(&content)?,
            Err(_) => {
                info!("No config file found, using default configuration.");
                Config::default()
            }
        };

        Ok(Core {
            config: Arc::new(AsyncMutex::new(config)),
            wallets: Arc::new(AsyncMutex::new(Vec::new())),
            discovered_nodes: Arc::new(AsyncMutex::new(HashMap::new())),
            available_utxos: Arc::new(AsyncMutex::new(HashMap::new())),
            pending_transactions: Arc::new(AsyncMutex::new(HashMap::new())),
            connected_node_stream: Arc::new(AsyncMutex::new(None)), // Initialize as None
        })
    }

    /// Helper to get the currently connected node address from config.
    async fn get_default_node_address(&self) -> String {
        let config_guard = self.config.lock().await;
        config_guard.default_node.clone()
    }

    /// Helper to get the response timeout from config.
    pub async fn get_node_response_timeout(&self) -> Duration {
        let config_guard = self.config.lock().await;
        Duration::from_secs(config_guard.node_response_timeout_secs)
    }

    /// Establishes a connection to the default node if not already connected.
    /// Returns a locked stream if successful. The returned MutexGuard wraps an Option<TcpStream>.
    /// The caller must handle the Option<TcpStream> (e.g., using .as_mut().expect()).
    pub async fn get_connected_stream(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<TcpStream>>> {
        let mut stream_lock = self.connected_node_stream.lock().await;

        if let Some(ref stream) = *stream_lock {
            if stream.peer_addr().is_ok() {
                debug!("Re-using existing connection to node.");
                return Ok(stream_lock);
            } else {
                warn!("Existing connection is dead, re-connecting.");
                *stream_lock = None;
            }
        }

        let node_address = self.get_default_node_address().await;
        let connect_timeout =
            Duration::from_secs(self.config.lock().await.node_connect_timeout_secs);

        info!("Attempting to connect to node at: {}", node_address); // <--- You should see this if it gets here
        let stream = timeout(connect_timeout, TcpStream::connect(&node_address))
            .await
            .map_err(|e| anyhow!("Connection timed out to {}: {}", node_address, e))? // <--- This line is the actual connection attempt
            .map_err(|e| anyhow!("Failed to connect to node {}: {}", node_address, e))?;

        info!("Successfully connected to node at {}", node_address);
        *stream_lock = Some(stream);
        Ok(stream_lock)
    }

    pub async fn save_config(&self, path: &PathBuf, config_data: &Config) -> Result<()> {
        debug!("save_config: Attempting to save config to path: {:?}", path);

        debug!("save_config: Serializing config to TOML.");
        let config_string =
            toml::to_string_pretty(config_data).context("Failed to serialize config to TOML")?;

        debug!("save_config: Writing config to file.");
        tokio::fs::write(path, config_string)
            .await
            .context("Failed to write config file")?;

        info!("Config saved to {:?}", path);
        Ok(())
    }

    pub async fn create_wallet(
        &self,
        name: &str,
        password: &str,
        config_path: &PathBuf,
    ) -> Result<()> {
        let mut wallets_guard = self.wallets.lock().await;
        if wallets_guard.iter().any(|w| w.name == name) {
            return Err(anyhow!("Wallet with name '{}' already exists", name));
        }

        let private_key = PrivateKey::generate_keypair();
        let public_key = private_key.public_key();

        let mut rng = OsRng;
        let mut salt = vec![0u8; SALT_SIZE];
        rng.try_fill_bytes(&mut salt)
            .map_err(|e| anyhow!("Failed to fill bytes for salt: {}", e))?;

        let encrypted_private_key = Self::encrypt_private_key(&private_key, password, &salt)?;

        let new_wallet = SavedWallet {
            name: name.to_string(),
            encrypted_private_key,
            public_key,
            salt,
        };

        // Save the wallet to its individual file.
        // It's a method on SavedWallet, not directly on Core.
        new_wallet.save_to_file(password)?;

        // Update the current wallet in config
        {
            let mut config_guard = self.config.lock().await;
            config_guard.current_wallet_name = Some(name.to_string());
            self.save_config(config_path, &*config_guard).await?;
        }

        // Load the newly created wallet into memory
        let loaded_wallet = SavedWallet::load_from_file(name, password)?;
        wallets_guard.push(loaded_wallet);

        info!("Wallet '{}' created successfully!", name);
        Ok(())
    }

    pub async fn load_wallets() -> Result<Vec<String>> {
        let wallet_dir = PathBuf::from(WALLET_DIR);
        fs::create_dir_all(&wallet_dir)?; // Ensure directory exists
        let mut wallet_names = Vec::new();
        for entry in fs::read_dir(&wallet_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(base_name) =
                        name.strip_suffix(&format!(".{}", WALLET_FILE_EXTENSION))
                    {
                        wallet_names.push(base_name.to_string());
                    }
                }
            }
        }
        Ok(wallet_names)
    }

    pub async fn load_wallet(
        &self,
        name: &str,
        password: &str,
        config_path: &PathBuf,
    ) -> Result<()> {
        info!("Loading wallet: {}", name);

        let name_clone = name.to_string();
        let password_clone = password.to_string();

        let loaded_wallet = tokio::task::spawn_blocking(move || {
            SavedWallet::load_from_file(&name_clone, &password_clone)
                .context("Failed to load wallet file in blocking task")
        })
        .await
        .context("Failed to await wallet loading blocking task completion")?
        .context("Wallet loading blocking task returned an error")?;

        info!(
            "Wallet '{}' decrypted successfully (blocking task completed).",
            name
        );

        let mut wallets_guard = self.wallets.lock().await;
        debug!("load_wallet: Acquired wallets_guard lock.");

        // Check if wallet is already loaded to avoid duplicates
        if wallets_guard.iter().any(|w| w.name == name) {
            info!("Wallet '{}' is already loaded.", name);
            let mut config_guard = self.config.lock().await; // Acquire lock here
            config_guard.current_wallet_name = Some(name.to_string());
            // FIX THIS CALL SITE: Pass &*config_guard
            self.save_config(config_path, &*config_guard).await?;
            debug!("load_wallet: Exiting early because wallet is already loaded.");
            return Ok(());
        }

        debug!("load_wallet: Pushing loaded wallet to in-memory list.");
        wallets_guard.push(loaded_wallet.clone());
        drop(wallets_guard); // Release lock
        debug!("load_wallet: Released wallets_guard lock.");

        debug!("load_wallet: Attempting to acquire config_guard lock.");
        {
            let mut config_guard = self.config.lock().await; // Lock acquired here
            debug!("load_wallet: Acquired config_guard lock. Setting current wallet name.");
            config_guard.current_wallet_name = Some(name.to_string());

            debug!("load_wallet: Calling save_config.");
            // This was the call site we fixed last time. Keep it this way.
            self.save_config(config_path, &*config_guard).await?;
            debug!("load_wallet: Config updated and saved.");
        }

        debug!("load_wallet: Calling fetch_wallet_state...");
        self.fetch_wallet_state().await?;
        info!("Wallet '{}' loaded and state fetched.", name);
        Ok(())
    }

    pub async fn get_current_wallet(&self) -> Result<SavedWallet> {
        let config_guard = self.config.lock().await;
        match &config_guard.current_wallet_name {
            Some(name) => {
                let wallets_guard = self.wallets.lock().await;
                wallets_guard
                    .iter()
                    .find(|w| w.name == *name)
                    .cloned()
                    .ok_or_else(|| anyhow!("Current wallet '{}' not found in loaded wallets", name))
            }
            None => Err(anyhow!("No wallet loaded")),
        }
    }

    pub async fn decrypt_current_wallet_private_key(&self, password: &str) -> Result<PrivateKey> {
        let current_wallet = self.get_current_wallet().await?;
        Self::decrypt_private_key(
            &current_wallet.encrypted_private_key,
            password,
            &current_wallet.salt,
        )
    }

    pub fn encrypt_private_key(
        private_key: &PrivateKey,
        password: &str,
        salt: &[u8],
    ) -> Result<String> {
        let mut rng = OsRng;
        let mut nonce = [0u8; ENCRYPTION_NONCE_SIZE];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|e| anyhow!("Failed to fill bytes for nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce);

        let key = SavedWallet::derive_key(password, salt)?;
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key));

        let private_key_bytes = private_key.0.to_bytes();

        let ciphertext = cipher
            .encrypt(nonce, private_key_bytes.as_slice())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let combined = [nonce.as_slice(), ciphertext.as_slice()].concat();

        Ok(general_purpose::STANDARD_NO_PAD.encode(&combined))
    }

    fn decrypt_private_key(
        encrypted_private_key: &str,
        password: &str,
        salt: &[u8],
    ) -> Result<PrivateKey> {
        let decoded = general_purpose::STANDARD_NO_PAD.decode(encrypted_private_key)?;
        if decoded.len() <= ENCRYPTION_NONCE_SIZE {
            return Err(anyhow!("Invalid encrypted private key format"));
        }
        let nonce = Nonce::from_slice(&decoded[..ENCRYPTION_NONCE_SIZE]);
        let ciphertext = &decoded[ENCRYPTION_NONCE_SIZE..];

        let key = SavedWallet::derive_key(password, salt)?;
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key));

        let decrypted_private_key_bytes = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        SigningKey::from_slice(&decrypted_private_key_bytes)
            .map(|signing_key| PrivateKey(signing_key))
            .map_err(|e| anyhow!("Failed to load private key from decrypted bytes: {}", e))
    }

    pub async fn change_wallet_password(
        &self,
        current_password: &str,
        new_password: &str,
        _config_path: &PathBuf,
    ) -> Result<()> {
        let current_wallet = self.get_current_wallet().await?;
        let mut wallets_guard = self.wallets.lock().await;

        if let Some(wallet) = wallets_guard
            .iter_mut()
            .find(|w| w.name == current_wallet.name)
        {
            match self
                .decrypt_current_wallet_private_key(current_password)
                .await
            {
                Ok(private_key) => {
                    let mut rng = OsRng;
                    let mut new_salt = vec![0u8; SALT_SIZE];
                    rng.try_fill_bytes(&mut new_salt)
                        .map_err(|e| anyhow!("Failed to fill bytes for new salt: {}", e))?;

                    wallet.salt = new_salt;
                    wallet.encrypted_private_key =
                        Self::encrypt_private_key(&private_key, new_password, &wallet.salt)?;

                    wallet.save_to_file(new_password)?;

                    info!(
                        "Wallet password for '{}' changed successfully.",
                        wallet.name
                    );
                    println!("🔑 Wallet password changed successfully.");
                }
                Err(_) => {
                    println!("⚠️ Incorrect current password.");
                    return Err(anyhow!("Incorrect current password."));
                }
            }
        } else {
            println!("⚠️ No wallet loaded or unable to find it in the list.");
            return Err(anyhow!("No wallet loaded or found."));
        }
        Ok(())
    }

    pub async fn delete_wallet(&self, name: &str, config_path: &PathBuf) -> Result<()> {
        let path = SavedWallet::wallet_file_path(name);
        if fs::remove_file(&path).is_ok() {
            info!("Wallet file '{}' deleted.", name);
            {
                let mut config_guard = self.config.lock().await;
                if config_guard.current_wallet_name.as_deref() == Some(name) {
                    config_guard.current_wallet_name = None;
                    self.save_config(config_path, &*config_guard).await?;

                    info!("Removed '{}' as the current wallet.", name);
                }
            }
            let mut wallets_guard = self.wallets.lock().await;
            wallets_guard.retain(|w| w.name != name);
            Ok(())
        } else {
            Err(anyhow!("Failed to delete wallet file '{}'", name))
        }
    }

    /// Fetches all UTXOs belonging to the current wallet's public key from the node.
    /// Updates the `self.available_utxos` map.
    pub async fn fetch_wallet_state(&self) -> Result<()> {
        let current_wallet = self.get_current_wallet().await?;
        let wallet_public_key = current_wallet.public_key.clone();
        info!(
            "Fetching wallet state for public key: {}",
            wallet_public_key.fingerprint()
        );

        // Step 1: Get connected stream
        debug!("fetch_wallet_state: Attempting to get connected stream.");
        let mut stream_guard = self.get_connected_stream().await?;
        debug!("fetch_wallet_state: Connected stream obtained.");
        let stream_ref = stream_guard
            .as_mut()
            .expect("Expected an active TCP stream after connection attempt");
        let response_timeout = self.get_node_response_timeout().await;

        // --- Fetch UTXOs ---
        debug!("fetch_wallet_state: Sending FetchUTXOs message.");
        let fetch_utxos_msg = Message::FetchUTXOs(wallet_public_key.clone());
        fetch_utxos_msg
            .send_async(stream_ref)
            .await
            .context("Failed to send FetchUTXOs message")?;
        debug!("fetch_wallet_state: Waiting for FetchUTXOs response.");

        let utxos_response =
            tokio::time::timeout(response_timeout, Message::receive_async(stream_ref))
                .await
                .context("Timeout waiting for FetchUTXOs response")??;

        match utxos_response {
            Message::UTXOs(utxos_with_mempool_status) => {
                debug!("fetch_wallet_state: Received UTXOs response.");
                let mut available_utxos_guard = self.available_utxos.lock().await;
                available_utxos_guard.clear();
                for (tx_hash, utxo, is_mempool) in utxos_with_mempool_status {
                    if !is_mempool {
                        available_utxos_guard.insert(utxo.hash()?, utxo);
                    } else {
                        debug!("Skipping mempool UTXO for available_utxos: {}", tx_hash);
                    }
                }
                info!(
                    "Fetched {} confirmed UTXOs for wallet.",
                    available_utxos_guard.len()
                );
            }
            other => {
                return Err(anyhow!("Unexpected response for FetchUTXOs: {:?}", other));
            }
        }

        // --- Fetch Pending Transactions for current wallet's outputs ---
        // After fetching, also update status of our *previously sent* pending transactions
        debug!("fetch_wallet_state: Starting pending transactions check.");
        let mut pending_tx_hashes_to_check: Vec<Hash> = self
            .pending_transactions
            .lock()
            .await
            .keys()
            .cloned()
            .collect();
        let mut confirmed_tx_hashes = Vec::new();
        let mut invalid_tx_hashes = Vec::new();

        for tx_hash in pending_tx_hashes_to_check.drain(..) {
            debug!(
                "fetch_wallet_state: Sending FetchTransactionStatus for {}",
                tx_hash
            );
            let fetch_status_msg = Message::FetchTransactionStatus(tx_hash);
            fetch_status_msg
                .send_async(stream_ref)
                .await
                .context(format!(
                    "Failed to send FetchTransactionStatus for {}",
                    tx_hash
                ))?;

            debug!(
                "fetch_wallet_state: Waiting for TransactionStatus response for {}",
                tx_hash
            );
            let status_response =
                tokio::time::timeout(response_timeout, Message::receive_async(stream_ref))
                    .await
                    .context(format!(
                        "Timeout waiting for TransactionStatus for {}",
                        tx_hash
                    ))??;

            match status_response {
                Message::TransactionStatus { hash, status } => {
                    debug!(
                        "fetch_wallet_state: Received TransactionStatus for {}: {:?}",
                        hash, status
                    );
                    match status {
                        TransactionStatus::Confirmed {
                            block_hash,
                            block_index,
                        } => {
                            info!(
                                "Transaction {} confirmed in block {} at index {}",
                                hash, block_hash, block_index
                            );
                            confirmed_tx_hashes.push(hash);
                        }
                        TransactionStatus::Invalid => {
                            warn!("Transaction {} is invalid/rejected by node.", hash);
                            invalid_tx_hashes.push(hash);
                        }
                        TransactionStatus::NotFound => {
                            warn!("Transaction {} not found on node (may have expired or been dropped).", hash);
                            invalid_tx_hashes.push(hash); // Treat as invalid/lost for now
                        }
                        TransactionStatus::Pending => {
                            debug!("Transaction {} is still pending.", hash);
                            // Do nothing, it remains in pending_transactions
                        }
                    }
                }
                other => {
                    return Err(anyhow!(
                        "Unexpected response for FetchTransactionStatus for {}: {:?}",
                        tx_hash,
                        other
                    ));
                }
            }
        }

        debug!("fetch_wallet_state: Updating pending transactions list.");
        // Remove confirmed/invalid transactions from pending_transactions
        let mut pending_transactions_guard = self.pending_transactions.lock().await;
        for hash in confirmed_tx_hashes {
            pending_transactions_guard.remove(&hash);
        }
        for hash in invalid_tx_hashes {
            pending_transactions_guard.remove(&hash);
        }

        info!("fetch_wallet_state: Wallet state fetch completed successfully.");
        Ok(())
    }

    /// Displays the total balance of the current wallet.
    pub async fn show_balance(&self) -> Result<()> {
        let current_wallet = self.get_current_wallet().await?;
        let wallet_public_key = current_wallet.public_key.clone();

        println!("Wallet: {}", current_wallet.name);
        println!("Public Key: {}", wallet_public_key.fingerprint());

        // Ensure UTXOs are up-to-date
        self.fetch_wallet_state().await?;

        let available_utxos_guard = self.available_utxos.lock().await;
        let total_balance = available_utxos_guard
            .values()
            .fold(Amount::zero(), |acc, output| {
                (acc + output.value).unwrap_or_else(|_| {
                    error!("Overflow calculating total balance!");
                    Amount::zero() // Handle overflow by returning 0 or Amount::MAX
                })
            });

        println!("Total Balance (Confirmed UTXOs): {}", total_balance);
        println!("Confirmed UTXOs Count: {}", available_utxos_guard.len());

        let pending_transactions_guard = self.pending_transactions.lock().await;
        println!(
            "Pending Outgoing Transactions: {}",
            pending_transactions_guard.len()
        );
        if !pending_transactions_guard.is_empty() {
            println!("(Transactions awaiting confirmation):");
            for (hash, tx) in pending_transactions_guard.iter() {
                println!("  - Hash: {}", hash);
                let output_sum = tx.outputs.iter().fold(Amount::zero(), |acc, output| {
                    if output.pubkey == wallet_public_key {
                        // Only count outputs going *to* this wallet
                        (acc + output.value).unwrap_or_else(|_| Amount::zero())
                    } else {
                        acc
                    }
                });
                println!("    Outputs (to self): {}", output_sum);
            }
        }

        Ok(())
    }

    /// Sends funds from the current wallet.
    #[allow(clippy::too_many_arguments)] // Temporarily allow for readability
    pub async fn send_funds(
        &self,
        recipient_public_key_str: String,
        amount_to_send_smallest_unit: u64,
        fee_type: FeeType,
        fee_value: f64, // For fixed: in smallest_unit, for percent: 0.0-100.0
        password: &str,
        _config_path: &PathBuf,
    ) -> Result<()> {
        let current_wallet = self.get_current_wallet().await?;
        let sender_private_key = self
            .decrypt_current_wallet_private_key(password)
            .await
            .context("Incorrect wallet password or decryption failed")?;

        let recipient_verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(
            &hex::decode(&recipient_public_key_str)
                .context("Invalid recipient public key hex format")?,
        )
        .context("Invalid recipient public key bytes")?;
        let recipient_public_key = PublicKey(recipient_verifying_key);

        let amount_to_send = Amount::from_smallest_unit(amount_to_send_smallest_unit);

        // Fetch latest UTXOs before creating transaction
        self.fetch_wallet_state().await?;
        let available_utxos_guard = self.available_utxos.lock().await;

        let mut selected_inputs: Vec<TransactionInput> = Vec::new();
        let mut current_input_sum = Amount::zero();
        let mut utxos_to_use = available_utxos_guard.values().cloned().collect::<Vec<_>>();
        utxos_to_use.sort_by_key(|output| output.value.as_smallest_unit()); // Sort smallest first

        // Simple UTXO selection strategy: pick smallest UTXOs until enough funds
        for utxo_output in utxos_to_use {
            if current_input_sum >= amount_to_send {
                break; // Already have enough
            }
            selected_inputs.push(TransactionInput {
                prev_transaction_output_hash: utxo_output.hash()?,
                signature: None, // Will be signed later
            });
            current_input_sum = (current_input_sum + utxo_output.value)?;
        }

        if current_input_sum < amount_to_send {
            return Err(anyhow!(
                "Insufficient funds. Available: {}, Required: {}",
                current_input_sum,
                amount_to_send
            ));
        }

        let mut outputs: Vec<TransactionOutput> = Vec::new();
        // Recipient output
        outputs.push(TransactionOutput {
            value: amount_to_send,
            unique_id: Uuid::new_v4(),
            pubkey: recipient_public_key,
        });

        // Calculate fees
        let transaction_fee = match fee_type {
            FeeType::Fixed => Amount::from_smallest_unit(fee_value as u64),
            FeeType::Percent => {
                let calculated_fee_val =
                    (amount_to_send.as_smallest_unit() as f64 * fee_value / 100.0) as u64;
                Amount::from_smallest_unit(calculated_fee_val)
            }
        };

        let total_output_sum_excluding_change = (amount_to_send + transaction_fee)?;
        let change_amount = (current_input_sum - total_output_sum_excluding_change)?;

        // Add change output if necessary
        if change_amount > Amount::zero() {
            outputs.push(TransactionOutput {
                value: change_amount,
                unique_id: Uuid::new_v4(),
                pubkey: current_wallet.public_key.clone(), // Send change back to self
            });
        }

        let mut new_transaction = Transaction {
            inputs: selected_inputs,
            outputs,
        };

        // Sign inputs
        let transaction_hash_for_signing = new_transaction.hash_for_signing()?;
        for input in &mut new_transaction.inputs {
            let signature: ECDSASignature = sender_private_key
                .0
                .sign(&transaction_hash_for_signing.as_bytes()[..]); // Sign the hash as bytes
            input.signature = Some(wisp_core::signatures::Signature(signature));
        }

        // Submit transaction to node
        let mut stream_guard = self.get_connected_stream().await?;
        let stream_ref = stream_guard
            .as_mut()
            .expect("Expected an active TCP stream after connection attempt");
        let response_timeout = self.get_node_response_timeout().await;

        let submit_tx_msg = Message::SubmitTransaction(new_transaction.clone()); // Clone to store in pending
        submit_tx_msg
            .send_async(stream_ref)
            .await
            .context("Failed to send SubmitTransaction message")?;

        let confirmation_response =
            tokio::time::timeout(response_timeout, Message::receive_async(stream_ref))
                .await
                .context("Timeout waiting for SubmitTransaction confirmation")??;

        match confirmation_response {
            Message::TransactionAcceptedConfirmation => {
                info!("Transaction submitted and accepted by node.");
                let tx_hash = new_transaction.hash_with_signatures()?;
                self.pending_transactions
                    .lock()
                    .await
                    .insert(tx_hash, new_transaction);
                println!("✅ Transaction submitted! Hash: {}", tx_hash);
                // The fetch_wallet_state will periodically update its status.
            }
            Message::TransactionRejected(hash, reason) => {
                warn!("Transaction rejected by node: {} - {}", hash, reason);
                return Err(anyhow!("Transaction rejected by node: {}", reason));
            }
            other => {
                warn!(
                    "Unexpected response after submitting transaction: {:?}",
                    other
                );
                return Err(anyhow!(
                    "Unexpected response after submitting transaction: {:?}",
                    other
                ));
            }
        }
        Ok(())
    }

    /// Sends a simple test transaction (e.g., from genesis address to current wallet).
    /// This is for DAA testing as requested by user.
    pub async fn send_test_transaction(&self) -> Result<()> {
        let current_wallet = self.get_current_wallet().await?;
        let wallet_public_key = current_wallet.public_key.clone();

        let mut stream_guard = self.get_connected_stream().await?;
        let stream_ref = stream_guard
            .as_mut()
            .expect("Expected an active TCP stream after connection attempt");
        let response_timeout = self.get_node_response_timeout().await;

        let msg = Message::GenerateTestTransaction(wallet_public_key);
        msg.send_async(stream_ref)
            .await
            .context("Failed to send GenerateTestTransaction message")?;

        let response = tokio::time::timeout(response_timeout, Message::receive_async(stream_ref))
            .await
            .context("Timeout waiting for GenerateTestTransaction response")??;

        match response {
            Message::TransactionAcceptedConfirmation => {
                info!("Test transaction generated and accepted by node.");
                println!("✅ Test transaction sent!");
            }
            Message::TransactionRejected(hash, reason) => {
                warn!("Test transaction rejected by node: {} - {}", hash, reason);
                return Err(anyhow!("Test transaction rejected: {}", reason));
            }
            other => {
                warn!("Unexpected response for test transaction: {:?}", other);
                return Err(anyhow!(
                    "Unexpected response for test transaction: {:?}",
                    other
                ));
            }
        }
        Ok(())
    }

    /// Fetches block information from the node.
    pub async fn get_block_info(&self, index: u64) -> Result<Option<Block>> {
        let mut stream_guard = self.get_connected_stream().await?;
        let stream_ref = stream_guard
            .as_mut()
            .expect("Expected an active TCP stream after connection attempt");
        let response_timeout = self.get_node_response_timeout().await;

        let msg = Message::FetchBlockInfo(index);
        msg.send_async(stream_ref)
            .await
            .context("Failed to send FetchBlockInfo message")?;

        let response = tokio::time::timeout(response_timeout, Message::receive_async(stream_ref))
            .await
            .context("Timeout waiting for FetchBlockInfo response")??;

        match response {
            Message::BlockInfo(block) => Ok(block),
            other => Err(anyhow!(
                "Unexpected response for FetchBlockInfo: {:?}",
                other
            )),
        }
    }

    /// Fetches the latest block from the node.
    pub async fn get_latest_block(&self) -> Result<Option<(Block, u64)>> {
        let mut stream_guard = self.get_connected_stream().await?;
        let stream_ref = stream_guard
            .as_mut()
            .expect("Expected an active TCP stream after connection attempt");
        let response_timeout = self.get_node_response_timeout().await;

        let msg = Message::FetchLatestBlock;
        msg.send_async(stream_ref)
            .await
            .context("Failed to send FetchLatestBlock message")?;

        let response = tokio::time::timeout(response_timeout, Message::receive_async(stream_ref))
            .await
            .context("Timeout waiting for FetchLatestBlock response")??;

        match response {
            Message::LatestBlock(block_and_height) => Ok(block_and_height),
            other => Err(anyhow!(
                "Unexpected response for FetchLatestBlock: {:?}",
                other
            )),
        }
    }
}
