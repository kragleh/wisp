// wisp-wallet/src/commands.rs
use crate::wallet::core::{Core, FeeType};
use anyhow::{anyhow, Context, Result};
use inquire::{Confirm, Password, Select, Text};
use log::{error, info};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::timeout;
use wisp_core::currency::Amount;
use wisp_core::network::Message;

// --- UI Helper Functions ---
fn clear_terminal() {
    print!("\x1B[2J\x1B[1;1H"); // ANSI escape codes for clear screen and move cursor to top-left
    io::stdout().flush().unwrap();
}

fn display_heading() {
    println!("\nWisp");
}

fn display_heading_with_wallet(wallet_name: Option<&str>) {
    clear_terminal();
    display_heading();
    match wallet_name {
        Some(name) => println!("Active Wallet: {}\n", name),
        None => println!("No wallet currently loaded.\n"),
    }
}

fn check_terminal_size() -> bool {
    if let Some((width, height)) = termion::terminal_size().ok() {
        if width < 80 || height < 20 {
            println!("Terminal too small. Please resize to at least 80x20.");
            return false;
        }
    }
    true
}

fn prompt_password(prompt: &str) -> Result<String> {
    // Inquire's Password input already handles non-echoing
    Password::new(prompt).prompt().map_err(|e| anyhow!(e))
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = io::stdin().read_line(&mut String::new());
}

async fn export_private_key_command(core: Arc<Core>, _config_path: PathBuf) -> Result<()> {
    clear_terminal();
    let current_wallet_name = core.get_current_wallet().await?.name; // Get name for display
    display_heading_with_wallet(Some(&current_wallet_name));
    println!("--- Export Private Key ---");
    println!("WARNING: Your private key grants full control over your funds. Only export if you understand the risks and keep it highly secure!");
    println!("It is NOT recommended to share this key or store it insecurely.");

    let password = prompt_password(&format!(
        "Enter password for wallet '{}':",
        current_wallet_name
    ))?;

    // Now, decrypt the private key
    match core.decrypt_current_wallet_private_key(&password).await {
        Ok(private_key) => {
            let private_key_bytes = private_key.0.to_bytes();
            let private_key_hex = hex::encode(private_key_bytes);
            let public_key_hex = private_key.public_key().fingerprint();

            println!("\n--- YOUR PRIVATE KEY (HEX) ---");
            println!("{}", private_key_hex);
            println!("------------------------------");
            println!("Corresponding Public Key (HEX): {}", public_key_hex);
            println!("\nCopy this private key carefully. Do not share it!");
        }
        Err(e) => {
            println!("⚠️ Failed to decrypt private key: {}", e);
            return Err(e); // Propagate the error
        }
    }
    pause();
    Ok(())
}

// NOTE: raw mode for inquire is generally handled internally by the crate.
// Explicit `enable_raw_mode` and `disable_raw_mode` are often not needed
// when inquire is used correctly. If you had custom input handling, you
// might need them. Given inquire is used, I'll remove direct calls, as
// they might conflict.
// If you see weird terminal behavior, we can revisit.

fn exit_program() -> ! {
    println!("\nExiting Wisp Wallet. Goodbye!");
    std::process::exit(0);
}

// --- Main Wallet UI Logic ---

pub async fn run_wallet_ui(core: Arc<Core>, config_path: PathBuf) -> Result<(), anyhow::Error> {
    loop {
        clear_terminal();
        display_heading();

        if !check_terminal_size() {
            pause();
            continue;
        }

        let main_options = vec![
            "Open wallet",
            "Create new wallet",
            // "Recover wallet from seed", // Seed recovery not yet fully implemented in Core
            "Exit",
        ];

        let main_menu_selection = Select::new("Main Menu", main_options).prompt();

        match main_menu_selection.as_deref() {
            Ok("Open wallet") => {
                info!("Attempting to open wallet from main menu."); // Added log
                if let Err(e) = open_wallet(Arc::clone(&core), &config_path).await {
                    error!("Failed to open wallet: {}", e);
                    println!("\nFailed to open wallet: {}", e);
                    pause();
                } else {
                    info!("Wallet loaded successfully. Proceeding to wallet management."); // Added log
                                                                                           // After successful open, immediately go to management
                    if let Err(e) = wallet_management(Arc::clone(&core), &config_path).await {
                        error!("Wallet management exited with error: {}", e);
                        println!("\nWallet management error: {}", e);
                        pause();
                    }
                }
            }
            Ok("Create new wallet") => {
                info!("Attempting to create new wallet from main menu."); // Added log
                if let Err(e) = prompt_create_wallet(Arc::clone(&core), &config_path).await {
                    error!("Failed to create wallet: {}", e);
                    println!("\nFailed to create wallet: {}", e);
                    pause();
                } else {
                    info!("Wallet created successfully. Proceeding to wallet management."); // Added log
                                                                                            // After successful create, immediately go to management
                    if let Err(e) = wallet_management(Arc::clone(&core), &config_path).await {
                        error!("Wallet management exited with error: {}", e);
                        println!("\nWallet management error: {}", e);
                        pause();
                    }
                }
            }
            // Ok("Recover wallet from seed") => recover_wallet(), // Not implemented
            Ok("Exit") => exit_program(),
            Err(e) => {
                error!("Main menu selection error: {}", e);
                println!("Invalid selection: {}", e);
                pause();
            }
            _ => { /* Should not happen with inquire::Select */ }
        }
    }
}

async fn wallet_management(core: Arc<Core>, config_path: &PathBuf) -> Result<()> {
    info!("Entered wallet_management function.");

    loop {
        info!("Start of wallet_management loop iteration.");
        clear_terminal();
        let current_wallet_name = core
            .get_current_wallet()
            .await
            .ok()
            .map(|w| w.name.to_string());
        display_heading_with_wallet(current_wallet_name.as_deref());

        let wallet_options = vec![
            "Send/Receive Funds",
            "Show Balance",
            "Transaction History",
            "Blockchain Interaction",
            "Network Commands",
            "Security and Backup",
            "Utilities and Information",
            "Delete wallet",
            "Back to main menu",
        ];
        let wallet_menu_selection = Select::new("Wallet Management", wallet_options).prompt()?; // Corrected: Added ? to unwrap the Result<String, Error>

        match wallet_menu_selection.as_ref() {
            // Corrected match statement: use .as_ref()
            "Send/Receive Funds" => {
                if let Err(e) = send_receive_funds(Arc::clone(&core), config_path).await {
                    error!("Send/Receive Funds failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                }
            }
            "Show Balance" => {
                if let Err(e) = show_total_balance(Arc::clone(&core)).await {
                    error!("Show Balance failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                }
            }
            "Transaction History" => {
                if let Err(e) = transaction_history(Arc::clone(&core)).await {
                    error!("Transaction History failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                }
            }
            "Blockchain Interaction" => {
                if let Err(e) = blockchain_interaction(Arc::clone(&core)).await {
                    error!("Blockchain Interaction failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                }
            }
            "Network Commands" => {
                if let Err(e) = network_commands(Arc::clone(&core), config_path).await {
                    error!("Network Commands failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                }
            }
            "Security and Backup" => {
                if let Err(e) = security_backup(Arc::clone(&core), config_path).await {
                    error!("Security and Backup failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                }
            }
            "Utilities and Information" => {
                if let Err(e) = utilities_information(Arc::clone(&core)).await {
                    error!("Utilities and Information failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                }
            }
            "Delete wallet" => {
                if delete_current_wallet_prompt(Arc::clone(&core), config_path)
                    .await
                    .context("Failed to delete wallet")?
                {
                    // If deletion successful, return to main menu
                    return Ok(());
                }
            }
            "Back to main menu" => return Ok(()),
            _ => {
                // Catches inquire::InquireError or unexpected string
                error!("Wallet management selection error: Unexpected selection or prompt error.");
                println!("Invalid selection or prompt error.");
                pause();
            }
        }
    }
}

pub async fn open_wallet(core: Arc<Core>, config_path: &PathBuf) -> Result<String> {
    info!("Attempting to open a wallet.");
    let available_wallets = Core::load_wallets().await?;
    info!("Available wallets loaded: {:?}", available_wallets); // Added log

    if available_wallets.is_empty() {
        println!("No wallets found. Please create one first.");
        pause();
        return Err(anyhow!("No wallets found."));
    }

    let selected_wallet_name = Select::new("Select a wallet:", available_wallets).prompt()?;
    info!("Selected wallet: {}", selected_wallet_name); // Added log

    let password = prompt_password("Enter the wallet password:")?;
    info!("Password entered for wallet: {}", selected_wallet_name); // Added log

    // Crucial: Add more specific logging around the load_wallet call
    println!("Loading wallet '{}'...", selected_wallet_name); // User feedback
    match core
        .load_wallet(&selected_wallet_name, &password, config_path)
        .await
    {
        Ok(_) => {
            info!("Successfully loaded wallet: {}", selected_wallet_name); // Success log
            println!("Wallet '{}' loaded successfully!", selected_wallet_name); // User feedback
            pause(); // Keep pause here for the user to see the success message
            Ok(selected_wallet_name)
        }
        Err(e) => {
            error!("Failed to load wallet '{}': {:?}", selected_wallet_name, e); // Detailed error log
            println!("❌ Failed to load wallet '{}': {}", selected_wallet_name, e); // User feedback
            pause(); // Keep pause here for the user to see the error message
            Err(e).context(format!("Failed to load wallet '{}'", selected_wallet_name))
        }
    }
}

async fn prompt_create_wallet(core: Arc<Core>, config_path: &PathBuf) -> Result<()> {
    clear_terminal();
    display_heading();

    let wallet_file_name = Text::new("Enter a name for your wallet:").prompt()?;
    info!("Wallet name entered for creation: {}", wallet_file_name);
    let password = prompt_password("Create a password: ")?;

    info!("Attempting to create wallet: {}", wallet_file_name);
    match core
        .create_wallet(&wallet_file_name, &password, config_path)
        .await
    {
        Ok(_) => {
            info!("Wallet '{}' created successfully.", wallet_file_name);
            println!("🎉 Wallet '{}' created successfully!", wallet_file_name);
            pause();
            Ok(())
        }
        Err(e) => {
            error!("Failed to create wallet '{}': {:?}", wallet_file_name, e);
            println!("❌ Failed to create wallet '{}': {}", wallet_file_name, e);
            pause();
            Err(e).context(format!("Failed to create wallet '{}'", wallet_file_name))
        }
    }
}

async fn delete_current_wallet_prompt(
    core: Arc<Core>,
    config_path: &PathBuf,
) -> Result<bool, anyhow::Error> {
    clear_terminal();
    display_heading();

    let current_wallet_name = match core.get_current_wallet().await {
        Ok(wallet) => {
            info!("Current wallet detected for deletion: {}", wallet.name);
            wallet.name
        }
        Err(e) => {
            println!("⚠️ No wallet is currently loaded. Cannot delete.");
            error!("Attempted to delete wallet when none loaded: {}", e);
            pause();
            return Ok(false);
        }
    };

    let password = prompt_password(&format!(
        "Enter password for wallet '{}' to confirm deletion:",
        current_wallet_name
    ))?;

    info!(
        "Password entered for deletion confirmation for wallet: {}",
        current_wallet_name
    );
    match core.decrypt_current_wallet_private_key(&password).await {
        Ok(_) => {
            info!(
                "Password for deletion confirmed for wallet: {}",
                current_wallet_name
            );
            let confirmation = Confirm::new(
                format!(
                    "Are you sure you want to delete wallet '{}'? This action is irreversible.",
                    current_wallet_name
                )
                .as_str(),
            )
            .with_default(false)
            .prompt()
            .unwrap_or(false); // Inquire unwrap_or handles user cancelling

            if confirmation {
                info!(
                    "Deletion confirmed by user for wallet: {}",
                    current_wallet_name
                );
                match core.delete_wallet(&current_wallet_name, config_path).await {
                    Ok(_) => {
                        println!("🗑️ Wallet '{}' deleted successfully.", current_wallet_name);
                        info!("Wallet '{}' deleted successfully.", current_wallet_name);
                        pause();
                        Ok(true)
                    }
                    Err(e) => {
                        error!("Failed to delete wallet '{}': {}", current_wallet_name, e);
                        println!("❌ Failed to delete wallet: {}", e);
                        pause();
                        Err(e)
                    }
                }
            } else {
                info!(
                    "Deletion cancelled by user for wallet: {}",
                    current_wallet_name
                );
                println!("Deletion cancelled.");
                pause();
                Ok(false)
            }
        }
        Err(e) => {
            error!(
                "Incorrect password for wallet '{}' deletion: {}",
                current_wallet_name, e
            );
            println!("⚠️ Incorrect password. Deletion cancelled.");
            pause();
            Ok(false)
        }
    }
}

// fn recover_wallet() { /* Not implemented */ } // Kept commented as per your original

async fn show_total_balance(core: Arc<Core>) -> Result<()> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    ); // Pass name here

    info!("Attempting to show total balance.");
    match core.show_balance().await {
        Ok(_) => {
            info!("Balance displayed successfully.");
            // Balance logic handled inside core.show_balance()
        }
        Err(e) => {
            error!("Failed to show balance: {}", e);
            println!("\n❌ Failed to show balance: {}", e);
        }
    }
    pause();
    Ok(())
}

async fn send_receive_funds(core: Arc<Core>, config_path: &PathBuf) -> Result<()> {
    loop {
        clear_terminal();
        display_heading_with_wallet(
            core.get_current_wallet()
                .await
                .ok()
                .map(|w| w.name)
                .as_deref(),
        ); // Pass name here

        let send_receive_options = vec![
            "Send funds",
            "Receive funds",
            "Send Test Transaction (for DAA testing)",
            "Back to wallet menu",
        ];
        let send_receive_menu_selection =
            Select::new("Send and Receive Funds", send_receive_options).prompt()?;

        // Corrected match statement: use .as_ref() to get &str from String
        match send_receive_menu_selection.as_ref() {
            "Send funds" => {
                send_funds_prompt(Arc::clone(&core), config_path).await?;
            }
            "Receive funds" => receive_funds(&core).await?,
            "Send Test Transaction (for DAA testing)" => {
                println!("Attempting to send test transaction...");
                core.send_test_transaction().await?;
                println!("Test transaction attempt finished.");
                pause();
            }
            "Back to wallet menu" => return Ok(()),
            _ => {
                // This will catch any unexpected selections or errors from prompt()
                error!("Send/Receive menu selection error: Invalid selection or prompt error.");
                println!("Invalid selection or prompt error.");
                pause();
            }
        }
    }
}

async fn send_funds_prompt(core: Arc<Core>, _config_path: &PathBuf) -> Result<()> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );

    let recipient_public_key_str = Text::new("Enter recipient's public key (hex):")
        .prompt()
        .context("Failed to read recipient's public key")?;

    let amount_str =
        Text::new("Enter amount to send (in smallest units, e.g., 100000000 for 1 coin):")
            .prompt()
            .context("Failed to read amount")?;
    let amount = amount_str
        .parse::<u64>()
        .context("Invalid amount entered, must be a number")?;

    let fee_type =
        Select::new("Select fee type:", vec![FeeType::Fixed, FeeType::Percent]).prompt()?;

    let fee_value_str = Text::new(
        format!(
            "Enter fee value (for {}: for Fixed, smallest units; for Percent, 0.0-100.0):",
            fee_type
        )
        .as_str(),
    )
    .prompt()
    .context("Failed to read fee value")?;
    let fee_value = fee_value_str
        .parse::<f64>()
        .context("Invalid fee value entered, must be a number")?;

    let password = prompt_password("Enter your wallet password:")?;

    core.send_funds(
        recipient_public_key_str,
        amount,
        fee_type,
        fee_value,
        &password,
        _config_path, // <--- ADD THIS ARGUMENT
    )
    .await
    .context("Failed to send funds")?;

    pause();
    Ok(())
}

async fn receive_funds(core: &Core) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );

    match core.get_current_wallet().await {
        Ok(wallet) => {
            println!("\nYour public key (share this to receive funds):");
            println!("{}", wallet.public_key.fingerprint());
        }
        Err(_) => println!("⚠️ No wallet loaded."),
    }
    pause();
    Ok(())
}

async fn transaction_history(core: Arc<Core>) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );

    let current_wallet = core.get_current_wallet().await?;
    let wallet_public_key = current_wallet.public_key.clone();

    println!(
        "Fetching transaction history for wallet: {}",
        wallet_public_key.fingerprint()
    );

    let mut stream_guard = core.get_connected_stream().await?; // This is MutexGuard<Option<TcpStream>>
                                                               // Extract the actual TcpStream from the Option within the MutexGuard
    let stream_ref = stream_guard
        .as_mut()
        .expect("Expected an active TCP stream for transaction history");
    let response_timeout = core.get_node_response_timeout().await;

    let message = Message::FetchTransactionHistory(wallet_public_key);

    message
        .send_async(stream_ref) // Pass the &mut TcpStream directly
        .await
        .context("Error sending transaction history request")?;

    match timeout(response_timeout, Message::receive_async(stream_ref)) // Pass the &mut TcpStream directly
        .await
        .context("Timeout waiting for transaction history response")??
    {
        Message::TransactionHistory(history) => {
            println!("--------------------");
            println!("Transaction History:");
            println!("--------------------");
            if history.is_empty() {
                println!("No transactions found for this wallet.");
            } else {
                for tx in history {
                    println!(
                        "Transaction ID: {}",
                        tx.hash_with_signatures()
                            .ok()
                            .map_or("<unhashable>".to_string(), |hash| hash.to_string())
                    );

                    println!("  Inputs:");
                    if tx.inputs.is_empty() {
                        println!("    (Coinbase transaction)");
                    } else {
                        for input in &tx.inputs {
                            println!(
                                "    Previous Output Hash: {}",
                                input.prev_transaction_output_hash
                            );
                        }
                    }

                    println!("  Outputs:");
                    if tx.outputs.is_empty() {
                        println!("    (No outputs)");
                    } else {
                        for output in &tx.outputs {
                            println!("    Value: {}", output.value);
                            println!("    Recipient: {}", output.pubkey.fingerprint());
                            println!("    Output ID: {}", output.unique_id);
                        }
                    }
                    println!("--------------------");
                }
            }
        }
        response => {
            return Err(anyhow!("Unexpected response from node: {:?}", response)
                .context("When fetching transaction history"));
        }
    }
    pause();
    Ok(())
}

async fn blockchain_interaction(core: Arc<Core>) -> Result<(), anyhow::Error> {
    loop {
        clear_terminal();
        display_heading_with_wallet(
            core.get_current_wallet()
                .await
                .ok()
                .map(|w| w.name)
                .as_deref(),
        );
        let blockchain_options = vec![
            "Start mining (spawn wisp-flame)",
            "Get block information",
            "Get latest block",
            "Back to wallet menu",
        ];
        let blockchain_menu_selection =
            Select::new("Blockchain Interaction", blockchain_options).prompt()?;

        match blockchain_menu_selection.as_ref() {
            // Corrected match statement: use .as_ref()
            "Start mining (spawn wisp-flame)" => start_miner_prompt(&core).await?,
            "Get block information" => get_block_info(&core).await?,
            "Get latest block" => get_latest_block(&core).await?,
            "Back to wallet menu" => return Ok(()),
            _ => {
                error!("Blockchain interaction menu selection error: Invalid selection or prompt error.");
                println!("Invalid selection or prompt error.");
                pause();
            }
        }
    }
}

async fn start_miner_prompt(core: &Core) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );

    let config_guard = core.config.lock().await;
    let default_node_address = config_guard.default_node.clone();
    drop(config_guard); // Release lock early

    let node_address_for_miner = Text::new("Enter the node address for the miner to connect to:")
        .with_default(&default_node_address)
        .prompt()
        .context("Failed to read miner node address")?;

    let current_wallet = core.get_current_wallet().await?;
    let public_key_for_miner = current_wallet.public_key.fingerprint(); // Hex format

    println!("Attempting to spawn wisp-flame miner in background...");
    println!("Miner will connect to: {}", node_address_for_miner);
    println!("Miner will send rewards to: {}", public_key_for_miner);

    // Spawn the wisp-flame miner as a separate process
    // This assumes `wisp-flame` is built and accessible in your PATH,
    // or located relative to your `wisp-wallet` executable.
    let miner_executable_name = "wisp-flame"; // Adjust if your binary name is different

    match tokio::process::Command::new(miner_executable_name)
        .arg("--node-address")
        .arg(&node_address_for_miner)
        .arg("--reward-address")
        .arg(&public_key_for_miner)
        .spawn()
    {
        Ok(_) => {
            println!("✅ Miner (wisp-flame) spawned successfully in the background!");
            println!("Check your system's process manager or console for miner output.");
        }
        Err(e) => {
            error!("Failed to spawn wisp-flame miner: {}", e);
            println!("❌ Failed to spawn miner: {}", e);
            println!("Ensure 'wisp-flame' is compiled and accessible in your PATH.");
        }
    }

    pause();
    Ok(())
}

async fn get_block_info(core: &Core) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );

    let index_str = Text::new("Enter the index of the block you want to view:").prompt()?;
    let index = index_str
        .parse::<u64>()
        .context("Invalid block index entered, must be a number")?;

    match core.get_block_info(index).await {
        Ok(Some(block)) => {
            println!("\n--- Block Information ---");
            println!("Index: {}", block.index);
            println!("Timestamp: {}", block.timestamp);
            println!("Nonce: {}", block.nonce);
            println!("Previous Hash: {}", block.previous_hash);
            println!("Merkle Root: {:?}", block.merkle_root);
            println!("Target: {}", block.target);
            println!("Number of Transactions: {}", block.transactions.len());
            println!("Transactions:");
            if block.transactions.is_empty() {
                println!("  (No transactions)");
            } else {
                for tx in &block.transactions {
                    println!(
                        "  Hash: {}",
                        tx.hash_with_signatures()
                            .ok()
                            .map_or("<unhashable>".to_string(), |hash| hash.to_string())
                    );
                    if tx.inputs.is_empty() {
                        println!("    (Coinbase transaction)");
                    }
                    // Could add more details here (inputs/outputs)
                }
            }
            println!("-------------------------");
        }
        Ok(None) => {
            println!("Block with index {} not found on the node.", index);
        }
        Err(e) => {
            error!("Failed to get block info: {}", e);
            println!("❌ Failed to get block information: {}", e);
        }
    }

    pause();
    Ok(())
}

async fn get_latest_block(core: &Core) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );
    println!("Getting latest block from the node...");

    match core.get_latest_block().await {
        Ok(Some((block, height))) => {
            println!("\n--- Latest Block Information ---");
            println!("Height: {}", height); // This is the height of the block (0-indexed)
            println!("Index (from block header): {}", block.index); // Confirm it matches height
            println!("Timestamp: {}", block.timestamp);
            println!("Nonce: {}", block.nonce);
            println!("Previous Hash: {}", block.previous_hash);
            println!("Merkle Root: {:?}", block.merkle_root);
            println!("Target: {}", block.target);
            println!("Number of Transactions: {}", block.transactions.len());
            println!("Transactions:");
            if block.transactions.is_empty() {
                println!("  (No transactions)");
            } else {
                for tx in &block.transactions {
                    println!(
                        "  Hash: {}",
                        tx.hash_with_signatures()
                            .ok()
                            .map_or("<unhashable>".to_string(), |hash| hash.to_string())
                    );
                    if tx.inputs.is_empty() {
                        println!("    (Coinbase transaction)");
                    }
                }
            }
            println!("-------------------------");
        }
        Ok(None) => {
            println!("⚠️ Could not retrieve the latest block from the node.");
        }
        Err(e) => {
            error!("Failed to get latest block: {}", e);
            println!("❌ Failed to get latest block: {}", e);
        }
    }

    pause();
    Ok(())
}

async fn network_commands(core: Arc<Core>, _config_path: &PathBuf) -> Result<(), anyhow::Error> {
    loop {
        clear_terminal();
        display_heading_with_wallet(
            core.get_current_wallet()
                .await
                .ok()
                .map(|w| w.name)
                .as_deref(),
        );
        let network_options = vec![
            "Connect to default node (force reconnect)",
            "List discovered peers",
            "Clear discovered nodes list",
            // "Sync with network (Placeholder)",
            "Back to wallet menu",
        ];
        let network_menu_selection = Select::new("Network Commands", network_options).prompt()?;

        match network_menu_selection.as_ref() {
            // Corrected match statement: use .as_ref()
            "Connect to default node (force reconnect)" => connect_node(&core).await?,
            "List discovered peers" => list_peers(&core).await,
            "Clear discovered nodes list" => clear_discovered_nodes(&core).await?,
            // "Sync with network (Placeholder)" => sync_network(), // Placeholder
            "Back to wallet menu" => return Ok(()),
            _ => {
                error!("Network commands menu selection error: Invalid selection or prompt error.");
                println!("Invalid selection or prompt error.");
                pause();
            }
        }
    }
}

async fn connect_node(core: &Core) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );

    println!("Attempting to connect to default node...");
    match core.get_connected_stream().await {
        Ok(_) => {
            println!("✅ Successfully connected to the default node.");
        }
        Err(e) => {
            error!("Failed to connect to node: {}", e);
            println!("❌ Failed to connect to node: {}", e);
        }
    }
    pause();
    Ok(())
}

async fn clear_discovered_nodes(core: &Core) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );

    let confirmation = Confirm::new("Do you want to clear the list of discovered nodes?")
        .with_default(false)
        .prompt()
        .unwrap_or(false);

    if confirmation {
        let mut discovered_nodes_guard = core.discovered_nodes.lock().await;
        discovered_nodes_guard.clear();
        println!("✅ List of discovered nodes cleared.");
    } else {
        println!("Operation cancelled.");
    }

    pause();
    Ok(())
}

async fn list_peers(core: &Core) {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );
    println!("Discovered Peers:");
    println!("------------------");

    let discovered_nodes_guard = core.discovered_nodes.lock().await;
    if discovered_nodes_guard.is_empty() {
        println!("No peers have been discovered yet.");
    } else {
        for (address, last_seen) in discovered_nodes_guard.iter() {
            match last_seen {
                Some(duration) => {
                    // Convert Duration to more readable format
                    let total_secs = duration.as_secs();
                    let mins = total_secs / 60;
                    let secs = total_secs % 60;
                    println!("Address: {}, Last Seen: {}m {}s ago", address, mins, secs);
                }
                None => println!("Address: {}, Status: Unknown/Inactive", address),
            }
        }
    }
    println!("------------------");
    pause();
}

// fn sync_network() { /* Placeholder */ } // Kept commented

async fn security_backup(core: Arc<Core>, config_path: &PathBuf) -> Result<(), anyhow::Error> {
    loop {
        clear_terminal();
        display_heading_with_wallet(
            core.get_current_wallet()
                .await
                .ok()
                .map(|w| w.name)
                .as_deref(),
        );
        let security_options = vec![
            "Backup wallet (Not Implemented)",
            "Change wallet password",
            "Export Private Key (DANGER ZONE)",
            "Back to wallet menu",
        ];
        let security_menu_selection =
            Select::new("Security and Backup", security_options).prompt()?;

        match security_menu_selection.as_ref() {
            // Corrected match statement: use .as_ref()
            "Backup wallet (Not Implemented)" => {
                println!("This feature is currently disabled.");
                pause();
            }
            "Export Private Key (DANGER ZONE)" => {
                if let Err(e) =
                    export_private_key_command(Arc::clone(&core), config_path.clone()).await
                {
                    error!("Export private key failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                }
            }
            "Change wallet password" => {
                if let Err(e) = prompt_change_wallet_password(core.clone(), config_path).await {
                    error!("Change wallet password failed: {}", e);
                    println!("\nError: {}", e);
                    pause();
                } else {
                    println!("Password changed successfully.");
                    pause();
                }
            }
            "Back to wallet menu" => return Ok(()),
            _ => {
                error!("Security menu selection error: Invalid selection or prompt error.");
                println!("Invalid selection or prompt error.");
                pause();
            }
        }
    }
}

async fn prompt_change_wallet_password(
    core: Arc<Core>,
    config_path: &PathBuf,
) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(), // "Recover wallet from seed", // Seed recovery not yet fully implemented in Core
    );

    let current_password = prompt_password("Enter your current password:")?;
    let new_password = prompt_password("Enter your new password:")?;

    core.change_wallet_password(&current_password, &new_password, config_path)
        .await
        .context("Failed to change wallet password")?;

    pause();
    Ok(())
}

async fn utilities_information(core: Arc<Core>) -> Result<(), anyhow::Error> {
    loop {
        clear_terminal();
        display_heading_with_wallet(
            core.get_current_wallet()
                .await
                .ok()
                .map(|w| w.name)
                .as_deref(),
        );
        let utilities_options = vec![
            "Get wallet and node info",
            "Output debug information (Not Implemented)",
            "Back to wallet menu",
        ];
        let utilities_menu_selection =
            Select::new("Utilities and Information", utilities_options).prompt()?;

        match utilities_menu_selection.as_ref() {
            // Corrected match statement: use .as_ref()
            "Get wallet and node info" => get_info(&core).await?,
            "Output debug information (Not Implemented)" => {
                println!("This feature is currently disabled.");
                pause();
            }
            "Back to wallet menu" => return Ok(()),
            _ => {
                error!("Utilities menu selection error: Invalid selection or prompt error.");
                println!("Invalid selection or prompt error.");
                pause();
            }
        }
    }
}

async fn get_info(core: &Core) -> Result<(), anyhow::Error> {
    clear_terminal();
    display_heading_with_wallet(
        core.get_current_wallet()
            .await
            .ok()
            .map(|w| w.name)
            .as_deref(),
    );

    match core.get_current_wallet().await {
        Ok(wallet) => {
            println!("Wallet Name: {}", wallet.name);
            println!("Public Key: {}", wallet.public_key.fingerprint());
            let config_guard = core.config.lock().await;
            println!("Default Node: {}", config_guard.default_node);
            drop(config_guard);

            let discovered_nodes_guard = core.discovered_nodes.lock().await;
            let healthy_nodes_count = discovered_nodes_guard
                .iter()
                .filter(|(_, last_seen)| last_seen.is_some())
                .count();
            let total_discovered_nodes = discovered_nodes_guard.len();

            println!("Total Discovered Nodes: {}", total_discovered_nodes);
            println!("Healthy Discovered Nodes: {}", healthy_nodes_count);
            println!("Connection Status: Connections are established on demand for each action.");

            let available_utxos_guard = core.available_utxos.lock().await;
            let total_utxo_value = available_utxos_guard
                .values()
                .fold(Amount::zero(), |acc, output| {
                    (acc + output.value).unwrap_or_else(|_| Amount::zero())
                });
            println!("Local UTXO Cache Count: {}", available_utxos_guard.len());
            println!("Local UTXO Cache Value: {}", total_utxo_value);

            let pending_tx_guard = core.pending_transactions.lock().await;
            println!("Local Pending Tx Count: {}", pending_tx_guard.len());
        }
        Err(_) => {
            println!("⚠️ No wallet loaded.");
            println!("Node information is unavailable until a wallet is loaded.");
        }
    }

    pause();
    Ok(())
}
