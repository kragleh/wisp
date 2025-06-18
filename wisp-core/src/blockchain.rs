use std::{
    cmp::max,
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    currency::Amount,
    network::TransactionStatus,
    signatures::PublicKey,
    utils::{calculate_block_reward, Saveable},
    IDEAL_BLOCK_TIME, SIMPLE_DAA_WINDOW,
};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use k256::ecdsa::VerifyingKey;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};

use crate::{
    sha256::Hash,
    transactions::{Transaction, TransactionOutput},
    utils::MerkleRoot,
    U256,
};

#[derive(Debug)]
pub enum AddBlockResult {
    Added,
    Rejected(String),
    PotentialLongerForkDetected {
        common_ancestor_index: u64,
        new_block_index: u64,
        new_block_hash: Hash,
    },
    OrphanedOrDisconnected(String),
    ShorterForkRejected(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    pub timestamp: DateTime<Utc>,
    pub nonce: u64,
    pub previous_hash: Hash,
    pub merkle_root: MerkleRoot,
    pub target: U256,
    pub index: u64,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new(
        timestamp: DateTime<Utc>,
        nonce: u64,
        previous_hash: Hash,
        merkle_root: MerkleRoot,
        target: U256,
        index: u64,
        transactions: Vec<Transaction>,
    ) -> Self {
        Block {
            timestamp,
            nonce,
            previous_hash,
            merkle_root,
            target,
            index,
            transactions,
        }
    }

    pub fn hash_with_signatures(&self) -> Result<Hash, anyhow::Error> {
        Hash::hash(self)
    }

    pub fn calculate_total_fees(
        &self,
        utxos: &HashMap<Hash, (bool, TransactionOutput)>,
    ) -> Result<Amount> {
        let mut inputs_total = Amount::zero();
        let mut outputs_total = Amount::zero();

        for transaction in self.transactions.iter().skip(1) {
            for input in &transaction.inputs {
                let prev_output = utxos
                    .get(&input.prev_transaction_output_hash)
                    .map(|(_, output)| output);
                let prev_output =
                    prev_output.ok_or_else(|| anyhow!("Transaction input UTXO not found..."))?;
                inputs_total = (inputs_total + prev_output.value)?;
            }

            for output in &transaction.outputs {
                outputs_total = (outputs_total + output.value)?;
            }
        }

        if inputs_total < outputs_total {
            Err(anyhow!(
                "Input value less than output value in fee calculation: inputs ({}) < outputs ({})",
                inputs_total,
                outputs_total
            ))
        } else {
            inputs_total - outputs_total
        }
    }

    pub fn verify_transactions(
        &self,
        _predicted_block_height: u64,
        current_utxos: &HashMap<Hash, (bool, TransactionOutput)>,
    ) -> Result<()> {
        let mut inputs_in_block: HashSet<Hash> = HashSet::new();
        if self.transactions.is_empty() {
            return Err(anyhow!("Empty transactions"));
        }

        for transaction in self.transactions.iter().skip(1) {
            let tx_hash_for_verification = transaction.hash_for_signing()?;
            let tx_hash_for_logging = transaction.hash_with_signatures()?;

            let mut input_value = Amount::zero();
            let mut output_value = Amount::zero();
            let mut inputs_checked_in_tx: HashSet<Hash> = HashSet::new();

            if transaction.inputs.is_empty() {
                return Err(anyhow!(
                    "Non-coinbase transaction {} has no inputs",
                    tx_hash_for_logging
                ));
            }
            if transaction.outputs.is_empty() {
                return Err(anyhow!(
                    "Non-coinbase transaction {} has no outputs",
                    tx_hash_for_logging
                ));
            }

            for input in &transaction.inputs {
                let prev_output_hash = &input.prev_transaction_output_hash;

                if inputs_in_block.contains(prev_output_hash) {
                    return Err(anyhow!(
                        "Double spend within block: input {}",
                        prev_output_hash
                    ));
                }
                if !inputs_checked_in_tx.insert(prev_output_hash.clone()) {
                    return Err(anyhow!(
                        "Duplicate input within transaction {}: {}",
                        tx_hash_for_logging,
                        prev_output_hash
                    ));
                }

                let prev_output = current_utxos
                    .get(prev_output_hash)
                    .map(|(_, output)| output);
                if prev_output.is_none() {
                    return Err(anyhow!(
                        "Transaction input UTXO {} not found",
                        prev_output_hash
                    ));
                }

                let prev_output = prev_output.unwrap();
                let is_signature_valid = match input.signature.as_ref() {
                    Some(sig) => {
                        sig.verify_transaction_hash(&tx_hash_for_verification, &prev_output.pubkey)
                    }
                    None => false,
                };

                if !is_signature_valid {
                    let sig_status = if input.signature.is_none() {
                        "missing"
                    } else {
                        "invalid"
                    };
                    return Err(anyhow!(
                        "Transaction signature {} for input {} in transaction {}",
                        sig_status,
                        prev_output_hash,
                        tx_hash_for_logging
                    ));
                }

                input_value = (input_value + prev_output.value)?;
                inputs_in_block.insert(prev_output_hash.clone());
            }

            let mut outputs_checked_in_tx: HashSet<Hash> = HashSet::new();
            for output in &transaction.outputs {
                let output_hash = output.hash()?;
                if !outputs_checked_in_tx.insert(output_hash) {
                    return Err(anyhow!(
                        "Duplicate output within transaction {}: {}",
                        tx_hash_for_logging,
                        output_hash
                    ));
                }
                output_value = (output_value + output.value)?;
            }

            if input_value < output_value {
                return Err(anyhow!(
                    "Insufficient funds in transaction {}: inputs ({}) < outputs ({})",
                    tx_hash_for_logging,
                    input_value,
                    output_value
                ));
            }
        }

        Ok(())
    }

    pub fn verify_coinbase_transaction(
        &self,
        block_index: u64,
        total_fees_in_block: Amount,
    ) -> Result<()> {
        if self.transactions.is_empty() {
            return Err(anyhow!("Block has no transactions (missing coinbase)"));
        }
        let coinbase_transaction = self
            .transactions
            .get(0)
            .ok_or_else(|| anyhow!("Block is empty, missing coinbase transaction"))?;

        if !coinbase_transaction.inputs.is_empty() {
            return Err(anyhow!("Coinbase transaction must have no inputs"));
        }

        if coinbase_transaction.outputs.is_empty() {
            return Err(anyhow!("Coinbase transaction must have outputs"));
        }

        let block_reward = calculate_block_reward(block_index);
        let expected_total_coinbase = (block_reward + total_fees_in_block)?;
        let mut actual_total_coinbase_outputs = Amount::zero();
        for output in coinbase_transaction.outputs.iter() {
            actual_total_coinbase_outputs =
                (actual_total_coinbase_outputs + output.value).unwrap_or_else(|_| Amount::MAX);
        }
        if actual_total_coinbase_outputs == Amount::MAX {
            return Err(anyhow!("Coinbase transaction output sum overflowed."));
        }

        if actual_total_coinbase_outputs != expected_total_coinbase {
            return Err(anyhow!(
                "Invalid coinbase reward. Expected: {}, Actual: {}",
                expected_total_coinbase,
                actual_total_coinbase_outputs
            ));
        }
        Ok(())
    }

    pub fn validate_block(
        &self,
        current_utxos: &HashMap<Hash, (bool, TransactionOutput)>,
        expected_target: &U256,
    ) -> Result<()> {
        let block_hash = self.hash_with_signatures()?;
        info!(
            "Validating block with hash: {} at index {}",
            block_hash, self.index
        );

        if !block_hash.matches_target(self.target) {
            return Err(anyhow!(
                "Block hash ({}) does not meet its own target ({}) (PoW failed)",
                block_hash,
                self.target
            ));
        }
        debug!("PoW valid against block's own target.");

        if self.target != *expected_target {
            return Err(anyhow!(
                "Block's declared target ({}) does not match expected target ({}) for index {}",
                self.target,
                expected_target,
                self.index
            ));
        }
        debug!("Block's target matches expected target.");

        let calculated_merkle_root = MerkleRoot::calculate(&self.transactions)
            .context("Failed to calculate Merkle root during block validation")?;
        if calculated_merkle_root != self.merkle_root {
            return Err(anyhow!(
                "Merkle root mismatch. Expected: {:?}, Calculated: {:?}",
                self.merkle_root,
                calculated_merkle_root
            ));
        }
        debug!("Merkle root validation passed.");

        let now = Utc::now();
        if self.timestamp > now + ChronoDuration::seconds(crate::MAX_BLOCK_FUTURE_TIMESTAMP as i64)
        {
            return Err(anyhow!("Block timestamp is too far in the future"));
        }
        debug!("Timestamp validation passed.");

        if self.transactions.is_empty() {
            return Err(anyhow!(
                "Block must contain at least a coinbase transaction."
            ));
        }

        let total_miner_fees = self
            .calculate_total_fees(current_utxos)
            .context("Failed to calculate miner fees for block validation")?;
        debug!("Miner fees calculated: {}", total_miner_fees);

        self.verify_coinbase_transaction(self.index, total_miner_fees)
            .context("Coinbase transaction verification failed")?;
        debug!("Coinbase transaction validation passed.");

        self.verify_transactions(self.index, current_utxos)
            .context("Regular transactions verification failed")?;
        debug!("Regular transactions validation passed.");

        Ok(())
    }

    pub fn mine_block(&mut self, steps: usize) -> Result<bool> {
        // println!("DEBUG: Miner using target: {:?}", self.target);

        if self.hash_with_signatures()?.matches_target(self.target) {
            println!("Block already matches target before mining.");
            return Ok(true);
        }

        for _i in 0..steps {
            if let Some(new_nonce) = self.nonce.checked_add(1) {
                self.nonce = new_nonce;
            } else {
                self.nonce = 0;
                self.timestamp = Utc::now();
            }

            if self.hash_with_signatures()?.matches_target(self.target) {
                // println!("Block mined successfully after {} hashes.", i + 1);
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn mine_block_parallel(
        &mut self,
        start_nonce: u64,
        nonce_step: u64,
        max_attempts_per_call: usize,
        mining_active: &AtomicBool,
    ) -> Result<bool> {
        self.nonce = start_nonce; // Set the starting nonce for this thread

        for _i in 0..max_attempts_per_call {
            // Check if mining should stop (e.g., another thread found a block)
            if !mining_active.load(Ordering::Relaxed) {
                return Ok(false); // Stop mining if flag is false
            }

            // Check if the current hash meets the target
            if self.hash_with_signatures()?.matches_target(self.target) {
                return Ok(true); // Block mined successfully
            }

            // Increment nonce for the next attempt by the thread's step
            // Use wrapping_add for nonce to allow it to cycle around (important for 64-bit nonces)
            self.nonce = self.nonce.wrapping_add(nonce_step);
        }
        Ok(false) // No solution found within the given attempts for this call
    }

    pub fn check_proof_of_work(&self) -> bool {
        let hash = self
            .hash_with_signatures()
            .expect("Failed to hash block for PoW check");
        hash.matches_target(self.target)
    }
}

impl Saveable for Block {
    fn load<I: Read>(reader: I) -> IoResult<Self> {
        serde_json::from_reader(reader).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to deserialize Block: {}", e),
            )
        })
    }

    fn save<O: Write>(&self, writer: O) -> IoResult<()> {
        serde_json::to_writer_pretty(writer, self).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to serialize Block: {}", e),
            )
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde_as]
pub struct Blockchain {
    #[serde_as(as = "Map<DisplayFromStr, _>")]
    utxos: HashMap<Hash, (bool, TransactionOutput)>,
    pub target: U256,
    blocks: Vec<Block>,
    #[serde(default)]
    mempool: Vec<(DateTime<Utc>, Transaction, Amount)>,
}

impl Blockchain {
    pub fn new_genesis() -> Result<Self> {
        let mut blockchain = Blockchain {
            utxos: HashMap::new(),
            target: crate::MAX_TARGET,
            blocks: vec![],
            mempool: vec![],
        };

        println!("Creating genesis block.");

        let genesis_pubkey_bytes =
            hex::decode("02c2a7bd55e629da5b9c8673a0d43353e224a7f4ea55662ffe456e97e6009904fd")?;
        let genesis_verifying_key = VerifyingKey::from_sec1_bytes(&genesis_pubkey_bytes)?;

        let genesis_transaction = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                value: Amount::from_smallest_unit(crate::INITIAL_BLOCK_REWARD_SMALLEST_UNITS),
                unique_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000000")
                    .expect("Invalid genesis unique ID string"),
                pubkey: PublicKey(genesis_verifying_key),
            }],
        };

        let merkle_root = MerkleRoot::calculate(&[genesis_transaction.clone()])?;
        let fixed_timestamp_str = "2024-01-01T00:00:00Z";
        let fixed_timestamp = DateTime::parse_from_rfc3339(fixed_timestamp_str)
            .expect("Failed to parse fixed genesis timestamp")
            .with_timezone(&Utc);
        let genesis_block = Block::new(
            fixed_timestamp,
            0,
            Hash::zero(),
            merkle_root,
            crate::MAX_TARGET,
            0,
            vec![genesis_transaction.clone()],
        );

        blockchain.blocks.push(genesis_block.clone());
        blockchain.rebuild_utxos()?;

        println!("Genesis Block created and added.");
        println!(
            "Genesis Block Hash: {}",
            blockchain.blocks[0]
                .hash_with_signatures()
                .expect("Failed to hash genesis block")
        );
        if let Some(genesis_tx) = blockchain.blocks[0].transactions.first() {
            println!(
                "Genesis Transaction Hash: {}",
                genesis_tx
                    .hash_with_signatures()
                    .expect("Failed to hash genesis transaction")
            );
        }
        println!("Initial UTXO set size: {}", blockchain.utxos.len());
        Ok(blockchain)
    }

    pub fn load_from_file(blockchain_file_path: &str) -> Result<Self> {
        let file = std::fs::File::open(blockchain_file_path)
            .map_err(|e| anyhow!("Failed to open blockchain file for loading: {}", e))?;
        Self::load(file).map_err(|e| anyhow!("Failed to load blockchain from file: {}", e))
    }

    pub fn utxos(&self) -> &HashMap<Hash, (bool, TransactionOutput)> {
        &self.utxos
    }

    pub fn blocks(&self) -> &Vec<Block> {
        &self.blocks
    }

    pub fn mempool(&self) -> &[(DateTime<Utc>, Transaction, Amount)] {
        &self.mempool
    }

    pub fn block_height(&self) -> u64 {
        self.blocks.len() as u64
    }

    pub fn calculate_next_target(&self) -> Result<U256> {
        let current_height = self.block_height();

        if current_height <= SIMPLE_DAA_WINDOW as u64 {
            return Ok(crate::MAX_TARGET);
        }

        let window_start_index = current_height as usize - SIMPLE_DAA_WINDOW;
        let window_blocks = &self.blocks[window_start_index..current_height as usize];
        let first_block_timestamp = window_blocks.first().unwrap().timestamp;
        let last_block_timestamp = window_blocks.last().unwrap().timestamp;
        let actual_time_span = last_block_timestamp
            .signed_duration_since(first_block_timestamp)
            .num_seconds();
        let actual_time_span_seconds = max(1, actual_time_span) as u64;
        let expected_time_span_seconds = IDEAL_BLOCK_TIME * SIMPLE_DAA_WINDOW as u64;
        let current_target = window_blocks.last().unwrap().target;
        let actual_time_u256: U256 = actual_time_span_seconds.into();
        let expected_time_u256: U256 = expected_time_span_seconds.into();
        if expected_time_u256.is_zero() {
            return Err(anyhow!(
                "Expected time for DAA calculation is zero, impossible."
            ));
        }

        let numerator = current_target
            .checked_mul(actual_time_u256)
            .ok_or_else(|| anyhow!("DAA calculation overflow during multiplication"))?;
        let mut new_target = numerator / expected_time_u256;
        let min_clamped_target = current_target / U256::from(4);
        let max_clamped_target = current_target * U256::from(4);

        new_target = new_target.max(min_clamped_target);
        new_target = new_target.min(max_clamped_target);
        new_target = new_target.min(crate::MAX_TARGET);
        new_target = new_target.max(crate::MIN_TARGET);

        if new_target == U256::zero() {
            new_target = U256::from(1);
        }

        Ok(new_target)
    }

    pub fn add_block(&mut self, new_block: Block) -> AddBlockResult {
        let new_block_hash = match new_block.hash_with_signatures() {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to hash new block: {}", e);
                return AddBlockResult::Rejected(format!("Failed to hash new block: {}", e));
            }
        };
        info!(
            "Attempting to add block with hash: {} at index {}",
            new_block_hash, new_block.index
        );

        if self.blocks.is_empty() {
            if new_block.index != 0 {
                return AddBlockResult::Rejected(format!(
                    "Received first block with non-zero index: {}",
                    new_block.index
                ));
            }

            if new_block.previous_hash != Hash::zero() {
                return AddBlockResult::Rejected(String::from(
                    "Genesis block invalid previous hash",
                ));
            }
            if new_block.transactions.is_empty() {
                return AddBlockResult::Rejected(String::from(
                    "Genesis block missing transactions",
                ));
            }
            if new_block.transactions.len() != 1 {
                return AddBlockResult::Rejected(String::from(
                    "Genesis block must contain exactly one transaction (coinbase)",
                ));
            }
            if new_block.target != crate::MAX_TARGET {
                return AddBlockResult::Rejected(String::from("Genesis block invalid target"));
            }
            let fixed_timestamp_str = "2024-01-01T00:00:00Z";
            let fixed_timestamp = DateTime::parse_from_rfc3339(fixed_timestamp_str)
                .unwrap()
                .with_timezone(&Utc);
            if new_block.timestamp != fixed_timestamp {
                return AddBlockResult::Rejected(String::from("Genesis block invalid timestamp"));
            }
            let calculated_merkle_root = match MerkleRoot::calculate(&new_block.transactions) {
                Ok(mr) => mr,
                Err(e) => {
                    return AddBlockResult::Rejected(format!(
                        "Failed to calculate Merkle root for genesis: {}",
                        e
                    ))
                }
            };
            if calculated_merkle_root != new_block.merkle_root {
                return AddBlockResult::Rejected(String::from("Merkle root mismatch for genesis"));
            }

            if let Err(e) = new_block.verify_coinbase_transaction(new_block.index, Amount::zero()) {
                return AddBlockResult::Rejected(format!(
                    "Genesis coinbase verification failed: {}",
                    e
                ));
            }

            self.blocks.push(new_block.clone());
            if let Err(e) = self.apply_block_to_utxos(&new_block) {
                error!("Failed to apply genesis block UTXOs: {}", e);

                return AddBlockResult::Rejected(format!(
                    "Failed to apply genesis block UTXOs: {}",
                    e
                ));
            }
            self.clear_mempool_of_block_transactions(&new_block);
            info!("Genesis block added successfully.");
            return AddBlockResult::Added;
        }

        let current_chain_tip = self.blocks.last().unwrap();
        let current_chain_tip_hash = match current_chain_tip.hash_with_signatures() {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to hash current chain tip: {}", e);
                return AddBlockResult::Rejected(format!(
                    "Failed to hash current chain tip: {}",
                    e
                ));
            }
        };
        let expected_next_index = self.block_height();
        let expected_next_target = match self.calculate_next_target() {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to calculate next target: {}", e);
                return AddBlockResult::Rejected(format!("Failed to calculate next target: {}", e));
            }
        };

        if new_block.timestamp < current_chain_tip.timestamp {
            return AddBlockResult::Rejected(String::from(
                "Block timestamp is earlier than current chain tip",
            ));
        }

        if new_block.previous_hash == current_chain_tip_hash {
            if new_block.index != expected_next_index {
                return AddBlockResult::Rejected(format!(
                    "Direct extension block {} has incorrect index. Expected {}, got {}",
                    new_block_hash, expected_next_index, new_block.index
                ));
            }
            info!("Block {} is a direct extension.", new_block_hash);

            if let Err(e) = new_block.validate_block(&self.utxos, &expected_next_target) {
                return AddBlockResult::Rejected(format!(
                    "Direct extension block {} (index {}) failed internal validation: {}",
                    new_block_hash, new_block.index, e
                ));
            }
            info!(
                "Internal validation successful for direct extension block {}",
                new_block_hash
            );

            self.blocks.push(new_block.clone());
            if let Err(e) = self.apply_block_to_utxos(&new_block) {
                error!("Failed to apply direct extension block UTXOs: {}", e);
                return AddBlockResult::Rejected(format!("Failed to apply block UTXOs: {}", e));
            }
            self.clear_mempool_of_block_transactions(&new_block);
            if let Err(e) = self.calculate_next_target().map(|t| self.target = t) {
                error!("Failed to update target after direct extension: {}", e);
                return AddBlockResult::Rejected(format!("Failed to update target: {}", e));
            }
            info!(
                "Direct extension block {} added successfully. New height: {}, New target: {:?}",
                new_block_hash,
                self.block_height(),
                self.target
            );
            return AddBlockResult::Added;
        } else {
            warn!(
                "Fork detected or out-of-order block ({}). Local tip: {} (index {}), New block previous: {} (index {})",
                new_block_hash,
                current_chain_tip_hash, current_chain_tip.index,
                new_block.previous_hash, new_block.index.saturating_sub(1)
            );

            if let Some(common_ancestor_index) =
                self.find_common_ancestor_by_hash(&new_block.previous_hash)
            {
                info!(
                    "Found common ancestor at index {} for received block {}",
                    common_ancestor_index, new_block_hash
                );

                if new_block.index <= common_ancestor_index {
                    return AddBlockResult::ShorterForkRejected(format!(
                        "Received block {} is part of a shorter or equal length fork (index {} <= common ancestor index {}). Rejecting.",
                        new_block_hash, new_block.index, common_ancestor_index
                    ));
                }

                AddBlockResult::PotentialLongerForkDetected {
                    common_ancestor_index,
                    new_block_index: new_block.index,
                    new_block_hash,
                }
            } else {
                AddBlockResult::OrphanedOrDisconnected(format!(
                    "Received block {} does not connect to the current chain or any known ancestor. Previous hash: {}",
                    new_block_hash, new_block.previous_hash
                ))
            }
        }
    }

    pub fn add_to_mempool(&mut self, transaction: Transaction) -> Result<()> {
        if transaction.inputs.is_empty() {
            return Err(anyhow!("Coinbase transaction cannot be added to mempool"));
        }

        let tx_hash = transaction.hash_with_signatures()?;
        if self
            .mempool
            .iter()
            .any(|(_, t, _)| t.hash_with_signatures().ok() == Some(tx_hash))
        {
            debug!(
                "Transaction {} already exists in mempool. Ignoring.",
                tx_hash
            );
            return Ok(());
        }

        let mut input_sum = Amount::zero();
        let mut inputs_checked_in_tx: HashSet<Hash> = HashSet::new();

        for input in &transaction.inputs {
            let prev_output_hash = &input.prev_transaction_output_hash;

            if !inputs_checked_in_tx.insert(prev_output_hash.clone()) {
                return Err(anyhow!(
                    "Transaction has duplicate inputs: {}",
                    prev_output_hash
                ));
            }

            match self.utxos.get(prev_output_hash) {
                Some((is_in_mempool, output)) => {
                    if *is_in_mempool {
                        return Err(anyhow!(
                            "Double spend: input {} already spent by transaction in mempool",
                            prev_output_hash
                        ));
                    }

                    input_sum = (input_sum + output.value)?;
                }
                None => {
                    return Err(anyhow!(
                        "Transaction input UTXO {} not found or already spent on chain",
                        prev_output_hash
                    ));
                }
            }
        }

        let mut output_sum = Amount::zero();
        let mut outputs_checked_in_tx: HashSet<Hash> = HashSet::new();
        for output in &transaction.outputs {
            let output_hash = output.hash()?;
            if !outputs_checked_in_tx.insert(output_hash) {
                return Err(anyhow!(
                    "Transaction has duplicate outputs in tx {}: {}",
                    transaction.hash_with_signatures()?,
                    output_hash
                ));
            }
            output_sum = (output_sum + output.value)?;
        }

        if input_sum < output_sum {
            return Err(anyhow!(
                "Invalid transaction {}: inputs ({}) < outputs ({}) (insufficient funds)",
                transaction.hash_with_signatures()?,
                input_sum,
                output_sum
            ));
        }

        let transaction_hash_for_verification = transaction.hash_for_signing()?;
        for input in &transaction.inputs {
            let prev_output_hash = &input.prev_transaction_output_hash;

            let (_, prev_output) = self
                .utxos
                .get(prev_output_hash)
                .expect("UTXO must exist due to previous check");

            let is_signature_valid = match input.signature.as_ref() {
                Some(sig) => sig.verify_transaction_hash(
                    &transaction_hash_for_verification,
                    &prev_output.pubkey,
                ),
                None => false,
            };

            if !is_signature_valid {
                let sig_status = if input.signature.is_none() {
                    "missing"
                } else {
                    "invalid"
                };
                return Err(anyhow!(
                    "Transaction signature {} for input {} in transaction {}",
                    sig_status,
                    prev_output_hash,
                    transaction.hash_with_signatures()?
                ));
            }
        }

        let fee = (input_sum - output_sum)?;
        self.mempool.push((Utc::now(), transaction.clone(), fee));
        for input in &transaction.inputs {
            self.utxos
                .entry(input.prev_transaction_output_hash)
                .and_modify(|(marked, _)| {
                    *marked = true;
                });
        }

        self.mempool.sort_by(|a, b| b.2.cmp(&a.2));

        println!(
            "Transaction added to mempool. Mempool size: {}",
            self.mempool.len()
        );
        Ok(())
    }

    pub fn clear_mempool(&mut self) {
        let now = Utc::now();
        let mut utxo_hashes_to_unmark: Vec<Hash> = vec![];

        self.mempool.retain(|(timestamp, transaction, _)| {
            let is_too_old = now.signed_duration_since(*timestamp)
                > ChronoDuration::seconds(crate::MAX_MEMPOOL_TRANSACTION_AGE as i64);
            if is_too_old {
                utxo_hashes_to_unmark.extend(
                    transaction
                        .inputs
                        .iter()
                        .map(|input| input.prev_transaction_output_hash.clone()),
                );
            }
            !is_too_old
        });

        for hash in utxo_hashes_to_unmark {
            if let Some((marked, _)) = self.utxos.get_mut(&hash) {
                *marked = false;
            }
        }
    }

    pub fn clear_mempool_of_block_transactions(&mut self, block: &Block) {
        let mut block_transaction_hashes: HashSet<Hash> = HashSet::new();
        for tx in &block.transactions {
            if let Ok(hash) = tx.hash_with_signatures() {
                block_transaction_hashes.insert(hash);
            } else {
                warn!("Failed to hash transaction for mempool clearing.");
            }
        }

        let initial_mempool_size = self.mempool.len();
        self.mempool.retain(|(_timestamp, tx, _fee)| {
            tx.hash_with_signatures()
                .ok()
                .map_or(true, |hash| !block_transaction_hashes.contains(&hash))
        });

        debug!(
            "Removed {} transactions from mempool for block {}.",
            initial_mempool_size - self.mempool.len(),
            block.hash_with_signatures().unwrap_or_default()
        );
    }

    pub fn rebuild_utxos(&mut self) -> Result<()> {
        self.utxos.clear();
        for block in &self.blocks {
            for transaction in &block.transactions {
                for input in &transaction.inputs {
                    self.utxos.remove(&input.prev_transaction_output_hash);
                }
                for output in &transaction.outputs {
                    self.utxos.insert(output.hash()?, (false, output.clone()));
                }
            }
        }
        Ok(())
    }

    fn apply_block_to_utxos(&mut self, block: &Block) -> Result<()> {
        debug!(
            "Applying UTXO changes for block {}",
            block.hash_with_signatures()?
        );
        for transaction in &block.transactions {
            for input in &transaction.inputs {
                self.utxos.remove(&input.prev_transaction_output_hash);
            }
            for output in &transaction.outputs {
                self.utxos.insert(output.hash()?, (false, output.clone()));
            }
        }
        Ok(())
    }

    fn revert_block_utxos(&mut self, block: &Block) -> Result<()> {
        debug!(
            "Reverting UTXO changes for block {}",
            block.hash_with_signatures()?
        );
        for transaction in &block.transactions {
            for output in &transaction.outputs {
                self.utxos.remove(&output.hash()?);
            }
        }
        Ok(())
    }

    fn find_common_ancestor_by_hash(&self, previous_hash: &Hash) -> Option<u64> {
        for (i, block) in self.blocks.iter().enumerate().rev() {
            if block.hash_with_signatures().unwrap() == *previous_hash {
                return Some(i as u64);
            }
        }
        None
    }

    pub fn reorganize_chain(
        &mut self,
        new_chain_segment: Vec<Block>,
        common_ancestor_index: u64,
    ) -> Result<()> {
        info!(
            "Initiating chain reorganization from common ancestor index {}. New segment length: {}",
            common_ancestor_index,
            new_chain_segment.len()
        );

        let mut rolled_back_blocks: Vec<Block> = Vec::new();
        while self.block_height() > common_ancestor_index + 1 {
            if let Some(block_to_revert) = self.blocks.pop() {
                info!(
                    "Rolling back block: {} (index {})",
                    block_to_revert.hash_with_signatures().unwrap_or_default(),
                    block_to_revert.index
                );

                self.revert_block_utxos(&block_to_revert)?;

                for tx_from_reverted_block in &block_to_revert.transactions {
                    if tx_from_reverted_block.inputs.is_empty() {
                        continue;
                    }

                    match self.add_to_mempool(tx_from_reverted_block.clone()) {
                        Ok(_) => debug!(
                            "Re-added transaction {} from rolled back block {} to mempool.",
                            tx_from_reverted_block
                                .hash_with_signatures()
                                .unwrap_or_default(),
                            block_to_revert.hash_with_signatures().unwrap_or_default()
                        ),
                        Err(e) => {
                            warn!(
                                "Failed to re-add transaction {} from rolled back block {} to mempool: {}",
                                tx_from_reverted_block.hash_with_signatures().unwrap_or_default(),
                                block_to_revert.hash_with_signatures().unwrap_or_default(),
                                e
                            );
                        }
                    }
                }
                rolled_back_blocks.push(block_to_revert);
            }
        }

        info!(
            "Local chain rolled back to index {}.",
            self.blocks.len().saturating_sub(1)
        );

        self.rebuild_utxos()?;
        info!("UTXO set rebuilt to common ancestor.");

        for block in new_chain_segment {
            info!(
                "Applying new block from fork: {} (index {})",
                block.hash_with_signatures().unwrap_or_default(),
                block.index
            );

            let expected_target = self.calculate_next_target()?;
            block
                .validate_block(&self.utxos, &expected_target)
                .context(format!(
                    "Block {} (index {}) in new chain segment failed validation during reorg.",
                    block.hash_with_signatures().unwrap_or_default(),
                    block.index
                ))?;

            let current_tip_hash = self
                .blocks
                .last()
                .map(|b| b.hash_with_signatures().unwrap_or_default())
                .unwrap_or_default();
            if block.previous_hash != current_tip_hash {
                return Err(anyhow!(
                    "Block {} (index {}) in new chain segment has invalid previous hash during reorg. Expected {}, got {}",
                    block.hash_with_signatures().unwrap_or_default(), block.index, current_tip_hash, block.previous_hash
                ));
            }
            if block.index != self.block_height() {
                return Err(anyhow!(
                    "Block {} (index {}) in new chain segment has incorrect index. Expected {}, got {}",
                    block.hash_with_signatures().unwrap_or_default(), block.index, self.block_height(), block.index
                ));
            }

            self.blocks.push(block.clone());
            self.apply_block_to_utxos(&block)?;
            self.clear_mempool_of_block_transactions(&block);
            self.target = self.calculate_next_target()?;
        }

        info!(
            "Chain reorganization completed successfully. New chain height: {}",
            self.block_height()
        );
        Ok(())
    }

    //TODO: rewrite this shit
    pub async fn get_transactions_for_pubkey(
        &self,
        pubkey: &PublicKey,
    ) -> Vec<crate::transactions::Transaction> {
        let mut transaction_history = Vec::new();
        for block in &self.blocks {
            for transaction in &block.transactions {
                for output in &transaction.outputs {
                    if &output.pubkey == pubkey {
                        transaction_history.push(transaction.clone());
                        break;
                    }
                }
            }
        }
        transaction_history
    }

    pub async fn get_transaction_status(&self, tx_hash: &Hash) -> TransactionStatus {
        // Check mempool first
        for (_timestamp, tx_in_mempool, _fee) in self.mempool.iter() {
            if let Ok(mempool_tx_hash) = tx_in_mempool.hash_with_signatures() {
                if mempool_tx_hash == *tx_hash {
                    debug!("Transaction {} found in mempool.", tx_hash);
                    return TransactionStatus::Pending;
                }
            } else {
                warn!("Failed to hash transaction in mempool for status check.");
            }
        }

        // If not in mempool, check confirmed blocks
        for block in self.blocks.iter().rev() {
            // Iterate in reverse for likely faster discovery
            if let Ok(block_hash) = block.hash_with_signatures() {
                for tx_in_block in &block.transactions {
                    if let Ok(block_tx_hash) = tx_in_block.hash_with_signatures() {
                        if block_tx_hash == *tx_hash {
                            debug!(
                                "Transaction {} found in block {} at index {}.",
                                tx_hash, block_hash, block.index
                            );
                            return TransactionStatus::Confirmed {
                                block_hash,
                                block_index: block.index,
                            };
                        }
                    } else {
                        warn!(
                            "Failed to hash transaction in block {} for status check.",
                            block.index
                        );
                    }
                }
            } else {
                warn!("Failed to hash block {} for status check.", block.index);
            }
        }

        debug!(
            "Transaction {} not found in mempool or confirmed blocks.",
            tx_hash
        );
        TransactionStatus::NotFound
    }
}

impl Saveable for Blockchain {
    fn load<I: Read>(reader: I) -> IoResult<Self> {
        dbg!("Attempting to deserialize Blockchain");
        let result: Result<Self, serde_json::Error> = serde_json::from_reader(reader);
        match result {
            Ok(blockchain) => {
                dbg!("Blockchain deserialized successfully");
                let mut loaded_blockchain = blockchain;

                loaded_blockchain.rebuild_utxos().map_err(|e| {
                    IoError::new(
                        IoErrorKind::InvalidData,
                        format!("Failed to rebuild UTXOs after loading: {}", e),
                    )
                })?;
                Ok(loaded_blockchain)
            }
            Err(e) => {
                eprintln!("Error during deserialization: {}", e);
                Err(IoError::new(
                    IoErrorKind::InvalidData,
                    format!("Failed to deserialize Blockchain: {}", e),
                ))
            }
        }
    }

    fn save<O: Write>(&self, writer: O) -> IoResult<()> {
        serde_json::to_writer_pretty(writer, self).map_err(|e| {
            eprintln!("Serialization error: {}", e);
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to serialize Blockchain: {}", e),
            )
        })
    }
}
