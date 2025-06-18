use crate::{sha256::Hash, signatures::PublicKey, MAX_MESSAGE_SIZE};
use serde::{Deserialize, Serialize};
use std::io::{Error as IoError, Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    blockchain::Block,
    transactions::{Transaction, TransactionOutput},
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Transaction is currently in the mempool, waiting to be included in a block.
    Pending,
    /// Transaction has been included in a block at a specific height.
    Confirmed { block_hash: Hash, block_index: u64 },
    /// Transaction's inputs are no longer valid, or it was never valid/was dropped.
    Invalid,
    /// Transaction is not found (e.g., has expired from mempool or never existed).
    NotFound,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Message {
    FetchUTXOs(PublicKey),
    UTXOs(Vec<(Hash, TransactionOutput, bool)>),
    SubmitTransaction(Transaction),
    NewTransaction(Transaction),
    FetchTemplate(PublicKey),
    Template(Block),
    ValidateTemplate(Block),
    TemplateValidity(bool),
    SubmitTemplate(Block),
    DiscoverNodes,
    NodeList(Vec<String>),
    AskDifference(u32),
    Difference(i32),
    FetchBlock(u64),
    NewBlock(Block),
    NoNewTemplate,
    FetchTransactionHistory(PublicKey),
    TransactionHistory(Vec<Transaction>),
    FetchBlockInfo(u64),
    BlockInfo(Option<Block>),
    FetchLatestBlock,
    LatestBlock(Option<(Block, u64)>),
    Ping,
    Pong,
    BlockSubmittedConfirmation,
    BlockRejected(String),
    TransactionAcceptedConfirmation,
    TransactionRejected(Hash, String),
    FetchTransactionStatus(Hash),
    TransactionStatus {
        hash: Hash,
        status: TransactionStatus, // Uses the new TransactionStatus enum
    },
    GenerateTestTransaction(PublicKey),
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, IoError> {
        // Return IoError directly
        serde_json::to_vec(self).map_err(|e| {
            IoError::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to encode message: {}", e),
            )
        })
    }

    pub fn decode(data: &[u8]) -> Result<Self, IoError> {
        // Return IoError directly
        serde_json::from_slice(data).map_err(|e| {
            IoError::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to decode message: {}", e),
            )
        })
    }

    pub fn send(&self, stream: &mut impl Write) -> Result<(), IoError> {
        let bytes = self
            .encode()
            .map_err(|_| IoError::from(std::io::ErrorKind::InvalidData))?;
        let len = bytes.len() as u64;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(&bytes)?;
        Ok(())
    }

    pub fn receive(stream: &mut impl Read) -> Result<Self, IoError> {
        let mut len_bytes = [0u8; 8];
        stream.read_exact(&mut len_bytes)?;
        let len = u64::from_be_bytes(len_bytes) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(IoError::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Received message too large: {} bytes, max is {} bytes",
                    len, MAX_MESSAGE_SIZE
                ),
            ));
        }

        let mut data = vec![0u8; len];
        stream.read_exact(&mut data)?;

        Self::decode(&data).map_err(|_| IoError::from(std::io::ErrorKind::InvalidData))
    }

    pub async fn send_async(&self, stream: &mut (impl AsyncWrite + Unpin)) -> Result<(), IoError> {
        let bytes = self
            .encode()
            .map_err(|_| IoError::from(std::io::ErrorKind::InvalidData))?;
        let len = bytes.len() as u64;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn receive_async(stream: &mut (impl AsyncRead + Unpin)) -> Result<Self, IoError> {
        let mut len_bytes = [0u8; 8];
        stream.read_exact(&mut len_bytes).await?;
        let len = u64::from_be_bytes(len_bytes) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(IoError::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Received message too large: {} bytes, max is {} bytes",
                    len, MAX_MESSAGE_SIZE
                ),
            ));
        }

        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;

        Self::decode(&data).map_err(|_| IoError::from(std::io::ErrorKind::InvalidData))
    }
}
