use crate::currency::Amount;

use crate::signatures::{PrivateKey, Signature};
use crate::utils::Saveable;
use crate::{sha256::Hash, signatures::PublicKey};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::hash::Hash as StdHash;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionInput {
    pub prev_transaction_output_hash: Hash,
    pub signature: Option<Signature>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, StdHash)]
pub struct TransactionOutput {
    pub value: Amount,
    pub unique_id: Uuid,
    pub pubkey: PublicKey,
}

impl TransactionOutput {
    pub fn hash(&self) -> Result<Hash, anyhow::Error> {
        Hash::hash(self)
    }
}

#[derive(Serialize)]
struct TransactionForHashing<'a> {
    inputs: Vec<TransactionInputForHashing<'a>>,
    outputs: &'a [TransactionOutput],
}

#[derive(Serialize)]
struct TransactionInputForHashing<'a> {
    prev_transaction_output_hash: &'a Hash,
}

impl Transaction {
    pub fn new(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Self {
        Transaction { inputs, outputs }
    }

    pub fn new_signed(
        prev_transaction_output_hash: Hash,
        outputs: Vec<TransactionOutput>,
        private_key: &PrivateKey,
    ) -> Result<Self, anyhow::Error> {
        // Create a temporary transaction structure to generate the hash that needs to be signed.
        // The signature itself is excluded from the data that gets signed.
        let temp_tx_for_signing = Transaction {
            inputs: vec![TransactionInput {
                prev_transaction_output_hash,
                signature: None, // Signature is explicitly None for hashing
            }],
            outputs: outputs.clone(), // Clone outputs to be used in the final transaction
        };

        // Get the hash of the transaction data that will be signed.
        let tx_hash_to_sign = temp_tx_for_signing.hash_for_signing()?;

        // Generate the signature using the private key.
        let signature = Signature::sign_transaction_hash(&tx_hash_to_sign, private_key);

        // Construct the final transaction with the input including the generated signature.
        let inputs_with_signature = vec![TransactionInput {
            prev_transaction_output_hash,
            signature: Some(signature),
        }];

        Ok(Transaction {
            inputs: inputs_with_signature,
            outputs, // Use the original outputs vector
        })
    }

    pub fn hash_for_signing(&self) -> Result<Hash, anyhow::Error> {
        let inputs_for_hashing: Vec<TransactionInputForHashing> = self
            .inputs
            .iter()
            .map(|input| TransactionInputForHashing {
                prev_transaction_output_hash: &input.prev_transaction_output_hash,
            })
            .collect();

        let tx_for_hashing = TransactionForHashing {
            inputs: inputs_for_hashing,
            outputs: &self.outputs,
        };

        Hash::hash(&tx_for_hashing)
    }

    pub fn hash_with_signatures(&self) -> Result<Hash, anyhow::Error> {
        Hash::hash(self)
    }
}

impl Saveable for Transaction {
    fn load<I: Read>(reader: I) -> IoResult<Self> {
        serde_json::from_reader(reader).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to deserialize Transaction: {}", e),
            )
        })
    }

    fn save<O: Write>(&self, writer: O) -> IoResult<()> {
        serde_json::to_writer_pretty(writer, self).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to serialize Transaction: {}", e),
            )
        })
    }
}
