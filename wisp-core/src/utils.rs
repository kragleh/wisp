use std::fs::File;
use std::io::{Read, Result as IoResult, Write};
use std::path::Path;

use crate::currency::Amount;
use crate::{sha256::Hash, transactions::Transaction};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleRoot(Hash);
impl MerkleRoot {
    pub fn calculate(transactions: &[Transaction]) -> Result<MerkleRoot, anyhow::Error> {
        let mut layer: Vec<Hash> = vec![];

        for transaction in transactions {
            layer.push(Hash::hash(transaction)?);
        }

        if layer.is_empty() {
            return Ok(MerkleRoot(Hash::zero()));
        }

        while layer.len() > 1 {
            let mut new_layer = vec![];
            for pair in layer.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).unwrap_or(&pair[0]);

                new_layer.push(Hash::hash(&[left, *right])?);
            }
            layer = new_layer;
        }

        Ok(MerkleRoot(layer[0]))
    }
}

pub fn calculate_block_reward(block_height: u64) -> Amount {
    let halvings = block_height / crate::HALVING_INTERVAL;

    if halvings >= 64 {
        Amount::zero()
    } else {
        let reward_in_smallest_units = (crate::INITIAL_BLOCK_REWARD_SMALLEST_UNITS)
            .checked_shr(halvings as u32)
            .unwrap_or(0);

        Amount::from_smallest_unit(reward_in_smallest_units)
    }
}

pub trait Saveable
where
    Self: Sized,
{
    fn load<I: Read>(reader: I) -> IoResult<Self>;
    fn save<O: Write>(&self, writer: O) -> IoResult<()>;
    fn save_to_file<P: AsRef<Path>>(&self, path: P) -> IoResult<()> {
        let file = File::create(&path)?;
        self.save(file)
    }

    fn load_from_file<P: AsRef<Path>>(path: P) -> IoResult<Self> {
        let file = File::open(&path)?;
        Self::load(file)
    }
}
