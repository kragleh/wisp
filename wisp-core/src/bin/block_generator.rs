use std::{env, process::exit};

use chrono::Utc;
use uuid::Uuid;
use wisp_core::{
    blockchain::Block,
    currency::Amount,
    sha256::Hash,
    signatures::PrivateKey,
    transactions::{Transaction, TransactionOutput},
    utils::{MerkleRoot, Saveable},
    INITIAL_BLOCK_REWARD_SMALLEST_UNITS,
};

fn main() {
    let path = if let Some(arg) = env::args().nth(1) {
        arg
    } else {
        eprintln!("Usage: block_gen <block_file>");
        exit(1);
    };

    let private_key = PrivateKey::generate_keypair();
    let pubkey = private_key.public_key();

    let transactions = vec![Transaction::new(
        vec![],
        vec![TransactionOutput {
            unique_id: Uuid::new_v4(),
            value: Amount::from_smallest_unit(INITIAL_BLOCK_REWARD_SMALLEST_UNITS),
            pubkey,
        }],
    )];

    let merkle_root =
        MerkleRoot::calculate(&transactions).expect("Failed to calculate Merkle root for block");

    let block = Block::new(
        Utc::now(),
        0,
        Hash::zero(),
        merkle_root,
        wisp_core::MAX_TARGET,
        0,
        transactions,
    );

    block.save_to_file(path).expect("Failed to save block");
}
