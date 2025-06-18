use std::{env, process::exit};

use uuid::Uuid;
use wisp_core::{
    currency::Amount,
    signatures::PrivateKey,
    transactions::{Transaction, TransactionOutput},
    utils::Saveable,
    INITIAL_BLOCK_REWARD_SMALLEST_UNITS,
};

fn main() {
    let path = if let Some(arg) = env::args().nth(1) {
        arg
    } else {
        eprintln!("Usage: tx_gen <tx_file>");
        exit(1);
    };

    let private_key = PrivateKey::generate_keypair();
    let pubkey = private_key.public_key();

    let transaction = Transaction::new(
        vec![],
        vec![TransactionOutput {
            unique_id: Uuid::new_v4(),
            value: Amount::from_smallest_unit(INITIAL_BLOCK_REWARD_SMALLEST_UNITS),
            pubkey,
        }],
    );

    transaction
        .save_to_file(path)
        .expect("Failed to save transaction");
}
