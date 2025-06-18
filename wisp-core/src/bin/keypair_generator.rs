use std::{env, fs::File};

use wisp_core::{signatures::PrivateKey, utils::Saveable};

fn main() {
    let name = env::args().nth(1).expect("Please provide a name");

    let private_key = PrivateKey::generate_keypair();
    let public_key = private_key.public_key();

    let public_key_file = name.clone() + ".pub.json";
    let private_key_file = name + ".priv.json";

    let private_key_file =
        File::create(&private_key_file).expect("Failed to create private key file");
    private_key
        .save(private_key_file)
        .expect("Failed to save private key");

    let public_key_file = File::create(&public_key_file).expect("Failed to create public key file");
    public_key
        .save(public_key_file)
        .expect("Failed to save public key");
}
