// wisp-wallet/src/wallet/storage.rs
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key as AesKey, Nonce,
};
use anyhow::Result;
use argon2::{password_hash::Salt, Algorithm, Argon2, ParamsBuilder, PasswordHasher, Version};
use base64::{engine::general_purpose, Engine as Base64Engine};
use hex;
use log::info;
use password_hash::Result as PwHashResult;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::wallet::constants::*;
use wisp_core::signatures::PublicKey;

/// Represents a saved wallet structure.
#[derive(Serialize, Deserialize, Clone)]
pub struct SavedWallet {
    pub name: String,
    pub encrypted_private_key: String,
    pub public_key: PublicKey,
    pub salt: Vec<u8>,
    // pub encrypted_seed_phrase: String, // Kept commented as per your original
}

impl SavedWallet {
    pub fn wallet_file_path(name: &str) -> PathBuf {
        let mut path = PathBuf::from(WALLET_DIR);
        path.push(format!("{}.{}", name, WALLET_FILE_EXTENSION));
        path
    }

    /// Save the wallet to a password-encrypted file.
    pub fn save_to_file(&self, password: &str) -> Result<()> {
        let path = Self::wallet_file_path(&self.name);
        log::info!("Saving wallet '{}' to path: {:?}", self.name, path);
        fs::create_dir_all(WALLET_DIR)?;

        let serialized_result = serde_json::to_vec(self);
        match serialized_result {
            Ok(serialized_wallet) => {
                log::debug!(
                    "Wallet serialized to JSON successfully (length: {}).",
                    serialized_wallet.len()
                );

                let mut rng = OsRng;
                let mut nonce = [0u8; ENCRYPTION_NONCE_SIZE];
                if let Err(e) = rng.try_fill_bytes(&mut nonce) {
                    log::error!("Failed to fill bytes for nonce: {:?}", e);
                    return Err(anyhow::anyhow!("Failed to generate nonce"));
                }
                let nonce = Nonce::from_slice(&nonce);
                log::debug!("Generated nonce (hex): {}", hex::encode(&nonce));

                let key_result = Self::derive_key(password, &self.salt);
                match key_result {
                    Ok(key) => {
                        log::debug!("Derived key successfully (length: {}).", key.len());
                        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key));

                        let encrypted_result = cipher.encrypt(nonce, serialized_wallet.as_slice());
                        match encrypted_result {
                            Ok(ciphertext) => {
                                log::debug!(
                                    "Wallet data encrypted successfully (length: {}).",
                                    ciphertext.len()
                                );

                                let mut file = File::create(&path)?;
                                if let Err(e) = file.write_all(&nonce) {
                                    log::error!("Error writing nonce to file: {:?}", e);
                                    return Err(anyhow::anyhow!("Failed to write nonce"));
                                }
                                if let Err(e) = file.write_all(&self.salt) {
                                    log::error!("Error writing salt to file: {:?}", e);
                                    return Err(anyhow::anyhow!("Failed to write salt"));
                                }
                                if let Err(e) = file.write_all(&ciphertext) {
                                    log::error!("Error writing ciphertext to file: {:?}", e);
                                    return Err(anyhow::anyhow!("Failed to write ciphertext"));
                                }
                                log::info!("Wallet '{}' saved to file successfully.", self.name);
                                Ok(())
                            }
                            Err(e) => {
                                log::error!("Encryption failed: {:?}", e);
                                Err(anyhow::anyhow!("Encryption failed"))
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Key derivation failed: {:?}", e);
                        Err(e)
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to serialize wallet to JSON: {:?}", e);
                Err(anyhow::anyhow!("Serialization failed"))
            }
        }
    }

    /// Load and decrypt the wallet from a file.
    pub fn load_from_file(name: &str, password: &str) -> Result<Self> {
        let path = Self::wallet_file_path(name);
        log::info!("Attempting to load wallet '{}' from path: {:?}", name, path);
        let mut file = File::open(&path)?;

        let mut nonce_bytes = [0u8; ENCRYPTION_NONCE_SIZE];
        file.read_exact(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        log::debug!("Loaded nonce (hex): {}", hex::encode(&nonce_bytes));

        let mut salt_bytes = vec![0u8; SALT_SIZE];
        file.read_exact(&mut salt_bytes)?;
        log::debug!("Loaded salt (hex): {}", hex::encode(&salt_bytes));

        let key = Self::derive_key(password, &salt_bytes)?; // This is the call
        log::debug!(
            "Derived key for decryption (hex prefix): {}",
            hex::encode(&key[..8])
        );
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key));

        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;
        log::debug!("Read ciphertext length: {}", ciphertext.len());

        let decrypted_wallet = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?; // <-- This is the one
        log::info!("Wallet '{}' decrypted successfully.", name);

        let wallet: SavedWallet = serde_json::from_slice(&decrypted_wallet)?;
        Ok(wallet)
    }

    // Helper function to derive key using Argon2
    pub fn derive_key(password: &str, salt_bytes: &[u8]) -> Result<Vec<u8>> {
        let params = ParamsBuilder::new()
            .t_cost(3)
            .m_cost(16) // <--- CORRECTED: Changed 4096 to 16 (for 64 MiB memory)
            .p_cost(1)
            .build()
            .map_err(|_| anyhow::anyhow!("Failed to build Argon2 parameters"))?;

        info!(
            "Derive Key - Raw Salt Bytes (Hex): {}",
            hex::encode(salt_bytes)
        );
        let salt_str = general_purpose::STANDARD_NO_PAD.encode(salt_bytes);
        info!("Derive Key - Base64 Encoded Salt: '{}'", salt_str);
        let salt: PwHashResult<Salt> = Salt::from_b64(&salt_str);
        let salt = salt.map_err(|e| anyhow::anyhow!("Failed to create Salt from Base64: {}", e))?;

        let argon2 = Argon2::new(Algorithm::default(), Version::V0x13, params);

        let password_hash = argon2
            .hash_password(password.as_bytes(), salt)
            .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;

        Ok(password_hash
            .hash
            .ok_or_else(|| anyhow::anyhow!("Password hash did not contain a hash"))?
            .as_bytes()
            .to_vec())
    }
}
