use anyhow::anyhow;
use anyhow::Context;
use ecdsa::{
    signature::{Signer, Verifier},
    Signature as ECDSASignature, SigningKey, VerifyingKey,
};
use k256::Secp256k1;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};
use std::{
    hash::{Hash as StdHash, Hasher},
    str::FromStr,
};

use crate::sha256::Hash;
use crate::utils::Saveable;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signature(pub ECDSASignature<Secp256k1>);

impl Signature {
    pub fn sign_transaction_hash(transaction_hash: &Hash, private_key: &PrivateKey) -> Self {
        let signing_key = &private_key.0;
        let signature = signing_key.sign(&transaction_hash.as_bytes()[..]);
        Signature(signature)
    }

    pub fn verify_transaction_hash(&self, transaction_hash: &Hash, public_key: &PublicKey) -> bool {
        public_key
            .0
            .verify(&transaction_hash.as_bytes()[..], &self.0)
            .is_ok()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey(pub VerifyingKey<Secp256k1>);

impl PublicKey {
    pub fn fingerprint(&self) -> String {
        let encoded_point = self.0.to_encoded_point(true);
        hex::encode(encoded_point.as_bytes())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrivateKey(#[serde(with = "signkey_serde")] pub SigningKey<Secp256k1>);

impl PrivateKey {
    pub fn generate_keypair() -> Self {
        PrivateKey(SigningKey::random(&mut OsRng))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().clone())
    }
}

impl FromStr for PrivateKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).context("Failed to hex-decode private key string")?;
        SigningKey::from_slice(&bytes)
            .map(PrivateKey)
            .map_err(|e| anyhow!("Failed to create SigningKey from bytes: {}", e))
    }
}

impl Saveable for PrivateKey {
    fn load<I: Read>(reader: I) -> IoResult<Self> {
        serde_json::from_reader(reader).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to deserialize PrivateKey: {}", e),
            )
        })
    }

    fn save<O: Write>(&self, writer: O) -> IoResult<()> {
        serde_json::to_writer(writer, self).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to serialize PrivateKey: {}", e),
            )
        })
    }
}

impl Saveable for PublicKey {
    fn load<I: Read>(reader: I) -> IoResult<Self> {
        serde_json::from_reader(reader).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to deserialize PublicKey: {}", e),
            )
        })
    }

    fn save<O: Write>(&self, writer: O) -> IoResult<()> {
        serde_json::to_writer(writer, self).map_err(|e| {
            IoError::new(
                IoErrorKind::InvalidData,
                format!("Failed to serialize PublicKey: {}", e),
            )
        })
    }
}

impl StdHash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let encoded_point = self.0.to_encoded_point(true);
        state.write(encoded_point.as_bytes());
    }
}

mod signkey_serde {
    use serde::Deserialize;
    pub fn serialize<S>(
        key: &super::SigningKey<super::Secp256k1>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&key.to_bytes())
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<super::SigningKey<super::Secp256k1>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        super::SigningKey::from_slice(&bytes).map_err(|e| {
            serde::de::Error::custom(format!("Failed to create SigningKey from bytes: {}", e))
        })
    }
}
