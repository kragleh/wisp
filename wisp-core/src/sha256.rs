use crate::U256;
use anyhow::{Context, Result};
use hex;
use sha2::{Digest, Sha256};
use std::{convert::TryFrom, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Hash(crate::U256);

impl serde::Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.to_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> serde::Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Hash::try_from(s.as_str()).map_err(|e| {
            serde::de::Error::custom(format!("Failed to deserialize Hash from hex string: {}", e))
        })
    }
}

impl Hash {
    pub fn hash<T: serde::Serialize>(data: &T) -> Result<Self, anyhow::Error> {
        let serialized = bincode::serialize(data)
            .context("Failed to serialize data for hashing with bincode")?;
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let digest = hasher.finalize();
        let hash_bytes: [u8; 32] = digest.into();
        let hash_u256 = U256::from_big_endian(&hash_bytes);
        Ok(Hash(hash_u256))
    }

    pub fn matches_target(&self, target: U256) -> bool {
        self.0 <= target
    }

    pub fn zero() -> Self {
        Hash(U256::zero())
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_big_endian()
    }
}

impl From<Hash> for String {
    fn from(hash: Hash) -> Self {
        hex::encode(hash.as_bytes())
    }
}

impl TryFrom<&str> for Hash {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;

        if bytes.len() != 32 {
            return Err(format!(
                "Invalid hex string length: expected 64 chars (32 bytes), found {} bytes",
                bytes.len()
            ));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);

        let u256 = U256::from_big_endian(&array);
        Ok(Hash(u256))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}
