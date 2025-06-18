pub mod blockchain;
pub mod currency;
pub mod network;
pub mod sha256;
pub mod signatures;
pub mod transactions;
pub mod utils;

use serde::{Deserialize, Serialize};
use uint::construct_uint;

construct_uint! {
   #[derive(Serialize, Deserialize)]
   pub struct U256(4);
}

pub const INITIAL_BLOCK_REWARD_SMALLEST_UNITS: u64 =
    100 * 10u64.pow(currency::Amount::DECIMAL_PLACES);

pub const HALVING_INTERVAL: u64 = 100_000; // 100,000 blocks
pub const IDEAL_BLOCK_TIME: u64 = 120; // 2 minutes in seconds
pub const SIMPLE_DAA_WINDOW: usize = 30; // Use the last 30 blocks for adjustment

// The exact value for Bitcoin's initial target (0x1d00ffff compact) is represented here.
pub const MAX_TARGET: U256 = U256([
    0xFFFF_FFFF_FFFF_FFFF, // word0
    0xFFFF_FFFF_FFFF_FFFF, // word1
    0xFFFF_FFFF_FFFF_FFFF, // word2
    0x0000_0FFF_FFFF_FFFF, // word3 (starts with 0000) - High target, easy difficulty
]);

// Minimum allowed target (hardest difficulty cap). A very low target, representing extremely high difficulty.
pub const MIN_TARGET: U256 = U256([1, 0, 0, 0]);

pub const MAX_MEMPOOL_TRANSACTION_AGE: u64 = 172800; // Two days in seconds
pub const MAX_BLOCK_TRANSACTIONS: usize = 1000;
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB
pub const MAX_BLOCK_FUTURE_TIMESTAMP: u64 = 600; // 10 minutes in seconds
