use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Amount(u64);

impl Amount {
    pub const MAX: Amount = Amount(u64::MAX);
    pub const DECIMAL_PLACES: u32 = 8;
    pub const CONVERSION_FACTOR: u64 = 10u64.pow(Self::DECIMAL_PLACES);

    pub fn from_smallest_unit(units: u64) -> Self {
        Amount(units)
    }

    pub fn from_wisp(wisp: u64) -> Result<Self> {
        wisp.checked_mul(Self::CONVERSION_FACTOR)
            .map(Amount)
            .ok_or_else(|| anyhow!("Overflow when converting WISP to smallest units: {}", wisp))
    }

    pub fn as_smallest_unit(&self) -> u64 {
        self.0
    }

    pub fn zero() -> Self {
        Amount(0)
    }

    pub fn saturating_add(self, other: Self) -> Self {
        Amount(self.0.saturating_add(other.0))
    }

    pub fn saturating_sub(self, other: Self) -> Self {
        Amount(self.0.saturating_sub(other.0))
    }

    pub fn to_string_wisp(&self) -> String {
        if self.0 == 0 {
            return "0.".to_string();
        }

        let integer_part = self.0 / Self::CONVERSION_FACTOR;
        let fractional_part = self.0 % Self::CONVERSION_FACTOR;

        if fractional_part == 0 {
            format!("{}.", integer_part)
        } else {
            let fractional_str = format!(
                "{:0width$}",
                fractional_part,
                width = Self::DECIMAL_PLACES as usize
            );

            let trimmed_fractional_str = fractional_str.trim_end_matches('0');
            format!("{}.{}", integer_part, trimmed_fractional_str)
        }
    }

    pub fn from_string_wisp(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() > 2 {
            return Err(anyhow!(
                "Invalid decimal format: multiple decimal points in '{}'",
                s
            ));
        }

        let integer_str = parts[0];
        let fractional_str = parts.get(1).unwrap_or(&"");

        if fractional_str.len() > Self::DECIMAL_PLACES as usize {
            return Err(anyhow!(
                "Too many decimal places in '{}'. Max {} allowed.",
                s,
                Self::DECIMAL_PLACES
            ));
        }

        let parsed_integer = if integer_str.is_empty() {
            0
        } else {
            integer_str
                .parse::<u64>()
                .map_err(|e| anyhow!("Invalid integer part in '{}': {}", s, e))?
        };

        let mut total_units = parsed_integer
            .checked_mul(Self::CONVERSION_FACTOR)
            .ok_or_else(|| anyhow!("Integer part overflow when converting '{}'", s))?;

        if !fractional_str.is_empty() {
            let mut fractional_val_str = String::from(*fractional_str);

            let padding_needed = Self::DECIMAL_PLACES as usize - fractional_str.len();
            for _ in 0..padding_needed {
                fractional_val_str.push('0');
            }
            let parsed_fractional = fractional_val_str
                .parse::<u64>()
                .map_err(|e| anyhow!("Invalid fractional part in '{}': {}", s, e))?;

            total_units = total_units.checked_add(parsed_fractional).ok_or_else(|| {
                anyhow!("Fractional part addition overflow when converting '{}'", s)
            })?;
        }

        Ok(Amount(total_units))
    }
}

impl Add for Amount {
    type Output = Result<Self>;
    fn add(self, other: Self) -> Self::Output {
        self.0.checked_add(other.0).map(Amount).ok_or_else(|| {
            anyhow!(
                "Amount overflow: {} + {}",
                self.to_string_wisp(),
                other.to_string_wisp()
            )
        })
    }
}

impl AddAssign for Amount {
    fn add_assign(&mut self, other: Self) {
        *self = (*self + other).expect("Amount overflow during AddAssign");
    }
}

impl Sub for Amount {
    type Output = Result<Self>;
    fn sub(self, other: Self) -> Self::Output {
        self.0.checked_sub(other.0).map(Amount).ok_or_else(|| {
            anyhow!(
                "Amount underflow: {} - {}",
                self.to_string_wisp(),
                other.to_string_wisp()
            )
        })
    }
}

impl SubAssign for Amount {
    fn sub_assign(&mut self, other: Self) {
        *self = (*self - other).expect("Amount underflow during SubAssign");
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string_wisp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_creation_and_conversion() {
        let one_wisp = Amount::from_wisp(1).unwrap();
        assert_eq!(one_wisp.as_smallest_unit(), 100_000_000);
        assert_eq!(one_wisp.to_string_wisp(), "1.");

        let half_wisp = Amount::from_smallest_unit(50_000_000);
        assert_eq!(half_wisp.to_string_wisp(), "0.5");

        let tiny_amount = Amount::from_smallest_unit(1);
        assert_eq!(tiny_amount.to_string_wisp(), "0.00000001");

        let zero_amount = Amount::from_smallest_unit(0);
        assert_eq!(zero_amount.to_string_wisp(), "0.");

        let full_precision_amount = Amount::from_smallest_unit(123_456_789_012_345_678);
        assert_eq!(
            full_precision_amount.to_string_wisp(),
            "1234567890.12345678"
        );

        let max_u64_amount = Amount::from_smallest_unit(u64::MAX);
        assert!(max_u64_amount
            .to_string_wisp()
            .contains("184467440737.09551615"));
    }

    #[test]
    fn test_amount_from_wisp_overflow() {
        let large_wisp = u64::MAX / Amount::CONVERSION_FACTOR + 1;
        assert!(Amount::from_wisp(large_wisp).is_err());
    }

    #[test]
    fn test_amount_from_string_wisp_valid() {
        assert_eq!(
            Amount::from_string_wisp("1.2345")
                .unwrap()
                .as_smallest_unit(),
            123_450_000
        );
        assert_eq!(
            Amount::from_string_wisp("1.00000001")
                .unwrap()
                .as_smallest_unit(),
            100_000_001
        );
        assert_eq!(
            Amount::from_string_wisp("123").unwrap().as_smallest_unit(),
            12_300_000_000
        );
        assert_eq!(
            Amount::from_string_wisp("0.1").unwrap().as_smallest_unit(),
            10_000_000
        );
        assert_eq!(
            Amount::from_string_wisp("0.").unwrap().as_smallest_unit(),
            0
        );
        assert_eq!(
            Amount::from_string_wisp("0.00000000")
                .unwrap()
                .as_smallest_unit(),
            0
        );
        assert_eq!(
            Amount::from_string_wisp("1.").unwrap().as_smallest_unit(),
            100_000_000
        );
        assert_eq!(
            Amount::from_string_wisp(".1").unwrap().as_smallest_unit(),
            10_000_000
        );
    }

    #[test]
    fn test_amount_from_string_wisp_invalid() {
        assert!(Amount::from_string_wisp("1.234567890").is_err());
        assert!(Amount::from_string_wisp("abc").is_err());
        assert!(Amount::from_string_wisp("1.2.3").is_err());
        assert!(Amount::from_string_wisp("").is_err());
        assert!(Amount::from_string_wisp(".").is_err());
        assert!(
            Amount::from_string_wisp("99999999999999999999999999999999999999999999.0").is_err()
        );
    }

    #[test]
    fn test_amount_arithmetic_valid() {
        let a = Amount::from_string_wisp("1.0").unwrap();
        let b = Amount::from_string_wisp("0.5").unwrap();
        let c = Amount::from_string_wisp("0.00000001").unwrap();

        assert_eq!((a + b).unwrap().to_string_wisp(), "1.5");
        assert_eq!((a - b).unwrap().to_string_wisp(), "0.5");
        assert_eq!((b + c).unwrap().to_string_wisp(), "0.50000001");
        assert_eq!((Amount::zero() + a).unwrap().to_string_wisp(), "1.");
        assert_eq!((a - Amount::zero()).unwrap().to_string_wisp(), "1.");
    }

    #[test]
    fn test_amount_add_overflow() {
        let max_u64 = Amount::from_smallest_unit(u64::MAX);
        let one_unit = Amount::from_smallest_unit(1);
        assert!((max_u64 + one_unit).is_err());
    }

    #[test]
    fn test_amount_sub_underflow() {
        let zero_amount = Amount::from_smallest_unit(0);
        let one_unit = Amount::from_smallest_unit(1);
        assert!((zero_amount - one_unit).is_err());
    }

    #[test]
    fn test_add_assign_overflow() {
        let mut x = Amount::from_smallest_unit(u64::MAX);
        let y = Amount::from_smallest_unit(1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            x += y;
        }));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .downcast_ref::<&str>()
            .unwrap()
            .contains("Amount overflow during AddAssign"));
    }

    #[test]
    fn test_sub_assign_underflow() {
        let mut x = Amount::from_smallest_unit(0);
        let y = Amount::from_smallest_unit(1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            x -= y;
        }));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .downcast_ref::<&str>()
            .unwrap()
            .contains("Amount underflow during SubAssign"));
    }
}
