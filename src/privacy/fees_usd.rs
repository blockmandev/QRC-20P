//! USD Fee System for QoraNet
//!
//! Implements USD-pegged fee calculation using TWAP oracle

use anyhow::{Result, anyhow};
use ethereum_types::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;

/// USD fee system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    pub target_fee_usd: f64,  // $0.01 target
    pub min_fee_qor: U256,
    pub max_fee_qor: U256,
    pub burn_percentage: u8,  // 50%
    pub oracle_address: Address,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            target_fee_usd: 0.01,
            min_fee_qor: U256::from(1_000_000_000_000_000u64), // 0.001 QOR
            max_fee_qor: U256::from(100_000_000_000_000_000u64), // 0.1 QOR
            burn_percentage: 50,
            oracle_address: Address::zero(),
        }
    }
}

/// Transaction fee types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionFeeType {
    Transfer,
    TokenDeploy,
    TokenTransfer,
    PrivateTransfer,
    ModeSwitch,
    ContractDeploy,
    ContractCall,
    Stake,
    Unstake,
    DexSwap,
    AddLiquidity,
    RemoveLiquidity,
}

impl TransactionFeeType {
    /// Get multiplier for fee type
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::Transfer => 1.0,
            Self::TokenTransfer => 1.0,
            Self::PrivateTransfer => 2.0,  // Higher fee for privacy
            Self::ModeSwitch => 1.5,
            Self::TokenDeploy => 100.0,
            Self::ContractDeploy => 50.0,
            Self::ContractCall => 1.2,
            Self::Stake | Self::Unstake => 1.0,
            Self::DexSwap => 1.5,
            Self::AddLiquidity | Self::RemoveLiquidity => 2.0,
        }
    }
}

/// USD fee calculation system
pub struct USDFeeSystem {
    config: FeeConfig,
    qor_price_usd: Arc<RwLock<f64>>,
    price_history: Arc<RwLock<Vec<(u64, f64)>>>,
}

impl USDFeeSystem {
    /// Create new fee system
    pub fn new(config: FeeConfig) -> Self {
        Self {
            config,
            qor_price_usd: Arc::new(RwLock::new(1.0)),
            price_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Update QOR price from oracle with validation
    pub fn update_price(&self, price_usd: f64, timestamp: u64) -> Result<()> {
        // Validate price is reasonable (between $0.0001 and $10000)
        if price_usd <= 0.0001 || price_usd >= 10000.0 {
            return Err(anyhow!("Invalid price: must be between $0.0001 and $10000"));
        }

        // Check for price manipulation (>50% change)
        let current_price = *self.qor_price_usd.read();
        if current_price > 0.0 {
            let price_change_ratio = (price_usd - current_price).abs() / current_price;
            if price_change_ratio > 0.5 {
                // Log suspicious price change but allow it with delay
                // In production, implement circuit breaker here
                eprintln!("WARNING: Large price change detected: {}%", price_change_ratio * 100.0);
            }
        }

        // Validate timestamp is not too old or in future
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if timestamp > current_time + 60 { // Allow 1 minute clock skew
            return Err(anyhow!("Invalid timestamp: cannot be in the future"));
        }

        if timestamp < current_time - 3600 { // Reject prices older than 1 hour
            return Err(anyhow!("Invalid timestamp: price data too old"));
        }

        // Update price with validation passed
        *self.qor_price_usd.write() = price_usd;

        let mut history = self.price_history.write();
        history.push((timestamp, price_usd));

        // Keep only last 100 price points
        if history.len() > 100 {
            let drain_count = history.len() - 100;
            history.drain(0..drain_count);
        }

        Ok(())
    }

    /// Calculate fee in QOR for transaction type
    pub fn calculate_fee(&self, tx_type: TransactionFeeType) -> U256 {
        let qor_price = *self.qor_price_usd.read();
        let target_usd = self.config.target_fee_usd * tx_type.multiplier();

        // Calculate QOR amount for target USD
        let qor_amount = target_usd / qor_price;
        let wei_amount = (qor_amount * 1e18) as u128;
        let fee = U256::from(wei_amount);

        // Apply min/max bounds
        if fee < self.config.min_fee_qor {
            self.config.min_fee_qor
        } else if fee > self.config.max_fee_qor {
            self.config.max_fee_qor
        } else {
            fee
        }
    }

    /// Get amount to burn from fee
    pub fn get_burn_amount(&self, fee: U256) -> U256 {
        fee * self.config.burn_percentage / 100
    }

    /// Get current QOR price
    pub fn get_qor_price(&self) -> f64 {
        *self.qor_price_usd.read()
    }

    /// Convert USD amount to QOR
    pub fn usd_to_qor(&self, usd_amount: f64) -> U256 {
        let qor_price = *self.qor_price_usd.read();
        let qor_amount = usd_amount / qor_price;
        let wei_amount = (qor_amount * 1e18) as u128;
        U256::from(wei_amount)
    }

    /// Calculate TWAP (Time-Weighted Average Price)
    pub fn calculate_twap(&self, window_seconds: u64) -> f64 {
        let history = self.price_history.read();
        if history.is_empty() {
            return *self.qor_price_usd.read();
        }

        let now = chrono::Utc::now().timestamp() as u64;
        let start_time = now.saturating_sub(window_seconds);

        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for window in history.windows(2) {
            let (t1, p1) = window[0];
            let (t2, _p2) = window[1];

            if t1 >= start_time {
                let duration = (t2 - t1) as f64;
                weighted_sum += p1 * duration;
                total_weight += duration;
            }
        }

        // Add current price for remaining time
        if let Some((last_t, _)) = history.last() {
            let current_price = *self.qor_price_usd.read();
            let duration = (now - last_t) as f64;
            weighted_sum += current_price * duration;
            total_weight += duration;
        }

        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            *self.qor_price_usd.read()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_calculation() {
        let fee_system = USDFeeSystem::new(FeeConfig::default());
        fee_system.update_price(0.10, 1000); // $0.10 per QOR

        let fee = fee_system.calculate_fee(TransactionFeeType::Transfer);
        // $0.01 / $0.10 = 0.1 QOR = 100000000000000000 wei
        // Allow small rounding difference
        let expected = U256::from(100_000_000_000_000_000u128);
        let diff = if fee > expected { fee - expected } else { expected - fee };
        assert!(diff < U256::from(1000), "Fee calculation off by too much");
    }
}