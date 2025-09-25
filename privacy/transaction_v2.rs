//! Transaction Types v2 for QoraNet
//!
//! Defines all transaction types including privacy features

use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::fmt;

// Import common types instead of defining them here
use super::common_types::{TokenId, TokenMode};

/// Transaction types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    /// Native QOR transfer
    Transfer {
        to: Address,
        value: U256,
    },
    
    /// Deploy dual-mode token
    DeployDualToken {
        name: String,
        symbol: String,
        total_supply: U256,
        decimals: u8,
        privacy_enabled: bool,
    },
    
    /// Token transfer (public mode)
    TokenTransfer {
        token_id: TokenId,
        to: Address,
        amount: U256,
    },
    
    /// Private token transfer
    PrivateTransfer {
        token_id: TokenId,
        proof: Vec<u8>,
        nullifiers: Vec<H256>,
        commitments: Vec<H256>,
    },
    
    /// Switch token mode
    SwitchMode {
        token_id: TokenId,
        from_mode: TokenMode,
        to_mode: TokenMode,
        amount: U256,
        proof: Option<Vec<u8>>,
    },
    
    /// Smart contract deployment
    ContractDeploy {
        code: Vec<u8>,
        constructor_args: Vec<u8>,
    },
    
    /// Smart contract call
    ContractCall {
        contract: Address,
        method: H256,
        args: Vec<u8>,
        value: U256,
    },
    
    /// Stake QOR
    Stake {
        validator: Address,
        amount: U256,
    },
    
    /// Unstake QOR
    Unstake {
        validator: Address,
        amount: U256,
    },
    
    /// DEX swap
    DexSwap {
        token_in: TokenId,
        token_out: TokenId,
        amount_in: U256,
        min_amount_out: U256,
        path: Vec<TokenId>,
    },
    
    /// Add liquidity
    AddLiquidity {
        token_a: TokenId,
        token_b: TokenId,
        amount_a: U256,
        amount_b: U256,
        min_lp_tokens: U256,
    },
    
    /// Remove liquidity
    RemoveLiquidity {
        token_a: TokenId,
        token_b: TokenId,
        lp_tokens: U256,
        min_amount_a: U256,
        min_amount_b: U256,
    },
}

/// Transaction with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction hash
    pub hash: H256,
    /// Sender address
    pub from: Address,
    /// Transaction nonce
    pub nonce: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Gas price
    pub gas_price: U256,
    /// Transaction type
    pub tx_type: TransactionType,
    /// Signature
    pub signature: TransactionSignature,
}

/// Transaction signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSignature {
    pub v: u8,
    pub r: H256,
    pub s: H256,
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: H256,
    pub block_number: u64,
    pub block_hash: H256,
    pub from: Address,
    pub to: Option<Address>,
    pub gas_used: u64,
    pub status: bool,
    pub logs: Vec<Log>,
}

/// Event log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}

impl Transaction {
    /// Calculate transaction hash
    pub fn hash(&self) -> H256 {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        
        hasher.update(self.from.as_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        
        let mut gas_bytes = [0u8; 32];
        self.gas_price.to_little_endian(&mut gas_bytes);
        hasher.update(&gas_bytes);
        
        // Hash transaction type
        let tx_bytes = bincode::serialize(&self.tx_type).unwrap_or_default();
        hasher.update(&tx_bytes);
        
        H256::from_slice(&hasher.finalize())
    }
    
    /// Get transaction cost in QOR
    pub fn cost(&self) -> U256 {
        U256::from(self.gas_limit) * self.gas_price
    }
    
    /// Check if transaction is private
    pub fn is_private(&self) -> bool {
        matches!(
            self.tx_type,
            TransactionType::PrivateTransfer { .. } |
            TransactionType::SwitchMode { to_mode: TokenMode::Private, .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_token_id_generation() {
        let public = Address::random();
        let private = Address::random();
        
        let id1 = TokenId::from_addresses(public, private);
        let id2 = TokenId::from_addresses(public, private);
        
        assert_eq!(id1, id2);
    }
}