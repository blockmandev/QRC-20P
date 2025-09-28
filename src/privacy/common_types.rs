//! Common privacy types shared across modules
//! This module provides unified type definitions to avoid conflicts

use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::fmt;
use sha3::{Digest, Keccak256};

// CRITICAL: Use the Fr type from halo2_axiom to avoid type mismatches
// All modules should import Fr from here, not directly from halo2curves
pub use halo2_axiom::halo2curves::bn256::Fr;
pub use halo2_axiom::halo2curves::bn256::{Bn256, G1Affine};

/// Token identifier (hash of public and private addresses)
/// Used across all privacy modules for consistent token identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub H256);

impl TokenId {
    /// Create token ID from addresses
    pub fn from_addresses(public: Address, private: Address) -> Self {
        let mut hasher = Keccak256::default();
        hasher.update(public.as_bytes());
        hasher.update(private.as_bytes());
        TokenId(H256::from_slice(&hasher.finalize()))
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({})", hex::encode(&self.0[..8]))
    }
}

/// ZK Proof structure for privacy operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<H256>,
}

/// Token operating mode
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TokenMode {
    Public = 0,
    Private = 1,
}

impl TokenMode {
    pub fn is_private(&self) -> bool {
        matches!(self, TokenMode::Private)
    }

    pub fn is_public(&self) -> bool {
        matches!(self, TokenMode::Public)
    }
}