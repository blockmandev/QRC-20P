//! Privacy module

pub mod common_types;
pub mod amount_splitter;
pub mod universal_switch;
pub mod ffi;
pub mod ffi_universal_switch;
pub mod poseidon;
pub mod bn256_poseidon;
pub mod zk_proofs;
pub mod secure_privacy;
pub mod fees_usd;
pub mod merkle_tree;
pub mod network_privacy;
pub mod privacy;
// pub mod ring_signatures;  // REMOVED: Using ZK-only, no ring signatures
pub mod state;
pub mod state_transitions;
pub mod transaction_v2;
pub mod token_factory;
pub mod validator_bridge;
pub mod halo2_circuits;
pub mod halo2_real_proofs;
pub mod halo2_range_check;
pub mod private_contracts;
pub mod complete_privacy;
pub mod blockchain {
    pub mod state_connector;
}

// Re-export commonly used types from common_types
pub use common_types::{TokenId, TokenMode, Proof};
pub use privacy::{PrivacyPool, PrivacyStateManager, CommitmentGenerator};