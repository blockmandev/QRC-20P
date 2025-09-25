//! Privacy module

pub mod amount_splitter;
pub mod universal_switch;
pub mod ffi;
pub mod ffi_universal_switch;
pub mod poseidon;
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
pub mod blockchain {
    pub mod state_connector;
}

// Re-export commonly used types
pub use privacy::{PrivacyPool, PrivacyStateManager, CommitmentGenerator, Proof};
pub use transaction_v2::{TokenId, TokenMode};