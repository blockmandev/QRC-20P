//! QoraNet Privacy Module - Production Ready for L1 Blockchain

pub mod privacy;

// Re-export main types for external use
pub use privacy::{
    // Core privacy components
    amount_splitter::{AmountSplitter, AmountMixer},
    universal_switch::{UniversalSwitch, SwitchConfig},

    // FFI interfaces for Go integration
    ffi::*,
    ffi_universal_switch::*,

    // Privacy primitives
    privacy::{PrivacyPool, PrivacyStateManager},
    transaction_v2::{TokenId, TokenMode},

    // ZK components
    zk_proofs::*,
    poseidon::*,

    // Network and state
    network_privacy::*,
    state::*,
};