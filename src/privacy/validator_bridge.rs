//! Validator Bridge for FFI Integration with Go
//!
//! Provides FFI functions to receive validator commitments from Go code

use anyhow::{Result, anyhow};
use ethereum_types::{Address, H256};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::slice;
use std::sync::Arc;
use parking_lot::RwLock;

// use crate::ring_signatures::{RingCommitment, CommitmentSource};  // REMOVED: Using ZK-only
use crate::universal_switch::UniversalSwitch;

// Replacement for RingCommitment - now using ZK commitments
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZKCommitment {
    pub commitment: H256,
    pub nullifier: Option<H256>,
    pub block_height: u64,
    pub timestamp: u64,
    pub source: CommitmentSource,
}

// Source tracking for ZK commitments
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum CommitmentSource {
    Validator { address: Address, index: u8 },
    P2PNode { peer_id: String },
    User { address: Address },
    Bootstrap,
}

/// Validator commitment data from Go
#[repr(C)]
pub struct ValidatorCommitmentData {
    pub validator_address: [u8; 20],
    pub commitment: [u8; 32],
    pub index: u8,
    pub timestamp: u64,
}

/// P2P node commitment data from Go
#[repr(C)]
pub struct P2PCommitmentData {
    pub peer_id: *const c_char,
    pub commitment: [u8; 32],
    pub timestamp: u64,
}

/// Global validator commitment storage
static VALIDATOR_COMMITMENTS: RwLock<Vec<ZKCommitment>> = RwLock::new(Vec::new());
static P2P_COMMITMENTS: RwLock<Vec<ZKCommitment>> = RwLock::new(Vec::new());

/// FFI: Add validator commitments from Go
///
/// # Safety
/// This function is unsafe as it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn add_validator_commitments(
    commitments: *const ValidatorCommitmentData,
    count: c_int,
) -> c_int {
    if commitments.is_null() || count <= 0 {
        return -1;
    }

    let commitment_slice = slice::from_raw_parts(commitments, count as usize);

    let mut storage = VALIDATOR_COMMITMENTS.write();

    for data in commitment_slice {
        let address = Address::from_slice(&data.validator_address);
        let commitment = H256::from_slice(&data.commitment);

        let zk_commitment = ZKCommitment {
            commitment,
            nullifier: None,
            block_height: data.timestamp / 10, // Approximate block height
            timestamp: data.timestamp,
            source: CommitmentSource::Validator { address, index: 0 },
        };

        storage.push(zk_commitment);
    }

    tracing::info!("Added {} validator commitments via FFI", count);

    0 // Success
}

/// FFI: Add P2P node commitments from Go
///
/// # Safety
/// This function is unsafe as it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn add_p2p_commitments(
    commitments: *const P2PCommitmentData,
    count: c_int,
) -> c_int {
    if commitments.is_null() || count <= 0 {
        return -1;
    }

    let commitment_slice = slice::from_raw_parts(commitments, count as usize);

    let mut storage = P2P_COMMITMENTS.write();

    for data in commitment_slice {
        let peer_id = if data.peer_id.is_null() {
            "unknown".to_string()
        } else {
            CStr::from_ptr(data.peer_id)
                .to_string_lossy()
                .to_string()
        };

        let commitment = H256::from_slice(&data.commitment);

        let zk_commitment = ZKCommitment {
            commitment,
            nullifier: None,
            block_height: data.timestamp / 10,
            timestamp: data.timestamp,
            source: CommitmentSource::P2PNode { peer_id },
        };

        storage.push(zk_commitment);
    }

    tracing::info!("Added {} P2P commitments via FFI", count);

    0 // Success
}

/// FFI: Load commitments into UniversalSwitch
///
/// # Safety
/// This function is unsafe as it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn load_commitments_to_switch(
    universal_switch_ptr: *mut c_void,
) -> c_int {
    if universal_switch_ptr.is_null() {
        return -1;
    }

    // Cast to UniversalSwitch
    let switch = &*(universal_switch_ptr as *const UniversalSwitch);

    // Get runtime for async operations
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Load validator commitments
    let validator_commitments = VALIDATOR_COMMITMENTS.read().clone();
    if !validator_commitments.is_empty() {
        rt.block_on(async {
            switch.load_validator_commitments(validator_commitments).await
        }).unwrap_or_else(|e| {
            tracing::error!("Failed to load validator commitments: {}", e);
        });
    }

    // Load P2P commitments
    let p2p_commitments = P2P_COMMITMENTS.read().clone();
    if !p2p_commitments.is_empty() {
        rt.block_on(async {
            switch.add_p2p_commitments(p2p_commitments).await
        }).unwrap_or_else(|e| {
            tracing::error!("Failed to load P2P commitments: {}", e);
        });
    }

    let total = VALIDATOR_COMMITMENTS.read().len() + P2P_COMMITMENTS.read().len();
    tracing::info!("Loaded {} total commitments into UniversalSwitch", total);

    total as c_int
}

/// FFI: Get total commitment count
#[no_mangle]
pub extern "C" fn get_total_commitment_count() -> c_int {
    let validator_count = VALIDATOR_COMMITMENTS.read().len();
    let p2p_count = P2P_COMMITMENTS.read().len();
    (validator_count + p2p_count) as c_int
}

/// FFI: Clear all commitments (for testing)
#[no_mangle]
pub extern "C" fn clear_all_commitments() {
    VALIDATOR_COMMITMENTS.write().clear();
    P2P_COMMITMENTS.write().clear();
    tracing::info!("Cleared all commitments");
}

/// FFI: Generate test validator commitments (for development)
#[no_mangle]
pub extern "C" fn generate_test_validator_commitments(
    validator_count: c_int,
    commitments_per_validator: c_int,
) -> c_int {
    if validator_count <= 0 || commitments_per_validator <= 0 {
        return -1;
    }

    let mut storage = VALIDATOR_COMMITMENTS.write();

    for v in 0..validator_count {
        let address = Address::from_low_u64_be(v as u64);

        for c in 0..commitments_per_validator {
            let commitment = H256::random();

            let zk_commitment = ZKCommitment {
                commitment,
                nullifier: None,
                block_height: 100000 + (v * commitments_per_validator + c) as u64,
                timestamp: chrono::Utc::now().timestamp() as u64,
                source: CommitmentSource::Validator { address, index: c as u8 },
            };

            storage.push(zk_commitment);
        }
    }

    let total = validator_count * commitments_per_validator;
    tracing::info!("Generated {} test validator commitments", total);

    total
}

/// FFI: Get validator commitment by index
///
/// # Safety
/// This function is unsafe as it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn get_validator_commitment(
    index: c_int,
    out_commitment: *mut [u8; 32],
    out_address: *mut [u8; 20],
) -> c_int {
    if index < 0 || out_commitment.is_null() || out_address.is_null() {
        return -1;
    }

    let storage = VALIDATOR_COMMITMENTS.read();

    if index as usize >= storage.len() {
        return -1;
    }

    let commitment = &storage[index as usize];

    // Copy commitment hash
    *out_commitment = *commitment.commitment.as_fixed_bytes();

    // Extract validator address if available
    if let CommitmentSource::Validator { address, .. } = &commitment.source {
        *out_address = *address.as_fixed_bytes();
    } else {
        *out_address = [0u8; 20];
    }

    0 // Success
}

/// FFI: Export commitments as JSON string
#[no_mangle]
pub extern "C" fn export_commitments_json() -> *mut c_char {
    let validator_commitments = VALIDATOR_COMMITMENTS.read();
    let p2p_commitments = P2P_COMMITMENTS.read();

    let export_data = serde_json::json!({
        "validator_commitments": validator_commitments.len(),
        "p2p_commitments": p2p_commitments.len(),
        "total": validator_commitments.len() + p2p_commitments.len(),
        "timestamp": chrono::Utc::now().timestamp(),
    });

    match serde_json::to_string(&export_data) {
        Ok(json_str) => {
            match CString::new(json_str) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// FFI: Free string allocated by Rust
///
/// # Safety
/// This function is unsafe as it deals with raw pointers from FFI
#[no_mangle]
pub unsafe extern "C" fn free_rust_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = CString::from_raw(s);
}

/// Helper function to get all validator commitments
pub fn get_all_validator_commitments() -> Vec<ZKCommitment> {
    VALIDATOR_COMMITMENTS.read().clone()
}

/// Helper function to get all P2P commitments
pub fn get_all_p2p_commitments() -> Vec<ZKCommitment> {
    P2P_COMMITMENTS.read().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_commitment_storage() {
        // Clear any existing commitments
        clear_all_commitments();

        // Generate test commitments
        let count = generate_test_validator_commitments(10, 5);
        assert_eq!(count, 50);

        // Check total count
        let total = get_total_commitment_count();
        assert_eq!(total, 50);

        // Get specific commitment
        unsafe {
            let mut commitment = [0u8; 32];
            let mut address = [0u8; 20];
            let result = get_validator_commitment(0, &mut commitment, &mut address);
            assert_eq!(result, 0);
            assert_ne!(commitment, [0u8; 32]);
        }
    }

    #[test]
    fn test_json_export() {
        clear_all_commitments();
        generate_test_validator_commitments(5, 2);

        let json_ptr = export_commitments_json();
        assert!(!json_ptr.is_null());

        unsafe {
            let json_str = CStr::from_ptr(json_ptr).to_string_lossy();
            assert!(json_str.contains("\"validator_commitments\":10"));
            assert!(json_str.contains("\"total\":10"));

            free_rust_string(json_ptr);
        }
    }
}