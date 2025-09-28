//! Direct FFI exports for ZK proof generation using real Halo2 implementation
//!
//! These functions provide C-compatible interfaces for Go to directly
//! call our production-ready ZK-SNARK proof generation.

use std::ptr;
use std::slice;
use std::os::raw::c_char;
use std::ffi::CStr;

use anyhow::Result;
use super::halo2_circuits::{Halo2ProofSystem, PrivateTransferCircuit};
use super::common_types::Fr;
use halo2_axiom::circuit::Value;
use rand::rngs::OsRng;
use ff::{Field, PrimeField};

/// Result structure for proof generation
#[repr(C)]
pub struct ProofResult {
    /// Pointer to proof bytes (caller must free with qora_free_proof)
    pub proof: *mut u8,
    /// Length of proof in bytes
    pub proof_len: usize,
    /// Success flag (1 = success, 0 = failure)
    pub success: u8,
    /// Error message (null if success)
    pub error_msg: *mut c_char,
}

/// Opaque handle to proof system
pub struct ProofSystemHandle {
    system: Halo2ProofSystem,
    initialized: bool,
}

/// Initialize a new proof system with given circuit size
///
/// # Parameters
/// - `k`: Circuit size parameter (2^k rows). Recommended: 11 for most privacy operations
///
/// # Returns
/// - Handle to proof system or null on failure
#[no_mangle]
pub extern "C" fn qora_proof_system_init(k: u32) -> *mut ProofSystemHandle {
    if k < 4 || k > 20 {
        return ptr::null_mut();
    }

    let system = Halo2ProofSystem::new(k);

    let handle = Box::new(ProofSystemHandle {
        system,
        initialized: false,
    });

    Box::into_raw(handle)
}

/// Setup proof system with a sample circuit
/// This generates proving and verifying keys
///
/// # Parameters
/// - `handle`: Proof system handle from qora_proof_system_init
///
/// # Returns
/// - 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn qora_proof_system_setup(handle: *mut ProofSystemHandle) -> u8 {
    if handle.is_null() {
        return 0;
    }

    let system = unsafe { &mut *handle };

    // Create a dummy circuit for setup
    let dummy_circuit = PrivateTransferCircuit {
        secret: Value::known(Fr::from(1)),
        amount: Value::known(Fr::from(1)),
        blinding: Value::known(Fr::random(OsRng)),
        nullifier: Value::known(Fr::random(OsRng)),
        commitment: Value::known(Fr::random(OsRng)),
        leaf_index: Value::known(Fr::from(0)),
    };

    match system.system.setup(&dummy_circuit) {
        Ok(()) => {
            system.initialized = true;
            1
        }
        Err(_) => 0,
    }
}

/// Generate a ZK-SNARK proof for a private transfer
///
/// # Parameters
/// - `handle`: Initialized proof system handle
/// - `secret`: Secret value (32 bytes)
/// - `amount`: Transfer amount (as u64)
/// - `blinding`: Blinding factor (32 bytes, can be random)
/// - `nullifier`: Nullifier (32 bytes)
/// - `commitment`: Commitment (32 bytes)
/// - `public_inputs`: Array of public inputs (each 32 bytes)
/// - `public_inputs_len`: Number of public inputs
///
/// # Returns
/// - ProofResult containing the proof or error
#[no_mangle]
pub extern "C" fn qora_generate_proof(
    handle: *mut ProofSystemHandle,
    secret: *const u8,
    amount: u64,
    blinding: *const u8,
    nullifier: *const u8,
    commitment: *const u8,
    public_inputs: *const u8,
    public_inputs_len: usize,
) -> ProofResult {
    // Validate inputs
    if handle.is_null() || secret.is_null() || blinding.is_null() ||
       nullifier.is_null() || commitment.is_null() {
        return ProofResult {
            proof: ptr::null_mut(),
            proof_len: 0,
            success: 0,
            error_msg: c_string("Invalid input pointers"),
        };
    }

    let system = unsafe { &mut *handle };

    if !system.initialized {
        return ProofResult {
            proof: ptr::null_mut(),
            proof_len: 0,
            success: 0,
            error_msg: c_string("Proof system not initialized. Call qora_proof_system_setup first"),
        };
    }

    // Parse field elements from bytes
    let secret_bytes = unsafe { slice::from_raw_parts(secret, 32) };
    let secret_arr: [u8; 32] = secret_bytes.try_into().unwrap();
    let secret_fr = if let Some(fr) = Fr::from_repr(secret_arr).into() {
        fr
    } else {
            return ProofResult {
                proof: ptr::null_mut(),
                proof_len: 0,
                success: 0,
                error_msg: c_string("Invalid secret format"),
            };
    };

    let blinding_bytes = unsafe { slice::from_raw_parts(blinding, 32) };
    let blinding_arr: [u8; 32] = blinding_bytes.try_into().unwrap();
    let blinding_fr = if let Some(fr) = Fr::from_repr(blinding_arr).into() {
        fr
    } else {
        Fr::random(OsRng) // Use random if invalid
    };

    let nullifier_bytes = unsafe { slice::from_raw_parts(nullifier, 32) };
    let nullifier_arr: [u8; 32] = nullifier_bytes.try_into().unwrap();
    let nullifier_fr = if let Some(fr) = Fr::from_repr(nullifier_arr).into() {
        fr
    } else {
            return ProofResult {
                proof: ptr::null_mut(),
                proof_len: 0,
                success: 0,
                error_msg: c_string("Invalid nullifier format"),
            };
    };

    let commitment_bytes = unsafe { slice::from_raw_parts(commitment, 32) };
    let commitment_arr: [u8; 32] = commitment_bytes.try_into().unwrap();
    let commitment_fr = if let Some(fr) = Fr::from_repr(commitment_arr).into() {
        fr
    } else {
            return ProofResult {
                proof: ptr::null_mut(),
                proof_len: 0,
                success: 0,
                error_msg: c_string("Invalid commitment format"),
            };
    };

    // Parse public inputs
    let mut public_inputs_vec = Vec::new();
    if !public_inputs.is_null() && public_inputs_len > 0 {
        let inputs_bytes = unsafe {
            slice::from_raw_parts(public_inputs, public_inputs_len * 32)
        };

        for i in 0..public_inputs_len {
            let start = i * 32;
            let end = start + 32;
            let input_bytes: [u8; 32] = inputs_bytes[start..end].try_into().unwrap();

            if let Some(fr) = Fr::from_repr(input_bytes).into() {
                public_inputs_vec.push(fr);
            } else {
                return ProofResult {
                    proof: ptr::null_mut(),
                    proof_len: 0,
                    success: 0,
                    error_msg: c_string(&format!("Invalid public input at index {}", i)),
                };
            }
        }
    }

    // Create circuit
    let circuit = PrivateTransferCircuit {
        secret: Value::known(secret_fr),
        amount: Value::known(Fr::from(amount)),
        blinding: Value::known(blinding_fr),
        nullifier: Value::known(nullifier_fr),
        commitment: Value::known(commitment_fr),
        leaf_index: Value::known(Fr::from(0)), // Default to 0
    };

    // Generate proof
    match system.system.prove(circuit, &public_inputs_vec) {
        Ok(proof_bytes) => {
            let proof_len = proof_bytes.len();
            let proof_ptr = Box::into_raw(proof_bytes.into_boxed_slice()) as *mut u8;

            ProofResult {
                proof: proof_ptr,
                proof_len,
                success: 1,
                error_msg: ptr::null_mut(),
            }
        }
        Err(e) => {
            ProofResult {
                proof: ptr::null_mut(),
                proof_len: 0,
                success: 0,
                error_msg: c_string(&format!("Proof generation failed: {}", e)),
            }
        }
    }
}

/// Verify a ZK-SNARK proof
///
/// # Parameters
/// - `handle`: Initialized proof system handle
/// - `proof`: Proof bytes
/// - `proof_len`: Length of proof
/// - `public_inputs`: Public inputs (each 32 bytes)
/// - `public_inputs_len`: Number of public inputs
///
/// # Returns
/// - 1 if valid, 0 if invalid or error
#[no_mangle]
pub extern "C" fn qora_verify_proof(
    handle: *mut ProofSystemHandle,
    proof: *const u8,
    proof_len: usize,
    public_inputs: *const u8,
    public_inputs_len: usize,
) -> u8 {
    if handle.is_null() || proof.is_null() {
        return 0;
    }

    let system = unsafe { &*handle };

    if !system.initialized {
        return 0;
    }

    let proof_bytes = unsafe { slice::from_raw_parts(proof, proof_len) };

    // Parse public inputs
    let mut public_inputs_vec = Vec::new();
    if !public_inputs.is_null() && public_inputs_len > 0 {
        let inputs_bytes = unsafe {
            slice::from_raw_parts(public_inputs, public_inputs_len * 32)
        };

        for i in 0..public_inputs_len {
            let start = i * 32;
            let end = start + 32;
            let input_bytes: [u8; 32] = inputs_bytes[start..end].try_into().unwrap();

            if let Some(fr) = Fr::from_repr(input_bytes).into() {
                public_inputs_vec.push(fr);
            } else {
                return 0; // Invalid input
            }
        }
    }

    match system.system.verify(proof_bytes, &public_inputs_vec) {
        Ok(valid) => if valid { 1 } else { 0 },
        Err(_) => 0,
    }
}

/// Free a proof result
#[no_mangle]
pub extern "C" fn qora_free_proof(result: ProofResult) {
    if !result.proof.is_null() {
        unsafe {
            let _ = Box::from_raw(slice::from_raw_parts_mut(result.proof, result.proof_len));
        }
    }

    if !result.error_msg.is_null() {
        unsafe {
            let _ = CStr::from_ptr(result.error_msg);
            let _ = Box::from_raw(result.error_msg);
        }
    }
}

/// Free a proof system handle
#[no_mangle]
pub extern "C" fn qora_proof_system_free(handle: *mut ProofSystemHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

// Helper function to create C string
fn c_string(s: &str) -> *mut c_char {
    match std::ffi::CString::new(s) {
        Ok(cstr) => {
            let bytes = cstr.as_bytes_with_nul();
            let ptr = Box::into_raw(vec![0u8; bytes.len()].into_boxed_slice()) as *mut c_char;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
            }
            ptr
        }
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_proof_generation() {
        // Initialize proof system
        let handle = qora_proof_system_init(11);
        assert!(!handle.is_null());

        // Setup
        let setup_result = qora_proof_system_setup(handle);
        assert_eq!(setup_result, 1);

        // Create test data
        let secret = [1u8; 32];
        let amount = 1000u64;
        let blinding = [2u8; 32];
        let nullifier = [3u8; 32];
        let commitment = [4u8; 32];
        let public_inputs = [5u8; 64]; // 2 public inputs

        // Generate proof
        let result = qora_generate_proof(
            handle,
            secret.as_ptr(),
            amount,
            blinding.as_ptr(),
            nullifier.as_ptr(),
            commitment.as_ptr(),
            public_inputs.as_ptr(),
            2,
        );

        assert_eq!(result.success, 1);
        assert!(!result.proof.is_null());
        assert!(result.proof_len > 0);

        // Verify proof
        let verify_result = qora_verify_proof(
            handle,
            result.proof,
            result.proof_len,
            public_inputs.as_ptr(),
            2,
        );

        assert_eq!(verify_result, 1);

        // Cleanup
        qora_free_proof(result);
        qora_proof_system_free(handle);
    }
}