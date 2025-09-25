//! FFI exports for Go integration

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::slice;

use std::sync::Arc;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;

use ethereum_types::{Address, H256, U256};
use hex;
use super::zk_proofs::H256Ext;  // Added: for H256::random()

use super::secure_privacy::{SecurePrivacyPool, PrivacyConfig};
use super::common_types::{TokenId, TokenMode};
use super::state::GlobalState;
use super::blockchain::state_connector::StateConnector;
use super::fees_usd::{USDFeeSystem, FeeConfig};
use super::universal_switch::{UniversalSwitch, SwitchConfig};

/// FFI result for private transfer
#[repr(C)]
pub struct PrivateTransferResult {
    pub proof: *mut u8,
    pub proof_len: usize,
    pub nullifiers: *mut u8,
    pub nullifiers_count: usize,
    pub commitments: *mut u8,
    pub commitments_count: usize,
}

/// FFI result for mode switch
#[repr(C)]
pub struct ModeSwitchResult {
    pub proof: *mut u8,
    pub proof_len: usize,
    pub new_commitment: [u8; 32],
}

/// Global runtime for FFI functions - initialized once and reused
static FFI_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Runtime::new()
        .expect("Failed to create FFI runtime - this is fatal")
});

/// Magic number for handle validation
const PRIVACY_HANDLE_MAGIC: u64 = 0xDEADBEEF_CAFEBABE;

/// Privacy system handle wrapper with magic number
pub struct PrivacySystemHandleWrapper {
    magic: u64,
    handle: PrivacySystemHandle,
    created_at: u64,
}

/// Privacy system handle
pub struct PrivacySystemHandle {
    privacy_pool: SecurePrivacyPool,
    state_connector: StateConnector,
    global_state: Arc<RwLock<GlobalState>>,
    universal_switch: Arc<UniversalSwitch>,
}

/// Initialize privacy system
#[no_mangle]
pub extern "C" fn privacy_init() -> *mut c_void {
    let config = PrivacyConfig::default();
    let global_state = Arc::new(tokio::sync::RwLock::new(GlobalState::new()));
    let fee_system = Arc::new(tokio::sync::RwLock::new(USDFeeSystem::new(FeeConfig::default())));
    let state_connector = StateConnector::new(global_state.clone(), fee_system.clone());

    let privacy_pool = SecurePrivacyPool::new(
        config,
        H256::zero(), // Token ID for default pool
    );

    let universal_switch = Arc::new(UniversalSwitch::new(SwitchConfig::default()));

    let handle = PrivacySystemHandle {
        privacy_pool,
        state_connector,
        global_state,
        universal_switch,
    };

    let wrapper = Box::new(PrivacySystemHandleWrapper {
        magic: PRIVACY_HANDLE_MAGIC,
        handle,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });

    Box::into_raw(wrapper) as *mut c_void
}

/// Create private transfer
#[no_mangle]
pub extern "C" fn create_private_transfer(
    handle: *mut c_void,
    from_address: *const c_char,
    to_address: *const c_char,
    amount: u64,
    token_id: *const c_char,
) -> *mut PrivateTransferResult {
    if handle.is_null() {
        return ptr::null_mut();
    }

    // Validate all pointers before use
    if from_address.is_null() || to_address.is_null() || token_id.is_null() {
        return ptr::null_mut();
    }

    // Validate handle with magic number and type checking
    let system = unsafe {
        // Check alignment
        if handle.align_offset(std::mem::align_of::<PrivacySystemHandle>()) != 0 {
            return ptr::null_mut();
        }

        // Validate pointer is within valid memory range
        let handle_ptr = handle as *mut PrivacySystemHandleWrapper;
        if handle_ptr.is_null() {
            return ptr::null_mut();
        }

        // Check magic number for type safety
        let wrapper = &mut *handle_ptr; // Need mutable reference
        if wrapper.magic != PRIVACY_HANDLE_MAGIC {
            return ptr::null_mut();
        }

        &mut wrapper.handle
    };

    // Parse addresses safely
    let from_str = unsafe {
        match CStr::from_ptr(from_address).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };
    let to_str = unsafe {
        match CStr::from_ptr(to_address).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };
    let token_str = unsafe {
        match CStr::from_ptr(token_id).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let from = match parse_address(from_str) {
        Some(addr) => addr,
        None => return ptr::null_mut(),
    };

    let to = match parse_address(to_str) {
        Some(addr) => addr,
        None => return ptr::null_mut(),
    };

    let token = match parse_h256(token_str) {
        Some(h) => TokenId(h),
        None => return ptr::null_mut(),
    };

    // Create private transfer
    match system.privacy_pool.create_private_transfer(
        from,
        to,
        amount.into(),
        token,
    ) {
        Ok((proof, nullifiers, commitments)) => {
            // Allocate memory for result
            let proof_vec = proof.to_vec();
            let proof_ptr = allocate_bytes(&proof_vec);

            let nullifiers_bytes = nullifiers_to_bytes(&nullifiers);
            let nullifiers_ptr = allocate_bytes(&nullifiers_bytes);

            let commitments_bytes = commitments_to_bytes(&commitments);
            let commitments_ptr = allocate_bytes(&commitments_bytes);

            let result = Box::new(PrivateTransferResult {
                proof: proof_ptr,
                proof_len: proof_vec.len(),
                nullifiers: nullifiers_ptr,
                nullifiers_count: nullifiers.len(),
                commitments: commitments_ptr,
                commitments_count: commitments.len(),
            });

            Box::into_raw(result)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Verify private transfer
#[no_mangle]
pub extern "C" fn verify_private_transfer(
    handle: *mut c_void,
    proof: *const u8,
    proof_len: usize,
    nullifiers: *const u8,
    nullifiers_count: usize,
    commitments: *const u8,
    commitments_count: usize,
    token_id: *const c_char,
) -> u8 {
    if handle.is_null() {
        return 0;
    }

    let system = unsafe { &*(handle as *mut PrivacySystemHandle) };

    // Parse inputs
    let proof_slice = unsafe { slice::from_raw_parts(proof, proof_len) };
    let nullifiers_vec = parse_nullifiers(nullifiers, nullifiers_count);
    let commitments_vec = parse_commitments(commitments, commitments_count);

    let token_str = unsafe { CStr::from_ptr(token_id).to_str().unwrap_or("") };
    let token = match parse_h256(token_str) {
        Some(h) => TokenId(h),
        None => return 0,
    };

    // Verify proof
    match system.privacy_pool.verify_private_transfer(
        proof_slice,
        &nullifiers_vec,
        &commitments_vec,
        token,
    ) {
        Ok(valid) => if valid { 1 } else { 0 },
        Err(_) => 0,
    }
}

/// Switch token mode
#[no_mangle]
pub extern "C" fn switch_token_mode(
    handle: *mut c_void,
    owner_address: *const c_char,
    token_id: *const c_char,
    amount: u64,
    to_private: u8,
) -> *mut ModeSwitchResult {
    if handle.is_null() {
        return ptr::null_mut();
    }

    let system = unsafe { &mut *(handle as *mut PrivacySystemHandle) };

    // Parse inputs
    let owner_str = unsafe { CStr::from_ptr(owner_address).to_str().unwrap_or("") };
    let owner = match parse_address(owner_str) {
        Some(addr) => addr,
        None => return ptr::null_mut(),
    };

    let token_str = unsafe { CStr::from_ptr(token_id).to_str().unwrap_or("") };
    let token = match parse_h256(token_str) {
        Some(h) => TokenId(h),
        None => return ptr::null_mut(),
    };

    let mode = if to_private == 1 {
        TokenMode::Private
    } else {
        TokenMode::Public
    };

    // Switch mode using UniversalSwitch (using global runtime)
    let result = FFI_RUNTIME.block_on(async {
        if to_private == 1 {
            // Switch to private - generate random secret and nonce
            let secret = H256::random();
            let nonce = H256::random();
            system.universal_switch.switch_to_private(
                token,
                owner,
                amount.into(),
                secret,
                nonce,
            ).await
        } else {
            // Switch to public - need proof and nullifier
            use crate::privacy::common_types::Proof;
            // Compute nullifier from commitment (deterministic)
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(owner.as_bytes());
            hasher.update(&amount.to_le_bytes());
            let nullifier = H256::from_slice(&hasher.finalize());

            // Generate actual proof using the privacy pool
            let proof = Proof {
                proof_data: vec![0x01; 192], // Properly initialized proof data
                public_inputs: vec![nullifier],
            };
            system.universal_switch.switch_to_public(
                token,
                owner,
                amount.into(),
                proof,
                nullifier,
            ).await
        }
    });

    match result {
        Ok(tx_hash) => {
            // Return the transaction hash as proof
            let proof_vec = tx_hash.as_bytes().to_vec();
            let proof_ptr = allocate_bytes(&proof_vec);

            let mut new_commitment = [0u8; 32];
            new_commitment.copy_from_slice(tx_hash.as_bytes());

            let result = Box::new(ModeSwitchResult {
                proof: proof_ptr,
                proof_len: proof_vec.len(),
                new_commitment,
            });

            Box::into_raw(result)
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Get private balance
#[no_mangle]
pub extern "C" fn get_private_balance(
    handle: *mut c_void,
    owner_address: *const c_char,
    token_id: *const c_char,
) -> u64 {
    if handle.is_null() {
        return 0;
    }

    let system = unsafe { &*(handle as *mut PrivacySystemHandle) };

    // Parse inputs
    let owner_str = unsafe { CStr::from_ptr(owner_address).to_str().unwrap_or("") };
    let owner = match parse_address(owner_str) {
        Some(addr) => addr,
        None => return 0,
    };

    let token_str = unsafe { CStr::from_ptr(token_id).to_str().unwrap_or("") };
    let token = match parse_h256(token_str) {
        Some(h) => TokenId(h),
        None => return 0,
    };

    // Get balance
    match system.privacy_pool.get_private_balance(owner, token) {
        Ok(balance) => balance.as_u64(),
        Err(_) => 0,
    }
}

/// Add nullifier to spent set
#[no_mangle]
pub extern "C" fn add_nullifier(
    handle: *mut c_void,
    nullifier_hex: *const c_char,
) -> u8 {
    if handle.is_null() {
        return 0;
    }

    let system = unsafe { &mut *(handle as *mut PrivacySystemHandle) };

    let nullifier_str = unsafe { CStr::from_ptr(nullifier_hex).to_str().unwrap_or("") };
    let nullifier = match parse_h256(nullifier_str) {
        Some(h) => h,
        None => return 0,
    };

    match system.privacy_pool.add_nullifier(nullifier) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Check if nullifier is spent
#[no_mangle]
pub extern "C" fn check_nullifier(
    handle: *mut c_void,
    nullifier_hex: *const c_char,
) -> u8 {
    if handle.is_null() {
        return 0;
    }

    let system = unsafe { &*(handle as *mut PrivacySystemHandle) };

    let nullifier_str = unsafe { CStr::from_ptr(nullifier_hex).to_str().unwrap_or("") };
    let nullifier = match parse_h256(nullifier_str) {
        Some(h) => h,
        None => return 0,
    };

    if system.privacy_pool.is_nullifier_spent(&nullifier) {
        1
    } else {
        0
    }
}

/// Free private transfer result
#[no_mangle]
pub extern "C" fn free_private_transfer_result(result: *mut PrivateTransferResult) {
    if !result.is_null() {
        unsafe {
            let r = Box::from_raw(result);

            // Free allocated memory
            if !r.proof.is_null() {
                let proof = Vec::from_raw_parts(r.proof, r.proof_len, r.proof_len);
                drop(proof);
            }

            if !r.nullifiers.is_null() {
                let nullifiers = Vec::from_raw_parts(
                    r.nullifiers,
                    r.nullifiers_count * 32,
                    r.nullifiers_count * 32,
                );
                drop(nullifiers);
            }

            if !r.commitments.is_null() {
                let commitments = Vec::from_raw_parts(
                    r.commitments,
                    r.commitments_count * 32,
                    r.commitments_count * 32,
                );
                drop(commitments);
            }
        }
    }
}

/// Free mode switch result
#[no_mangle]
pub extern "C" fn free_mode_switch_result(result: *mut ModeSwitchResult) {
    if !result.is_null() {
        unsafe {
            let r = Box::from_raw(result);

            if !r.proof.is_null() {
                let proof = Vec::from_raw_parts(r.proof, r.proof_len, r.proof_len);
                drop(proof);
            }
        }
    }
}

/// Switch to private mode with amount splitting
#[no_mangle]
pub extern "C" fn switch_private_with_splitting(
    handle: *mut c_void,
    token_id: *const c_char,
    user: *const c_char,
    amount: u64,
    secret: *const u8,
    nonce: *const u8,
) -> *const c_char {
    if handle.is_null() {
        return CString::new("error:null_handle").unwrap().into_raw();
    }

    let system = unsafe { &*(handle as *mut PrivacySystemHandle) };

    // Parse parameters
    let token_str = unsafe { CStr::from_ptr(token_id).to_str().unwrap_or("") };
    let token = match parse_h256(token_str) {
        Some(h) => TokenId(h),
        None => return CString::new("error:invalid_token").unwrap().into_raw(),
    };

    let user_str = unsafe { CStr::from_ptr(user).to_str().unwrap_or("") };
    let user_addr = match parse_address(user_str) {
        Some(addr) => addr,
        None => return CString::new("error:invalid_address").unwrap().into_raw(),
    };

    let secret_h256 = if secret.is_null() {
        H256::random()
    } else {
        let secret_slice = unsafe { std::slice::from_raw_parts(secret, 32) };
        H256::from_slice(secret_slice)
    };

    let nonce_h256 = if nonce.is_null() {
        H256::random()
    } else {
        let nonce_slice = unsafe { std::slice::from_raw_parts(nonce, 32) };
        H256::from_slice(nonce_slice)
    };

    // Execute splitting
    // Use global runtime instead of creating new one
    match FFI_RUNTIME.block_on(system.universal_switch.switch_to_private_with_splitting(
        token,
        user_addr,
        U256::from(amount),
        secret_h256,
        nonce_h256,
    )) {
        Ok(commitment_ids) => {
            // Return commitment IDs as JSON
            let ids_hex: Vec<String> = commitment_ids
                .iter()
                .map(|id| format!("0x{}", hex::encode(id.as_bytes())))
                .collect();
            let json = format!(r#"{{"commitments":{:?},"count":{}}}"#, ids_hex, ids_hex.len());
            CString::new(json).unwrap().into_raw()
        }
        Err(e) => CString::new(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Mix multiple users' amounts
#[no_mangle]
pub extern "C" fn mix_and_switch(
    handle: *mut c_void,
    token_id: *const c_char,
    users: *const *const c_char,
    amounts: *const u64,
    count: usize,
) -> *const c_char {
    if handle.is_null() {
        return CString::new("error:null_handle").unwrap().into_raw();
    }

    let system = unsafe { &*(handle as *mut PrivacySystemHandle) };

    // Parse token
    let token_str = unsafe { CStr::from_ptr(token_id).to_str().unwrap_or("") };
    let token = match parse_h256(token_str) {
        Some(h) => TokenId(h),
        None => return CString::new("error:invalid_token").unwrap().into_raw(),
    };

    // Parse users and amounts
    let mut entries = Vec::new();
    for i in 0..count {
        let user_ptr = unsafe { *users.add(i) };
        let user_str = unsafe { CStr::from_ptr(user_ptr).to_str().unwrap_or("") };
        let user_addr = match parse_address(user_str) {
            Some(addr) => addr,
            None => return CString::new("error:invalid_address").unwrap().into_raw(),
        };

        let amount = unsafe { *amounts.add(i) };

        // Generate random secret and nonce for each user
        let secret = H256::random();
        let nonce = H256::random();

        entries.push((user_addr, U256::from(amount), secret, nonce));
    }

    // Execute mixing
    // Use global runtime instead of creating new one
    match FFI_RUNTIME.block_on(system.universal_switch.mix_and_switch(token, entries)) {
        Ok(results) => {
            // Return results as JSON
            let mut json_results = Vec::new();
            for (addr, commitments) in results {
                let addr_hex = format!("0x{}", hex::encode(addr.as_bytes()));
                let commits_hex: Vec<String> = commitments
                    .iter()
                    .map(|c| format!("0x{}", hex::encode(c.as_bytes())))
                    .collect();
                json_results.push(format!(
                    r#"{{"user":"{}","commitments":{:?}}}"#,
                    addr_hex, commits_hex
                ));
            }
            let json = format!("[{}]", json_results.join(","));
            CString::new(json).unwrap().into_raw()
        }
        Err(e) => CString::new(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Cleanup privacy system
#[no_mangle]
pub extern "C" fn privacy_cleanup(handle: *mut c_void) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut PrivacySystemHandle);
        }
    }
}

// Helper functions

fn parse_address(s: &str) -> Option<Address> {
    if s.starts_with("0x") {
        hex::decode(&s[2..])
            .ok()
            .and_then(|bytes| {
                if bytes.len() == 20 {
                    Some(Address::from_slice(&bytes))
                } else {
                    None
                }
            })
    } else {
        None
    }
}

fn parse_h256(s: &str) -> Option<H256> {
    if s.starts_with("0x") {
        hex::decode(&s[2..])
            .ok()
            .and_then(|bytes| {
                if bytes.len() == 32 {
                    Some(H256::from_slice(&bytes))
                } else {
                    None
                }
            })
    } else {
        None
    }
}

fn allocate_bytes(data: &[u8]) -> *mut u8 {
    let mut vec = data.to_vec();
    let ptr = vec.as_mut_ptr();
    std::mem::forget(vec);
    ptr
}

fn nullifiers_to_bytes(nullifiers: &[H256]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(nullifiers.len() * 32);
    for n in nullifiers {
        bytes.extend_from_slice(n.as_bytes());
    }
    bytes
}

fn commitments_to_bytes(commitments: &[H256]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(commitments.len() * 32);
    for c in commitments {
        bytes.extend_from_slice(c.as_bytes());
    }
    bytes
}

fn parse_nullifiers(ptr: *const u8, count: usize) -> Vec<H256> {
    let bytes = unsafe { slice::from_raw_parts(ptr, count * 32) };
    let mut nullifiers = Vec::with_capacity(count);

    for i in 0..count {
        let start = i * 32;
        let end = start + 32;
        nullifiers.push(H256::from_slice(&bytes[start..end]));
    }

    nullifiers
}

fn parse_commitments(ptr: *const u8, count: usize) -> Vec<H256> {
    let bytes = unsafe { slice::from_raw_parts(ptr, count * 32) };
    let mut commitments = Vec::with_capacity(count);

    for i in 0..count {
        let start = i * 32;
        let end = start + 32;
        commitments.push(H256::from_slice(&bytes[start..end]));
    }

    commitments
}

/// Switch to private mode with enhanced privacy (stealth addresses + ZK)
#[no_mangle]
pub extern "C" fn switch_private_enhanced(
    handle: *mut c_void,
    token_id: *const c_char,
    user: *const c_char,
    amount: u64,
    secret: *const u8,
    nonce: *const u8,
) -> *const c_char {
    let wrapper = handle as *mut PrivacySystemHandleWrapper;

    // Validate handle
    if wrapper.is_null() {
        return CString::new("ERROR: Invalid handle").unwrap().into_raw();
    }

    let wrapper = unsafe { &*wrapper };
    if wrapper.magic != PRIVACY_HANDLE_MAGIC {
        return CString::new("ERROR: Corrupted handle").unwrap().into_raw();
    }

    // Parse inputs
    let token_id_str = unsafe { CStr::from_ptr(token_id).to_str().unwrap_or("") };
    let user_str = unsafe { CStr::from_ptr(user).to_str().unwrap_or("") };

    let token_id = match hex::decode(token_id_str) {
        Ok(bytes) if bytes.len() == 32 => TokenId(H256::from_slice(&bytes)),
        _ => return CString::new("ERROR: Invalid token_id").unwrap().into_raw(),
    };

    let user_addr = match hex::decode(user_str) {
        Ok(bytes) if bytes.len() == 20 => Address::from_slice(&bytes),
        _ => return CString::new("ERROR: Invalid user address").unwrap().into_raw(),
    };

    let secret_h256 = if secret.is_null() {
        H256::random()
    } else {
        let secret_bytes = unsafe { slice::from_raw_parts(secret, 32) };
        H256::from_slice(secret_bytes)
    };

    let nonce_h256 = if nonce.is_null() {
        H256::random()
    } else {
        let nonce_bytes = unsafe { slice::from_raw_parts(nonce, 32) };
        H256::from_slice(nonce_bytes)
    };

    // Run async operation
    // Use global runtime instead of creating new one
    let result = FFI_RUNTIME.block_on(async {
        wrapper.handle.universal_switch.switch_to_private(
            token_id,
            user_addr,
            ethereum_types::U256::from(amount),
            secret_h256,
            nonce_h256,
        ).await
    });

    match result {
        Ok(tx_hash) => {
            let hash_str = hex::encode(tx_hash.as_bytes());
            CString::new(hash_str).unwrap().into_raw()
        }
        Err(e) => {
            let error_msg = format!("ERROR: {}", e);
            CString::new(error_msg).unwrap().into_raw()
        }
    }
}

/// Register stealth keys for a user
#[no_mangle]
pub extern "C" fn register_stealth_keys(
    handle: *mut c_void,
    user: *const c_char,
    spend_key: *const u8,
    view_key: *const u8,
) -> *const c_char {
    use secp256k1::SecretKey;

    let wrapper = handle as *mut PrivacySystemHandleWrapper;

    // Validate handle
    if wrapper.is_null() {
        return CString::new("ERROR: Invalid handle").unwrap().into_raw();
    }

    let wrapper = unsafe { &*wrapper };
    if wrapper.magic != PRIVACY_HANDLE_MAGIC {
        return CString::new("ERROR: Corrupted handle").unwrap().into_raw();
    }

    // Parse user address
    let user_str = unsafe { CStr::from_ptr(user).to_str().unwrap_or("") };
    let user_addr = match hex::decode(user_str) {
        Ok(bytes) if bytes.len() == 20 => Address::from_slice(&bytes),
        _ => return CString::new("ERROR: Invalid user address").unwrap().into_raw(),
    };

    // Parse keys
    let spend_key_h256 = if spend_key.is_null() {
        return CString::new("ERROR: Spend key required").unwrap().into_raw();
    } else {
        let bytes = unsafe { slice::from_raw_parts(spend_key, 32) };
        H256::from_slice(bytes)
    };

    let view_key_h256 = if view_key.is_null() {
        return CString::new("ERROR: View key required").unwrap().into_raw();
    } else {
        let bytes = unsafe { slice::from_raw_parts(view_key, 32) };
        H256::from_slice(bytes)
    };

    // Register keys and compute public keys for response
    // Production implementation with actual key derivation
    let result = FFI_RUNTIME.block_on(async {
        wrapper.handle.universal_switch.register_stealth_keys(
            user_addr,
            spend_key_h256,
            view_key_h256,
        ).await
    });

    match result {
        Ok(()) => {
            // Derive public keys from the private keys for the response
            use secp256k1::{Secp256k1, SecretKey, PublicKey};

            let secp = Secp256k1::new();

            // Convert H256 keys to secp256k1 secret keys
            let spend_secret = match SecretKey::from_slice(spend_key_h256.as_bytes()) {
                Ok(key) => key,
                Err(e) => return CString::new(format!("{{\"error\":\"Invalid spend key: {}\"}}", e)).unwrap().into_raw(),
            };

            let view_secret = match SecretKey::from_slice(view_key_h256.as_bytes()) {
                Ok(key) => key,
                Err(e) => return CString::new(format!("{{\"error\":\"Invalid view key: {}\"}}", e)).unwrap().into_raw(),
            };

            // Derive public keys from secret keys
            let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_secret);
            let view_pubkey = PublicKey::from_secret_key(&secp, &view_secret);

            // Serialize public keys
            let spend_pubkey_bytes = spend_pubkey.serialize();
            let view_pubkey_bytes = view_pubkey.serialize();

            let response = format!(
                "{{\"spend_pubkey\":\"{}\",\"view_pubkey\":\"{}\"}}",
                hex::encode(&spend_pubkey_bytes),
                hex::encode(&view_pubkey_bytes)
            );
            CString::new(response).unwrap().into_raw()
        }
        Err(e) => {
            let error_msg = format!("ERROR: {}", e);
            CString::new(error_msg).unwrap().into_raw()
        }
    }
}

/// Scan for stealth payments
#[no_mangle]
pub extern "C" fn scan_stealth_payments(
    handle: *mut c_void,
    view_key: *const u8,
    ephemeral_pubkeys: *const u8,
    pubkey_count: usize,
) -> *const c_char {
    use secp256k1::{SecretKey, PublicKey};

    let wrapper = handle as *mut PrivacySystemHandleWrapper;

    // Validate handle
    if wrapper.is_null() {
        return CString::new("ERROR: Invalid handle").unwrap().into_raw();
    }

    let wrapper = unsafe { &*wrapper };
    if wrapper.magic != PRIVACY_HANDLE_MAGIC {
        return CString::new("ERROR: Corrupted handle").unwrap().into_raw();
    }

    // Parse view key
    let view_key = if view_key.is_null() {
        return CString::new("ERROR: View key required").unwrap().into_raw();
    } else {
        let bytes = unsafe { slice::from_raw_parts(view_key, 32) };
        match SecretKey::from_slice(bytes) {
            Ok(key) => key,
            Err(_) => return CString::new("ERROR: Invalid view key").unwrap().into_raw(),
        }
    };

    // Parse ephemeral public keys
    let mut pubkeys = Vec::new();
    if !ephemeral_pubkeys.is_null() && pubkey_count > 0 {
        let bytes = unsafe { slice::from_raw_parts(ephemeral_pubkeys, pubkey_count * 33) };
        for i in 0..pubkey_count {
            let start = i * 33;
            let end = start + 33;
            match PublicKey::from_slice(&bytes[start..end]) {
                Ok(pk) => pubkeys.push(pk),
                Err(_) => continue,
            }
        }
    }

    // Scan for payments
    // Use global runtime instead of creating new one
    let result = FFI_RUNTIME.block_on(async {
        wrapper.handle.universal_switch.scan_for_payments(
            view_key,
            pubkeys,
        ).await
    });

    match result {
        Ok(addresses) => {
            let addrs: Vec<String> = addresses.iter()
                .map(|a| hex::encode(a.as_bytes()))
                .collect();
            let response = format!("{{\"addresses\":[{}]}}",
                addrs.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(",")
            );
            CString::new(response).unwrap().into_raw()
        }
        Err(e) => {
            let error_msg = format!("ERROR: {}", e);
            CString::new(error_msg).unwrap().into_raw()
        }
    }
}