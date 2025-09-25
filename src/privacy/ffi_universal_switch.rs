//! FFI exports for Universal Switch
//! For Go integration with L1 blockchain

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Arc;
use ethereum_types::{Address, H256, U256};
use anyhow::Result;
use super::zk_proofs::H256Ext;  // Added: for H256::random()
use serde_json;
use once_cell::sync::Lazy;

use super::universal_switch::{UniversalSwitch, SwitchConfig};
use super::transaction_v2::{TokenId, TokenMode};

/// Global runtime for FFI functions - initialized once and reused
static FFI_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Runtime::new()
        .expect("Failed to create FFI runtime - this is fatal")
});

/// FFI Result structure for Go integration
#[repr(C)]
pub struct SwitchResult {
    pub success: u8,
    pub request_id: [u8; 32],
    pub error_msg: *const c_char,
}

/// FFI handle for Universal Switch
pub struct UniversalSwitchHandle {
    switch: Arc<UniversalSwitch>,
}

/// Process switch request from Go - CRITICAL FOR L1
#[no_mangle]
pub extern "C" fn universal_switch_process(
    token_id: *const c_char,
    from_addr: *const c_char,
    to_mode: u8,  // 0=public, 1=private
    amount: *const c_char,
) -> SwitchResult {
    // Parse token ID
    let token_id_str = unsafe {
        match CStr::from_ptr(token_id).to_str() {
            Ok(s) => s,
            Err(e) => return SwitchResult {
                success: 0,
                request_id: [0; 32],
                error_msg: CString::new(format!("Invalid token_id: {}", e)).unwrap().into_raw(),
            }
        }
    };

    // Parse from address
    let from_str = unsafe {
        match CStr::from_ptr(from_addr).to_str() {
            Ok(s) => s,
            Err(e) => return SwitchResult {
                success: 0,
                request_id: [0; 32],
                error_msg: CString::new(format!("Invalid address: {}", e)).unwrap().into_raw(),
            }
        }
    };

    // Parse amount
    let amount_str = unsafe {
        match CStr::from_ptr(amount).to_str() {
            Ok(s) => s,
            Err(e) => return SwitchResult {
                success: 0,
                request_id: [0; 32],
                error_msg: CString::new(format!("Invalid amount: {}", e)).unwrap().into_raw(),
            }
        }
    };

    // Convert to proper types
    let token = match parse_h256(token_id_str) {
        Some(h) => TokenId(h),
        None => return SwitchResult {
            success: 0,
            request_id: [0; 32],
            error_msg: CString::new("Failed to parse token ID").unwrap().into_raw(),
        }
    };

    let addr = match parse_address(from_str) {
        Some(a) => a,
        None => return SwitchResult {
            success: 0,
            request_id: [0; 32],
            error_msg: CString::new("Failed to parse address").unwrap().into_raw(),
        }
    };

    let amt = match amount_str.parse::<u128>() {
        Ok(a) => U256::from(a),
        Err(_) => return SwitchResult {
            success: 0,
            request_id: [0; 32],
            error_msg: CString::new("Failed to parse amount").unwrap().into_raw(),
        }
    };

    // Generate request ID
    let request_id = H256::random();
    let mut request_id_bytes = [0u8; 32];
    request_id_bytes.copy_from_slice(request_id.as_bytes());

    // Create runtime and process
    // Use global runtime instead of creating new one
    let runtime = &*FFI_RUNTIME;

    // Create switch and process
    let config = SwitchConfig::default();
    let switch = UniversalSwitch::new(config);

    let result = runtime.block_on(async {
        match to_mode {
            1 => {
                // Switch to private
                switch.switch_to_private_with_splitting(
                    token,
                    addr,
                    amt,
                    H256::random(),
                    H256::random()
                ).await
            },
            0 => {
                // Switch to public (would need nullifier and proof)
                Err(anyhow::anyhow!("Public switch not implemented in this endpoint"))
            },
            _ => {
                Err(anyhow::anyhow!("Invalid mode: {}", to_mode))
            }
        }
    });

    match result {
        Ok(_) => SwitchResult {
            success: 1,
            request_id: request_id_bytes,
            error_msg: std::ptr::null(),
        },
        Err(e) => SwitchResult {
            success: 0,
            request_id: request_id_bytes,
            error_msg: CString::new(format!("Switch failed: {}", e)).unwrap().into_raw(),
        }
    }
}

/// Initialize Universal Switch
#[no_mangle]
pub extern "C" fn universal_switch_init(
    config_json: *const c_char,
) -> *mut UniversalSwitchHandle {
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let config: SwitchConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(_) => SwitchConfig::default(),
    };

    let switch = Arc::new(UniversalSwitch::new(config));

    Box::into_raw(Box::new(UniversalSwitchHandle { switch }))
}

/// Switch to private mode with optional splitting
#[no_mangle]
pub extern "C" fn switch_to_private_ffi(
    handle: *mut UniversalSwitchHandle,
    token_id_hex: *const c_char,
    user_hex: *const c_char,
    amount_str: *const c_char,
    use_splitting: u8,
) -> *const c_char {
    if handle.is_null() {
        return CString::new(r#"{"error": "null handle"}"#).unwrap().into_raw();
    }

    let handle = unsafe { &*handle };

    // Parse token ID
    let token_id_str = unsafe { CStr::from_ptr(token_id_hex).to_str().unwrap_or("") };
    let token_id = match parse_h256(token_id_str) {
        Some(h) => TokenId(h),
        None => return CString::new(r#"{"error": "invalid token_id"}"#).unwrap().into_raw(),
    };

    // Parse user address
    let user_str = unsafe { CStr::from_ptr(user_hex).to_str().unwrap_or("") };
    let user = match parse_address(user_str) {
        Some(addr) => addr,
        None => return CString::new(r#"{"error": "invalid user address"}"#).unwrap().into_raw(),
    };

    // Parse amount
    let amount_s = unsafe { CStr::from_ptr(amount_str).to_str().unwrap_or("0") };
    let amount = match amount_s.parse::<u128>() {
        Ok(a) => U256::from(a),
        Err(_) => return CString::new(r#"{"error": "invalid amount"}"#).unwrap().into_raw(),
    };

    // Run async code in sync context
    let result = FFI_RUNTIME.block_on(async {
        if use_splitting == 1 {
            handle.switch.switch_to_private_with_splitting(
                token_id, user, amount, H256::random(), H256::random()
            ).await
        } else {
            handle.switch.switch_to_private(
                token_id, user, amount, H256::random(), H256::random()
            ).await.map(|h| vec![h])
        }
    });

    match result {
        Ok(hashes) => {
            let hashes_hex: Vec<String> = hashes.iter()
                .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
                .collect();
            let json = serde_json::json!({
                "commitments": hashes_hex,
                "count": hashes_hex.len()
            });
            CString::new(json.to_string()).unwrap().into_raw()
        }
        Err(e) => {
            let error = format!(r#"{{"error": "{}"}}"#, e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Verify switch request for consensus
#[no_mangle]
pub extern "C" fn verify_switch_for_consensus(
    handle: *mut UniversalSwitchHandle,
    request_json: *const c_char,
    block_height: u64,
    state_root_hex: *const c_char,
) -> u8 {
    if handle.is_null() {
        return 0;
    }

    let handle = unsafe { &*handle };

    // Parse request
    let request_str = unsafe { CStr::from_ptr(request_json).to_str().unwrap_or("") };
    let request = match serde_json::from_str(request_str) {
        Ok(r) => r,
        Err(_) => return 0,
    };

    // Parse state root
    let state_root_str = unsafe { CStr::from_ptr(state_root_hex).to_str().unwrap_or("") };
    let state_root = match parse_h256(state_root_str) {
        Some(h) => h,
        None => return 0,
    };

    let result = FFI_RUNTIME.block_on(async {
        handle.switch.verify_switch_for_consensus(&request, block_height, state_root).await
    });

    match result {
        Ok(valid) => if valid { 1 } else { 0 },
        Err(_) => 0,
    }
}

/// Get unified balance
#[no_mangle]
pub extern "C" fn get_unified_balance(
    handle: *mut UniversalSwitchHandle,
    token_id_hex: *const c_char,
    user_hex: *const c_char,
) -> *const c_char {
    if handle.is_null() {
        return CString::new("0").unwrap().into_raw();
    }

    let handle = unsafe { &*handle };

    // Parse token ID
    let token_id_str = unsafe { CStr::from_ptr(token_id_hex).to_str().unwrap_or("") };
    let token_id = match parse_h256(token_id_str) {
        Some(h) => TokenId(h),
        None => return CString::new("0").unwrap().into_raw(),
    };

    // Parse user address
    let user_str = unsafe { CStr::from_ptr(user_hex).to_str().unwrap_or("") };
    let user = match parse_address(user_str) {
        Some(addr) => addr,
        None => return CString::new("0").unwrap().into_raw(),
    };

    let balance = FFI_RUNTIME.block_on(async {
        handle.switch.get_unified_balance(token_id, user).await
    });

    CString::new(balance.to_string()).unwrap().into_raw()
}

/// Register token pair
#[no_mangle]
pub extern "C" fn register_token_pair(
    handle: *mut UniversalSwitchHandle,
    public_address_hex: *const c_char,
    private_address_hex: *const c_char,
    name: *const c_char,
    symbol: *const c_char,
    decimals: u8,
    total_supply_str: *const c_char,
) -> *const c_char {
    if handle.is_null() {
        return CString::new(r#"{"error": "null handle"}"#).unwrap().into_raw();
    }

    let handle = unsafe { &*handle };

    // Parse addresses
    let public_str = unsafe { CStr::from_ptr(public_address_hex).to_str().unwrap_or("") };
    let public_address = match parse_address(public_str) {
        Some(addr) => addr,
        None => return CString::new(r#"{"error": "invalid public address"}"#).unwrap().into_raw(),
    };

    let private_str = unsafe { CStr::from_ptr(private_address_hex).to_str().unwrap_or("") };
    let private_address = match parse_address(private_str) {
        Some(addr) => addr,
        None => return CString::new(r#"{"error": "invalid private address"}"#).unwrap().into_raw(),
    };

    // Parse name and symbol
    let name_str = unsafe { CStr::from_ptr(name).to_str().unwrap_or("Unknown") };
    let symbol_str = unsafe { CStr::from_ptr(symbol).to_str().unwrap_or("UNK") };

    // Parse total supply
    let supply_str = unsafe { CStr::from_ptr(total_supply_str).to_str().unwrap_or("0") };
    let total_supply = match supply_str.parse::<u128>() {
        Ok(s) => U256::from(s),
        Err(_) => U256::zero(),
    };

    let result = FFI_RUNTIME.block_on(async {
        handle.switch.register_token_pair(
            public_address,
            private_address,
            name_str.to_string(),
            symbol_str.to_string(),
            decimals,
            total_supply,
        ).await
    });

    match result {
        Ok(token_id) => {
            let json = format!(r#"{{"token_id": "0x{}"}}"#, hex::encode(token_id.0.as_bytes()));
            CString::new(json).unwrap().into_raw()
        }
        Err(e) => {
            let error = format!(r#"{{"error": "{}"}}"#, e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Cleanup handle
#[no_mangle]
pub extern "C" fn universal_switch_cleanup(handle: *mut UniversalSwitchHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

/// Free string returned by FFI functions
#[no_mangle]
pub extern "C" fn free_ffi_string(s: *const c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s as *mut c_char);
        }
    }
}

// Helper functions
fn parse_h256(s: &str) -> Option<H256> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    Some(H256::from_slice(&bytes))
}

fn parse_address(s: &str) -> Option<Address> {
    let s = s.trim_start_matches("0x");
    if s.len() != 40 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    Some(Address::from_slice(&bytes))
}