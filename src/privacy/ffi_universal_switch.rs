//! FFI exports for Universal Switch
//! For Go integration with L1 blockchain

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};
use ethereum_types::{Address, H256, U256};
use anyhow::Result;
use super::zk_proofs::H256Ext;  // Added: for H256::random()
use serde_json;
use once_cell::sync::Lazy;

use super::universal_switch::{UniversalSwitch, SwitchConfig};
use super::common_types::{TokenId, TokenMode};

/// CRITICAL FIX: Implement isolated runtime management with proper resource control
/// Each runtime has its own thread pool and resource limits to prevent interference

/// Runtime pool configuration
struct RuntimeConfig {
    /// Maximum number of worker threads per runtime
    worker_threads: usize,
    /// Maximum number of blocking threads per runtime
    max_blocking_threads: usize,
    /// Thread stack size in bytes
    thread_stack_size: usize,
    /// Enable runtime metrics
    enable_metrics: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            // Limited threads per runtime for isolation
            worker_threads: 2,
            // Limited blocking threads to prevent resource exhaustion
            max_blocking_threads: 4,
            // 2MB stack size per thread
            thread_stack_size: 2 * 1024 * 1024,
            // Enable metrics for monitoring
            enable_metrics: true,
        }
    }
}

/// Runtime pool for isolated execution contexts
struct RuntimePool {
    /// Pool of isolated runtimes for different operation types
    runtimes: Vec<tokio::runtime::Runtime>,
    /// Current runtime index for round-robin distribution
    current_index: Mutex<usize>,
    /// Configuration for runtime creation
    config: RuntimeConfig,
}

impl RuntimePool {
    fn new(pool_size: usize, config: RuntimeConfig) -> Result<Self> {
        let mut runtimes = Vec::with_capacity(pool_size);

        for i in 0..pool_size {
            // Create isolated runtime with specific configuration
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(config.worker_threads)
                .max_blocking_threads(config.max_blocking_threads)
                .thread_stack_size(config.thread_stack_size)
                .thread_name(format!("ffi-runtime-{}", i))
                .enable_all()
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to create runtime {}: {}", i, e))?;

            runtimes.push(runtime);
        }

        Ok(Self {
            runtimes,
            current_index: Mutex::new(0),
            config,
        })
    }

    /// Get next runtime in round-robin fashion for load distribution
    fn get_runtime(&self) -> &tokio::runtime::Runtime {
        let mut index = self.current_index.lock().unwrap();
        let runtime = &self.runtimes[*index];
        *index = (*index + 1) % self.runtimes.len();
        runtime
    }

    /// Get dedicated runtime for critical operations
    fn get_critical_runtime(&self) -> &tokio::runtime::Runtime {
        // Always use the first runtime for critical operations
        // This ensures consistent performance for important tasks
        &self.runtimes[0]
    }
}

/// Isolated runtime pools for different operation types
static RUNTIME_POOLS: Lazy<RuntimePoolManager> = Lazy::new(|| {
    RuntimePoolManager::new().expect("Failed to initialize runtime pools - this is fatal")
});

/// Manager for multiple runtime pools with different isolation levels
struct RuntimePoolManager {
    /// Pool for normal switch operations
    switch_pool: RuntimePool,
    /// Pool for critical consensus operations
    consensus_pool: RuntimePool,
    /// Pool for background maintenance tasks
    maintenance_pool: RuntimePool,
}

impl RuntimePoolManager {
    fn new() -> Result<Self> {
        Ok(Self {
            // 4 runtimes for switch operations
            switch_pool: RuntimePool::new(4, RuntimeConfig::default())?,

            // 2 dedicated runtimes for critical consensus operations
            consensus_pool: RuntimePool::new(2, RuntimeConfig {
                worker_threads: 4,  // More threads for consensus
                max_blocking_threads: 2,  // Less blocking for consensus
                thread_stack_size: 4 * 1024 * 1024,  // Larger stack for consensus
                enable_metrics: true,
            })?,

            // 1 runtime for background tasks
            maintenance_pool: RuntimePool::new(1, RuntimeConfig {
                worker_threads: 1,  // Single thread for maintenance
                max_blocking_threads: 8,  // More blocking allowed
                thread_stack_size: 1024 * 1024,  // Smaller stack
                enable_metrics: false,
            })?,
        })
    }

    /// Get appropriate runtime based on operation type
    fn get_runtime_for_operation(&self, operation_type: OperationType) -> &tokio::runtime::Runtime {
        match operation_type {
            OperationType::Switch => self.switch_pool.get_runtime(),
            OperationType::Consensus => self.consensus_pool.get_critical_runtime(),
            OperationType::Maintenance => self.maintenance_pool.get_runtime(),
        }
    }
}

/// Operation types for runtime selection
enum OperationType {
    Switch,
    Consensus,
    Maintenance,
}

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

    // CRITICAL FIX: Use isolated runtime from pool for better resource management
    // Select appropriate runtime based on operation type
    let runtime = RUNTIME_POOLS.get_runtime_for_operation(OperationType::Switch);

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

    // Run async code in sync context using isolated runtime
    let runtime = RUNTIME_POOLS.get_runtime_for_operation(OperationType::Switch);
    let result = runtime.block_on(async {
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

    // Use consensus-specific runtime for verification
    let runtime = RUNTIME_POOLS.get_runtime_for_operation(OperationType::Consensus);
    let result = runtime.block_on(async {
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

    // Use switch runtime for balance queries
    let runtime = RUNTIME_POOLS.get_runtime_for_operation(OperationType::Switch);
    let balance = runtime.block_on(async {
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

    // Use maintenance runtime for token registration
    let runtime = RUNTIME_POOLS.get_runtime_for_operation(OperationType::Maintenance);
    let result = runtime.block_on(async {
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