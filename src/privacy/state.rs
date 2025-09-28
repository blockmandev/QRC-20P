//! Global State Management for QoraNet
//!
//! Manages blockchain state including accounts, storage, and code

use anyhow::{Result, anyhow};
use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::ops::Drop;

/// Global blockchain state
#[derive(Debug, Clone)]
pub struct GlobalState {
    /// Account states
    accounts: Arc<RwLock<HashMap<Address, AccountState>>>,
    /// Contract storage
    storage: Arc<RwLock<HashMap<(Address, H256), H256>>>,
    /// Contract code
    code: Arc<RwLock<HashMap<Address, Vec<u8>>>>,
    /// Block context
    block_context: Arc<RwLock<BlockContext>>,
    /// Reentrancy guard
    reentrancy_guard: Arc<parking_lot::Mutex<bool>>,
}

/// Account state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: H256,
    pub storage_root: H256,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            balance: U256::zero(),
            nonce: 0,
            code_hash: H256::from_slice(&[0u8; 32]),
            storage_root: H256::from_slice(&[0u8; 32]),
        }
    }
}

/// Block context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContext {
    pub block_number: u64,
    pub timestamp: u64,
    pub block_hash: H256,
    pub coinbase: Address,
    pub gas_limit: u64,
    pub base_fee: U256,
}

impl GlobalState {
    /// Create new global state
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            storage: Arc::new(RwLock::new(HashMap::new())),
            code: Arc::new(RwLock::new(HashMap::new())),
            block_context: Arc::new(RwLock::new(BlockContext {
                block_number: 0,
                timestamp: 0,
                block_hash: H256::zero(),
                coinbase: Address::zero(),
                gas_limit: 30_000_000,
                base_fee: U256::from(1_000_000_000), // 1 gwei
            })),
            reentrancy_guard: Arc::new(parking_lot::Mutex::new(false)),
        }
    }
    
    /// Get account state
    pub fn get_account(&self, address: Address) -> AccountState {
        self.accounts.read()
            .get(&address)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Set account balance
    pub fn set_balance(&self, address: Address, balance: U256) -> Result<()> {
        let mut accounts = self.accounts.write();
        let account = accounts.entry(address).or_default();
        account.balance = balance;
        Ok(())
    }
    
    /// Get balance
    pub fn get_balance(&self, address: Address) -> U256 {
        self.get_account(address).balance
    }
    
    /// Increment nonce
    pub fn increment_nonce(&self, address: Address) -> Result<u64> {
        let mut accounts = self.accounts.write();
        let account = accounts.entry(address).or_default();
        account.nonce += 1;
        Ok(account.nonce)
    }
    
    /// Get nonce
    pub fn get_nonce(&self, address: Address) -> u64 {
        self.get_account(address).nonce
    }
    
    /// Set contract code
    pub fn set_code(&self, address: Address, code: Vec<u8>) -> Result<()> {
        use sha3::{Digest, Keccak256};
        
        if code.is_empty() {
            return Err(anyhow!("Cannot set empty code"));
        }
        
        // Calculate code hash
        let mut hasher = Keccak256::default();
        hasher.update(&code);
        let code_hash = H256::from_slice(&hasher.finalize());
        
        // Store code
        self.code.write().insert(address, code);
        
        // Update account
        let mut accounts = self.accounts.write();
        let account = accounts.entry(address).or_default();
        account.code_hash = code_hash;
        
        Ok(())
    }
    
    /// Get contract code
    pub fn get_code(&self, address: Address) -> Vec<u8> {
        self.code.read()
            .get(&address)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Set storage value
    pub fn set_storage(&self, address: Address, key: H256, value: H256) -> Result<()> {
        self.storage.write().insert((address, key), value);
        Ok(())
    }
    
    /// Get storage value
    pub fn get_storage(&self, address: Address, key: H256) -> H256 {
        self.storage.read()
            .get(&(address, key))
            .copied()
            .unwrap_or_default()
    }
    
    /// Transfer value between accounts with RAII guard
    pub fn transfer(&self, from: Address, to: Address, value: U256) -> Result<()> {
        // Use RAII guard that automatically releases on drop
        let _guard = ReentrancyGuard::acquire(&self.reentrancy_guard)?;

        // Perform transfer in protected scope
        let mut accounts = self.accounts.write();

        // Check sender balance
        let sender = accounts.entry(from).or_default();
        if sender.balance < value {
            return Err(anyhow!("Insufficient balance"));
        }

        // Use checked arithmetic to prevent underflow
        sender.balance = sender.balance.checked_sub(value)
            .ok_or_else(|| anyhow!("Underflow in sender balance"))?;

        // Add to receiver with overflow check
        let receiver = accounts.entry(to).or_default();
        receiver.balance = receiver.balance.checked_add(value)
            .ok_or_else(|| anyhow!("Overflow in receiver balance"))?;

        Ok(())
        // Guard automatically released when _guard goes out of scope
    }
    
    /// Update block context
    pub fn update_block_context(
        &self,
        block_number: u64,
        timestamp: u64,
        block_hash: H256,
        coinbase: Address,
    ) -> Result<()> {
        let mut context = self.block_context.write();
        context.block_number = block_number;
        context.timestamp = timestamp;
        context.block_hash = block_hash;
        context.coinbase = coinbase;
        Ok(())
    }
    
    /// Get current block number
    pub fn get_block_number(&self) -> u64 {
        self.block_context.read().block_number
    }
    
    /// Create checkpoint for rollback
    pub fn checkpoint(&self) -> StateCheckpoint {
        StateCheckpoint {
            accounts: self.accounts.read().clone(),
            storage: self.storage.read().clone(),
            code: self.code.read().clone(),
            block_context: self.block_context.read().clone(),
        }
    }
    
    /// Restore from checkpoint
    pub fn restore(&self, checkpoint: StateCheckpoint) {
        *self.accounts.write() = checkpoint.accounts;
        *self.storage.write() = checkpoint.storage;
        *self.code.write() = checkpoint.code;
        *self.block_context.write() = checkpoint.block_context;
    }
    
    /// Clear all state
    pub fn clear(&self) {
        self.accounts.write().clear();
        self.storage.write().clear();
        self.code.write().clear();
    }
    
    /// Check if account exists
    pub fn account_exists(&self, address: Address) -> bool {
        self.accounts.read().contains_key(&address)
    }
    
    /// Check if account is contract
    pub fn is_contract(&self, address: Address) -> bool {
        self.code.read().contains_key(&address)
    }
}

/// RAII guard for reentrancy protection
struct ReentrancyGuard<'a> {
    lock: parking_lot::MutexGuard<'a, bool>,
}

impl<'a> ReentrancyGuard<'a> {
    /// Acquire the guard, returning error if reentrancy detected
    fn acquire(mutex: &'a Arc<parking_lot::Mutex<bool>>) -> Result<Self> {
        let mut lock = mutex.lock();
        if *lock {
            return Err(anyhow!("Reentrancy detected!"));
        }
        *lock = true;
        Ok(Self { lock })
    }
}

impl<'a> Drop for ReentrancyGuard<'a> {
    fn drop(&mut self) {
        // Always release the lock when guard is dropped
        // This ensures the lock is released even if the function panics
        *self.lock = false;
    }
}

/// State checkpoint for rollback
#[derive(Clone)]
pub struct StateCheckpoint {
    accounts: HashMap<Address, AccountState>,
    storage: HashMap<(Address, H256), H256>,
    code: HashMap<Address, Vec<u8>>,
    block_context: BlockContext,
}

/// State diff for tracking changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    pub balance_changes: HashMap<Address, (U256, U256)>,
    pub nonce_changes: HashMap<Address, (u64, u64)>,
    pub storage_changes: HashMap<(Address, H256), (H256, H256)>,
    pub code_changes: HashMap<Address, Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_balance_operations() {
        let state = GlobalState::new();
        let addr = Address::random();
        
        state.set_balance(addr, U256::from(1000)).unwrap();
        assert_eq!(state.get_balance(addr), U256::from(1000));
    }
    
    #[test]
    fn test_transfer() {
        let state = GlobalState::new();
        let from = Address::random();
        let to = Address::random();
        
        state.set_balance(from, U256::from(1000)).unwrap();
        state.transfer(from, to, U256::from(300)).unwrap();
        
        assert_eq!(state.get_balance(from), U256::from(700));
        assert_eq!(state.get_balance(to), U256::from(300));
    }
}