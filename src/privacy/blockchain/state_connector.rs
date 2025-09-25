//! Blockchain State Connector
//!
//! Connects privacy module to main blockchain state

use anyhow::{Result, anyhow};
use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

// Import from parent modules
use crate::state::GlobalState;
use crate::fees_usd::{USDFeeSystem, TransactionFeeType};
use crate::transaction_v2::{TokenId, TokenMode};

/// State connector for blockchain integration
pub struct StateConnector {
    /// Global state reference
    global_state: Arc<RwLock<GlobalState>>,
    /// Fee system reference
    fee_system: Arc<RwLock<USDFeeSystem>>,
    /// Privacy root in global state
    privacy_root_key: H256,
    /// Lock contract address
    lock_contract: Address,
    /// Privacy token contracts
    privacy_contracts: Arc<RwLock<HashMap<TokenId, PrivacyContract>>>,
    /// Event listeners
    event_listeners: Arc<RwLock<Vec<Box<dyn EventListener>>>>,
    /// State cache for performance
    state_cache: Arc<RwLock<StateCache>>,
}

/// Privacy contract information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyContract {
    pub token_id: TokenId,
    pub contract_address: Address,
    pub merkle_root: H256,
    pub total_locked: U256,
    pub total_shielded: U256,
    pub nullifier_count: u64,
    pub commitment_count: u64,
}

/// State cache for performance
#[derive(Debug, Clone)]
struct StateCache {
    /// Cached balances
    balances: HashMap<(Address, TokenId), U256>,
    /// Cached roots
    merkle_roots: HashMap<TokenId, H256>,
    /// Cache timestamp
    last_update: u64,
    /// Cache duration (blocks)
    cache_duration: u64,
}

impl StateCache {
    fn new() -> Self {
        Self {
            balances: HashMap::new(),
            merkle_roots: HashMap::new(),
            last_update: 0,
            cache_duration: 10, // Cache for 10 blocks
        }
    }

    fn is_valid(&self, current_block: u64) -> bool {
        current_block - self.last_update < self.cache_duration
    }

    fn invalidate(&mut self) {
        self.balances.clear();
        self.merkle_roots.clear();
        self.last_update = 0;
    }
}

/// Event listener trait
pub trait EventListener: Send + Sync {
    fn on_lock(&self, token_id: TokenId, owner: Address, amount: U256);
    fn on_unlock(&self, token_id: TokenId, recipient: Address, amount: U256);
    fn on_root_update(&self, token_id: TokenId, new_root: H256);
}

impl StateConnector {
    /// Create new state connector
    pub fn new(
        global_state: Arc<RwLock<GlobalState>>,
        fee_system: Arc<RwLock<USDFeeSystem>>,
    ) -> Self {
        Self {
            global_state,
            fee_system,
            privacy_root_key: H256::from_slice(b"PRIVACY_STATE_ROOT_KEY_V1_______"),
            lock_contract: Self::derive_lock_contract_address(),
            privacy_contracts: Arc::new(RwLock::new(HashMap::new())),
            event_listeners: Arc::new(RwLock::new(Vec::new())),
            state_cache: Arc::new(RwLock::new(StateCache::new())),
        }
    }
    
    /// Derive deterministic lock contract address
    fn derive_lock_contract_address() -> Address {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"QORANET_PRIVACY_LOCK_CONTRACT_V1");
        Address::from_slice(&hasher.finalize()[12..])
    }
    
    /// Initialize privacy contract for token
    pub async fn initialize_privacy_contract(
        &self,
        token_id: TokenId,
        contract_address: Address,
    ) -> Result<()> {
        let mut contracts = self.privacy_contracts.write().await;
        
        if contracts.contains_key(&token_id) {
            return Err(anyhow!("Privacy contract already initialized"));
        }
        
        let contract = PrivacyContract {
            token_id,
            contract_address,
            merkle_root: H256::zero(),
            total_locked: U256::zero(),
            total_shielded: U256::zero(),
            nullifier_count: 0,
            commitment_count: 0,
        };
        
        contracts.insert(token_id, contract);
        
        // Deploy contract code
        self.deploy_privacy_contract_code(contract_address).await?;
        
        Ok(())
    }
    
    /// Deploy privacy contract bytecode
    async fn deploy_privacy_contract_code(&self, address: Address) -> Result<()> {
        let state = self.global_state.write().await;
        
        // Generate minimal privacy contract bytecode
        // In production, this would be actual compiled contract code
        let bytecode = self.generate_privacy_contract_bytecode();
        
        state.set_code(address, bytecode)?;
        
        Ok(())
    }
    
    /// Generate privacy contract bytecode
    fn generate_privacy_contract_bytecode(&self) -> Vec<u8> {
        // Simplified bytecode generation
        // In production, use actual compiled Solidity/Vyper contract
        vec![
            0x60, 0x80, 0x60, 0x40, // Standard prefix
            0x52, 0x34, 0x80, 0x15, // Constructor check
            // ... more bytecode
        ]
    }
    
    /// Lock tokens in contract for privacy pool
    pub async fn lock_tokens(
        &self,
        token_id: TokenId,
        owner: Address,
        amount: U256,
    ) -> Result<H256> {
        // Validate amount
        if amount == U256::zero() {
            return Err(anyhow!("Cannot lock zero amount"));
        }
        
        let state = self.global_state.write().await;
        let mut contracts = self.privacy_contracts.write().await;
        
        let contract = contracts.get_mut(&token_id)
            .ok_or_else(|| anyhow!("Privacy contract not found"))?;
        
        // Check balance
        let balance = self.get_token_balance(&state, token_id, owner).await?;
        if balance < amount {
            return Err(anyhow!("Insufficient balance: have {}, need {}", balance, amount));
        }
        
        // Transfer tokens to lock contract
        self.transfer_tokens(&state, token_id, owner, contract.contract_address, amount).await?;
        
        // Update contract state with overflow protection
        contract.total_locked = contract.total_locked
            .checked_add(amount)
            .ok_or_else(|| anyhow!("Total locked amount overflow"))?;
        
        // Record lock in contract storage
        let lock_key = self.compute_lock_key(token_id, owner);
        let current_locked = self.get_storage_u256(&state, contract.contract_address, lock_key).await;
        let new_locked = current_locked + amount;
        self.set_storage_u256(&state, contract.contract_address, lock_key, new_locked).await?;
        
        // Emit event
        let tx_hash = self.emit_lock_event(token_id, owner, amount).await?;
        
        // Notify listeners
        self.notify_lock_listeners(token_id, owner, amount).await;
        
        // Invalidate cache
        self.state_cache.write().await.invalidate();
        
        Ok(tx_hash)
    }
    
    /// Release tokens from contract
    pub async fn release_tokens(
        &self,
        token_id: TokenId,
        recipient: Address,
        amount: U256,
        proof: Vec<u8>,
    ) -> Result<H256> {
        // Validate amount
        if amount == U256::zero() {
            return Err(anyhow!("Cannot release zero amount"));
        }
        
        // Verify proof (simplified - in production, verify actual ZK proof)
        if proof.len() < 192 {
            return Err(anyhow!("Invalid proof"));
        }
        
        let state = self.global_state.write().await;
        let mut contracts = self.privacy_contracts.write().await;
        
        let contract = contracts.get_mut(&token_id)
            .ok_or_else(|| anyhow!("Privacy contract not found"))?;
        
        // Check contract has enough locked balance
        if contract.total_locked < amount {
            return Err(anyhow!("Insufficient locked balance"));
        }
        
        // Transfer tokens from contract to recipient
        self.transfer_tokens(&state, token_id, contract.contract_address, recipient, amount).await?;
        
        // Update contract state
        contract.total_locked -= amount;
        contract.total_shielded = contract.total_shielded.saturating_sub(amount);
        
        // Update lock record
        let lock_key = self.compute_lock_key(token_id, recipient);
        let current_locked = self.get_storage_u256(&state, contract.contract_address, lock_key).await;
        let new_locked = current_locked.saturating_sub(amount);
        self.set_storage_u256(&state, contract.contract_address, lock_key, new_locked).await?;
        
        // Emit event
        let tx_hash = self.emit_unlock_event(token_id, recipient, amount).await?;
        
        // Notify listeners
        self.notify_unlock_listeners(token_id, recipient, amount).await;
        
        // Invalidate cache
        self.state_cache.write().await.invalidate();
        
        Ok(tx_hash)
    }
    
    /// Update privacy state root for token
    pub async fn update_privacy_root(
        &self,
        token_id: TokenId,
        new_root: H256,
        commitments_added: u64,
        nullifiers_added: u64,
    ) -> Result<()> {
        let mut contracts = self.privacy_contracts.write().await;
        
        let contract = contracts.get_mut(&token_id)
            .ok_or_else(|| anyhow!("Privacy contract not found"))?;
        
        // Update contract state
        contract.merkle_root = new_root;
        contract.commitment_count += commitments_added;
        contract.nullifier_count += nullifiers_added;
        
        // Store in global state
        let state = self.global_state.write().await;
        let root_key = self.compute_root_key(token_id);
        state.set_storage(contract.contract_address, root_key, new_root)?;
        
        // Store metadata
        let metadata_key = self.compute_metadata_key(token_id);
        let metadata = self.encode_metadata(contract.commitment_count, contract.nullifier_count);
        state.set_storage(contract.contract_address, metadata_key, metadata)?;
        
        // Notify listeners
        self.notify_root_update_listeners(token_id, new_root).await;
        
        Ok(())
    }
    
    /// Get current privacy root for token
    pub async fn get_privacy_root(&self, token_id: TokenId) -> Result<H256> {
        // Check cache first
        {
            let cache = self.state_cache.read().await;
            if let Some(&root) = cache.merkle_roots.get(&token_id) {
                let current_block = self.get_current_block().await?;
                if cache.is_valid(current_block) {
                    return Ok(root);
                }
            }
        }
        
        // Load from state
        let contracts = self.privacy_contracts.read().await;
        let contract = contracts.get(&token_id)
            .ok_or_else(|| anyhow!("Privacy contract not found"))?;
        
        let state = self.global_state.read().await;
        let root_key = self.compute_root_key(token_id);
        let root = state.get_storage(contract.contract_address, root_key);
        
        // Update cache
        let mut cache = self.state_cache.write().await;
        cache.merkle_roots.insert(token_id, root);
        cache.last_update = self.get_current_block().await?;
        
        Ok(root)
    }
    
    /// Shield tokens (convert to private)
    pub async fn shield_tokens(
        &self,
        token_id: TokenId,
        owner: Address,
        amount: U256,
        commitment: H256,
    ) -> Result<()> {
        let mut contracts = self.privacy_contracts.write().await;
        
        let contract = contracts.get_mut(&token_id)
            .ok_or_else(|| anyhow!("Privacy contract not found"))?;
        
        // Lock tokens first
        self.lock_tokens(token_id, owner, amount).await?;
        
        // Update shielded amount with overflow protection
        contract.total_shielded = contract.total_shielded
            .checked_add(amount)
            .ok_or_else(|| anyhow!("Total shielded amount overflow"))?;
        contract.commitment_count = contract.commitment_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("Commitment count overflow"))?;
        
        // Store commitment
        let state = self.global_state.write().await;
        let commitment_key = self.compute_commitment_key(token_id, contract.commitment_count);
        state.set_storage(contract.contract_address, commitment_key, commitment)?;
        
        Ok(())
    }
    
    /// Process nullifier (mark as spent)
    pub async fn process_nullifier(
        &self,
        token_id: TokenId,
        nullifier: H256,
    ) -> Result<()> {
        let contracts = self.privacy_contracts.read().await;
        
        let contract = contracts.get(&token_id)
            .ok_or_else(|| anyhow!("Privacy contract not found"))?;
        
        let state = self.global_state.write().await;
        
        // Check if nullifier already exists
        let nullifier_key = self.compute_nullifier_key(nullifier);
        let existing = state.get_storage(contract.contract_address, nullifier_key);
        
        if existing != H256::zero() {
            return Err(anyhow!("Nullifier already spent"));
        }
        
        // Mark nullifier as spent
        state.set_storage(
            contract.contract_address,
            nullifier_key,
            H256::from_low_u64_be(1),
        )?;
        
        Ok(())
    }
    
    /// Get locked balance for address
    pub async fn get_locked_balance(
        &self,
        token_id: TokenId,
        owner: Address,
    ) -> Result<U256> {
        let contracts = self.privacy_contracts.read().await;
        
        let contract = contracts.get(&token_id)
            .ok_or_else(|| anyhow!("Privacy contract not found"))?;
        
        let state = self.global_state.read().await;
        let lock_key = self.compute_lock_key(token_id, owner);
        
        Ok(self.get_storage_u256(&state, contract.contract_address, lock_key).await)
    }
    
    /// Get privacy contract info
    pub async fn get_privacy_contract(&self, token_id: TokenId) -> Option<PrivacyContract> {
        self.privacy_contracts.read().await.get(&token_id).cloned()
    }
    
    /// Add event listener
    pub async fn add_listener(&self, listener: Box<dyn EventListener>) {
        self.event_listeners.write().await.push(listener);
    }
    
    // Helper methods
    
    /// Compute storage key for locks
    fn compute_lock_key(&self, token_id: TokenId, owner: Address) -> H256 {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"LOCK_");
        hasher.update(token_id.0.as_bytes());
        hasher.update(owner.as_bytes());
        H256::from_slice(&hasher.finalize())
    }
    
    /// Compute storage key for root
    fn compute_root_key(&self, token_id: TokenId) -> H256 {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"ROOT_");
        hasher.update(token_id.0.as_bytes());
        H256::from_slice(&hasher.finalize())
    }
    
    /// Compute storage key for commitment
    fn compute_commitment_key(&self, token_id: TokenId, index: u64) -> H256 {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"COMMIT_");
        hasher.update(token_id.0.as_bytes());
        hasher.update(&index.to_le_bytes());
        H256::from_slice(&hasher.finalize())
    }
    
    /// Compute storage key for nullifier
    fn compute_nullifier_key(&self, nullifier: H256) -> H256 {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"NULL_");
        hasher.update(nullifier.as_bytes());
        H256::from_slice(&hasher.finalize())
    }
    
    /// Compute metadata key
    fn compute_metadata_key(&self, token_id: TokenId) -> H256 {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"META_");
        hasher.update(token_id.0.as_bytes());
        H256::from_slice(&hasher.finalize())
    }
    
    /// Encode metadata
    fn encode_metadata(&self, commitments: u64, nullifiers: u64) -> H256 {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&commitments.to_le_bytes());
        bytes[8..16].copy_from_slice(&nullifiers.to_le_bytes());
        H256::from(bytes)
    }
    
    /// Get token balance
    async fn get_token_balance(
        &self,
        state: &GlobalState,
        token_id: TokenId,
        owner: Address,
    ) -> Result<U256> {
        // Check cache
        {
            let cache = self.state_cache.read().await;
            if let Some(&balance) = cache.balances.get(&(owner, token_id)) {
                let current_block = self.get_current_block().await?;
                if cache.is_valid(current_block) {
                    return Ok(balance);
                }
            }
        }
        
        // In production, this would read from token contract
        // For now, use simplified balance tracking
        let balance_key = self.compute_balance_key(token_id, owner);
        let balance = self.get_storage_u256(state, token_id.0.into(), balance_key).await;
        
        // Update cache
        let mut cache = self.state_cache.write().await;
        cache.balances.insert((owner, token_id), balance);
        
        Ok(balance)
    }
    
    /// Compute balance key
    fn compute_balance_key(&self, token_id: TokenId, owner: Address) -> H256 {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(owner.as_bytes());
        hasher.update(&[0u8; 32]); // Slot 0 for balances
        H256::from_slice(&hasher.finalize())
    }
    
    /// Transfer tokens
    async fn transfer_tokens(
        &self,
        state: &GlobalState,
        token_id: TokenId,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<()> {
        // Update from balance
        let from_key = self.compute_balance_key(token_id, from);
        let from_balance = self.get_storage_u256(state, token_id.0.into(), from_key).await;
        
        if from_balance < amount {
            return Err(anyhow!("Insufficient balance for transfer"));
        }
        
        let new_from_balance = from_balance - amount;
        self.set_storage_u256(state, token_id.0.into(), from_key, new_from_balance).await?;
        
        // Update to balance with overflow protection
        let to_key = self.compute_balance_key(token_id, to);
        let to_balance = self.get_storage_u256(state, token_id.0.into(), to_key).await;
        let new_to_balance = to_balance.checked_add(amount)
            .ok_or_else(|| anyhow!("Balance overflow detected"))?;
        self.set_storage_u256(state, token_id.0.into(), to_key, new_to_balance).await?;
        
        Ok(())
    }
    
    /// Get U256 from storage
    async fn get_storage_u256(&self, state: &GlobalState, address: Address, key: H256) -> U256 {
        let value = state.get_storage(address, key);
        U256::from_big_endian(value.as_bytes())
    }
    
    /// Set U256 in storage
    async fn set_storage_u256(
        &self,
        state: &GlobalState,
        address: Address,
        key: H256,
        value: U256,
    ) -> Result<()> {
        let mut bytes = [0u8; 32];
        value.to_big_endian(&mut bytes);
        state.set_storage(address, key, H256::from(bytes))
    }
    
    /// Get current block number
    async fn get_current_block(&self) -> Result<u64> {
        Ok(self.global_state.read().await.get_block_number())
    }
    
    /// Emit lock event
    async fn emit_lock_event(
        &self,
        token_id: TokenId,
        owner: Address,
        amount: U256,
    ) -> Result<H256> {
        // Generate event hash
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"Lock(address,uint256)");
        hasher.update(owner.as_bytes());
        let mut amount_bytes = [0u8; 32];
        amount.to_big_endian(&mut amount_bytes);
        hasher.update(&amount_bytes);
        
        Ok(H256::from_slice(&hasher.finalize()))
    }
    
    /// Emit unlock event
    async fn emit_unlock_event(
        &self,
        token_id: TokenId,
        recipient: Address,
        amount: U256,
    ) -> Result<H256> {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(b"Unlock(address,uint256)");
        hasher.update(recipient.as_bytes());
        let mut amount_bytes = [0u8; 32];
        amount.to_big_endian(&mut amount_bytes);
        hasher.update(&amount_bytes);
        
        Ok(H256::from_slice(&hasher.finalize()))
    }
    
    /// Notify lock listeners
    async fn notify_lock_listeners(&self, token_id: TokenId, owner: Address, amount: U256) {
        let listeners = self.event_listeners.read().await;
        for listener in listeners.iter() {
            listener.on_lock(token_id, owner, amount);
        }
    }
    
    /// Notify unlock listeners
    async fn notify_unlock_listeners(&self, token_id: TokenId, recipient: Address, amount: U256) {
        let listeners = self.event_listeners.read().await;
        for listener in listeners.iter() {
            listener.on_unlock(token_id, recipient, amount);
        }
    }
    
    /// Notify root update listeners
    async fn notify_root_update_listeners(&self, token_id: TokenId, new_root: H256) {
        let listeners = self.event_listeners.read().await;
        for listener in listeners.iter() {
            listener.on_root_update(token_id, new_root);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::GlobalState;
    use crate::fees_usd::{USDFeeSystem, FeeConfig};
    use crate::transaction_v2::TokenId;
    
    #[tokio::test]
    async fn test_state_connector_creation() {
        let global_state = Arc::new(tokio::sync::RwLock::new(GlobalState::new()));
        let fee_system = Arc::new(tokio::sync::RwLock::new(USDFeeSystem::new(FeeConfig::default())));
        let connector = StateConnector::new(global_state, fee_system);
        
        assert_eq!(connector.privacy_contracts.read().await.len(), 0);
    }
    
    #[tokio::test]
    async fn test_privacy_contract_initialization() {
        let global_state = Arc::new(tokio::sync::RwLock::new(GlobalState::new()));
        let fee_system = Arc::new(tokio::sync::RwLock::new(USDFeeSystem::new(FeeConfig::default())));
        let connector = StateConnector::new(global_state, fee_system);
        
        let token_id = TokenId(H256::random());
        let contract_address = Address::random();
        
        connector.initialize_privacy_contract(token_id, contract_address).await.unwrap();
        
        let contract = connector.get_privacy_contract(token_id).await;
        assert!(contract.is_some());
    }
}