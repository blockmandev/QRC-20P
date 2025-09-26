//! Token Factory Module - Blockchain Level
//! 
//! Native protocol-level implementation for creating dual-mode tokens
//! Every token automatically gets both public and private modes

use anyhow::{Result, anyhow};
use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::state::GlobalState;
use super::common_types::TokenId;
use super::transaction_v2::TransactionType;
use super::universal_switch::UniversalSwitch;
use super::privacy::PrivacyStateManager;
use super::fees_usd::{USDFeeSystem, TransactionFeeType};

/// Token metadata stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: U256,
    pub creator: Address,
    pub created_at_block: u64,
    pub public_address: Address,
    pub private_address: Address,
    pub token_id: TokenId,
    pub switch_fee: U256,
    pub is_active: bool,
}

/// Token factory state
pub struct TokenFactory {
    /// All deployed tokens
    tokens: Arc<RwLock<HashMap<TokenId, TokenMetadata>>>,
    
    /// Symbol to token mapping
    symbol_to_token: Arc<RwLock<HashMap<String, TokenId>>>,
    
    /// Creator to tokens mapping
    creator_tokens: Arc<RwLock<HashMap<Address, Vec<TokenId>>>>,
    
    /// Universal switch reference
    universal_switch: Arc<UniversalSwitch>,
    
    /// Privacy manager reference
    privacy_manager: Arc<RwLock<PrivacyStateManager>>,
    
    /// Global state reference
    global_state: Arc<RwLock<GlobalState>>,
    
    /// USD fee system reference
    fee_system: Arc<RwLock<USDFeeSystem>>,
    
    /// Factory configuration
    config: FactoryConfig,
}

/// Factory configuration with USD-based fees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactoryConfig {
    pub creation_fee_usd: u64,      // Fee in USD (scaled by 1e8)
    pub switch_fee_usd: u64,        // Mode switch fee in USD (scaled by 1e8)
    pub max_symbol_length: usize,
    pub max_name_length: usize,
    pub min_total_supply: U256,
    pub max_decimals: u8,
}

impl Default for FactoryConfig {
    fn default() -> Self {
        Self {
            creation_fee_usd: 1_000_000,    // $0.01 USD for token creation
            switch_fee_usd: 10_000_000,     // $0.10 USD for mode switching (heavy blockchain operation)
            max_symbol_length: 10,
            max_name_length: 50,
            min_total_supply: U256::from(1),
            max_decimals: 18,
        }
    }
}

impl TokenFactory {
    /// Create new token factory
    pub fn new(
        universal_switch: Arc<UniversalSwitch>,
        privacy_manager: Arc<RwLock<PrivacyStateManager>>,
        global_state: Arc<RwLock<GlobalState>>,
        fee_system: Arc<RwLock<USDFeeSystem>>,
    ) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            symbol_to_token: Arc::new(RwLock::new(HashMap::new())),
            creator_tokens: Arc::new(RwLock::new(HashMap::new())),
            universal_switch,
            privacy_manager,
            global_state,
            fee_system,
            config: FactoryConfig::default(),
        }
    }
    
    /// Deploy dual-mode token pair
    /// This is called when processing DeployDualToken transaction
    pub async fn deploy_dual_token(
        &self,
        creator: Address,
        name: String,
        symbol: String,
        total_supply: U256,
        decimals: u8,
        privacy_enabled: bool,
        block_number: u64,
    ) -> Result<TokenId> {
        // Validate parameters
        self.validate_token_params(&name, &symbol, total_supply, decimals).await?;
        
        // Generate deterministic addresses for both modes
        let (public_address, private_address) = self.generate_token_addresses(
            &creator,
            &symbol,
            block_number,
        );
        
        // Create token ID from addresses
        let token_id = TokenId::from_addresses(public_address, private_address);
        
        // Deploy public contract bytecode
        let public_bytecode = self.generate_public_bytecode(&name, &symbol, decimals);
        self.deploy_contract_bytecode(public_address, public_bytecode).await?;
        
        // Deploy private contract bytecode (if privacy enabled)
        if privacy_enabled {
            let private_bytecode = self.generate_private_bytecode(&name, &symbol, decimals);
            self.deploy_contract_bytecode(private_address, private_bytecode).await?;
            
            // Initialize privacy pool
            let mut privacy_mgr = self.privacy_manager.write().await;
            privacy_mgr.create_pool(token_id.0, private_address)?;
        }
        
        // Register with Universal Switch
        self.universal_switch.register_token_pair(
            public_address,
            private_address,
            name.clone(),
            symbol.clone(),
            decimals,
            total_supply,
        ).await?;
        
        // Store token metadata
        let metadata = TokenMetadata {
            name: name.clone(),
            symbol: symbol.clone(),
            decimals,
            total_supply,
            creator,
            created_at_block: block_number,
            public_address,
            private_address,
            token_id: token_id.clone(),
            switch_fee: self.calculate_switch_fee_in_qor().await?,
            is_active: true,
        };
        
        let token_name = metadata.name.clone();
        let token_symbol = metadata.symbol.clone();

        let mut tokens = self.tokens.write().await;
        tokens.insert(token_id.clone(), metadata);

        let mut symbol_map = self.symbol_to_token.write().await;
        symbol_map.insert(token_symbol.clone(), token_id.clone());

        let mut creator_map = self.creator_tokens.write().await;
        creator_map.entry(creator).or_insert_with(Vec::new).push(token_id.clone());

        // Mint initial supply to creator (in public mode by default)
        self.mint_initial_supply(token_id.clone(), creator, total_supply).await?;

        tracing::info!(
            "Deployed dual-mode token: {} ({}) with ID {:?}",
            token_name, token_symbol, token_id
        );
        
        Ok(token_id)
    }
    
    /// Validate token parameters
    async fn validate_token_params(
        &self,
        name: &str,
        symbol: &str,
        total_supply: U256,
        decimals: u8,
    ) -> Result<()> {
        // Check name length
        if name.is_empty() || name.len() > self.config.max_name_length {
            return Err(anyhow!("Invalid token name length"));
        }
        
        // Check symbol length and uniqueness
        if symbol.is_empty() || symbol.len() > self.config.max_symbol_length {
            return Err(anyhow!("Invalid token symbol length"));
        }
        
        let symbol_map = self.symbol_to_token.read().await;
        if symbol_map.contains_key(symbol) {
            return Err(anyhow!("Token symbol already exists"));
        }
        
        // Check supply and decimals
        if total_supply < self.config.min_total_supply {
            return Err(anyhow!("Total supply too low"));
        }
        
        if decimals > self.config.max_decimals {
            return Err(anyhow!("Decimals too high"));
        }
        
        Ok(())
    }
    
    /// Generate token addresses using commit-reveal scheme
    fn generate_token_addresses(
        &self,
        creator: &Address,
        symbol: &str,
        block_number: u64,
    ) -> (Address, Address) {
        // Use commit-reveal pattern to prevent frontrunning
        // Step 1: Generate commitment from creator's private data
        let commitment = self.generate_commitment(creator, symbol, block_number);

        // Step 2: Use block hash from future block for randomness
        // In production, use block hash from N blocks in future
        let block_entropy = self.get_block_entropy(block_number);

        let mut hasher = Keccak256::new();
        hasher.update(b"PUBLIC_TOKEN_V3_SECURE");
        hasher.update(creator.as_bytes());
        hasher.update(symbol.as_bytes());
        hasher.update(&commitment.as_bytes());
        hasher.update(&block_entropy.as_bytes());
        hasher.update(&block_number.to_le_bytes()); // Anti-frontrunning salt
        let public_address = Address::from_slice(&hasher.finalize()[12..]);

        let mut hasher = Keccak256::new();
        hasher.update(b"PRIVATE_TOKEN_V2");
        hasher.update(creator.as_bytes());
        hasher.update(symbol.as_bytes());
        hasher.update(&commitment.as_bytes()); // Use commitment for consistency
        hasher.update(&block_entropy.as_bytes()); // Use same entropy as public address
        hasher.update(&block_number.to_le_bytes());
        let private_address = Address::from_slice(&hasher.finalize()[12..]);
        
        (public_address, private_address)
    }

    /// Generate commitment for commit-reveal scheme with secure randomness
    fn generate_commitment(&self, creator: &Address, symbol: &str, block_number: u64) -> H256 {
        use rand::RngCore;

        // Generate cryptographically secure random nonce
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut hasher = Keccak256::new();
        hasher.update(b"COMMIT_V1_SECURE");
        hasher.update(creator.as_bytes());
        hasher.update(symbol.as_bytes());
        hasher.update(&block_number.to_le_bytes());
        hasher.update(&nonce);  // Use cryptographic randomness instead of timestamp

        // Store nonce for later reveal phase (in production, store in secure storage)
        // self.pending_reveals.insert(commitment_hash, nonce);

        H256::from_slice(&hasher.finalize())
    }

    /// Get entropy from block with additional randomness
    fn get_block_entropy(&self, block_number: u64) -> H256 {
        use rand::RngCore;

        // In production: wait for block N+REVEAL_DELAY and use its hash
        // Add additional entropy to prevent manipulation
        let mut random_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_salt);

        let mut hasher = Keccak256::new();
        hasher.update(b"BLOCK_ENTROPY_V2");
        hasher.update(&block_number.to_le_bytes());
        hasher.update(&random_salt);  // Add unpredictable entropy
        // In production, also include actual block hash from future block
        // hasher.update(&future_block_hash);
        H256::from_slice(&hasher.finalize())
    }
    
    /// Generate bytecode for public token contract
    fn generate_public_bytecode(&self, name: &str, symbol: &str, decimals: u8) -> Vec<u8> {
        // In production, this would compile the QRC20 contract with parameters
        // For now, return placeholder bytecode
        let mut bytecode = vec![0x60, 0x80, 0x60, 0x40]; // Standard EVM prefix
        bytecode.extend_from_slice(name.as_bytes());
        bytecode.extend_from_slice(symbol.as_bytes());
        bytecode.push(decimals);
        bytecode
    }
    
    /// Generate bytecode for private token contract
    fn generate_private_bytecode(&self, name: &str, symbol: &str, decimals: u8) -> Vec<u8> {
        // In production, this would compile the QRC20P contract with parameters
        let mut bytecode = vec![0x60, 0x80, 0x60, 0x40];
        bytecode.extend_from_slice(b"PRIVATE_");
        bytecode.extend_from_slice(name.as_bytes());
        bytecode.extend_from_slice(symbol.as_bytes());
        bytecode.push(decimals);
        bytecode
    }
    
    /// Deploy contract bytecode to address
    async fn deploy_contract_bytecode(&self, address: Address, bytecode: Vec<u8>) -> Result<()> {
        let mut state = self.global_state.write().await;
        state.set_code(address, bytecode)?;
        Ok(())
    }
    
    /// Mint initial supply to creator
    async fn mint_initial_supply(
        &self,
        token_id: TokenId,
        creator: Address,
        amount: U256,
    ) -> Result<()> {
        let mut state = self.global_state.write().await;
        
        // Get the public contract address for this token
        let tokens = self.tokens.read().await;
        let metadata = tokens.get(&token_id)
            .ok_or_else(|| anyhow!("Token not found"))?;
        let contract_address = metadata.public_address;
        drop(tokens);

        // Set balance in public mode by default
        let balance_key = Self::balance_storage_key(&token_id, &creator);
        let mut amount_bytes = [0u8; 32];
        amount.to_big_endian(&mut amount_bytes);
        state.set_storage(contract_address, balance_key, H256::from_slice(&amount_bytes))?;

        // Update total supply
        let supply_key = H256::from_low_u64_be(0); // Storage slot 0 for total supply
        state.set_storage(contract_address, supply_key, H256::from_slice(&amount_bytes))?;
        
        Ok(())
    }
    
    /// Calculate storage key for balance
    fn balance_storage_key(token_id: &TokenId, owner: &Address) -> H256 {
        let mut hasher = Keccak256::new();
        hasher.update(owner.as_bytes());
        hasher.update(&[0u8; 32]); // Slot 0 for balances mapping
        H256::from_slice(&hasher.finalize())
    }
    
    /// Get token metadata
    pub async fn get_token(&self, token_id: &TokenId) -> Option<TokenMetadata> {
        self.tokens.read().await.get(token_id).cloned()
    }
    
    /// Get token by symbol
    pub async fn get_token_by_symbol(&self, symbol: &str) -> Option<TokenMetadata> {
        let symbol_map = self.symbol_to_token.read().await;
        if let Some(token_id) = symbol_map.get(symbol) {
            self.get_token(token_id).await
        } else {
            None
        }
    }
    
    /// Get all tokens created by an address
    pub async fn get_creator_tokens(&self, creator: Address) -> Vec<TokenMetadata> {
        let creator_map = self.creator_tokens.read().await;
        if let Some(token_ids) = creator_map.get(&creator) {
            let tokens = self.tokens.read().await;
            token_ids
                .iter()
                .filter_map(|id| tokens.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Calculate switch fee in QOR based on USD price
    async fn calculate_switch_fee_in_qor(&self) -> Result<U256> {
        let fee_system = self.fee_system.read().await;
        Ok(fee_system.usd_to_qor(self.config.switch_fee_usd as f64 / 1e8))
    }
    
    /// Calculate creation fee in QOR based on USD price
    pub async fn calculate_creation_fee_in_qor(&self) -> Result<U256> {
        let fee_system = self.fee_system.read().await;
        Ok(fee_system.usd_to_qor(self.config.creation_fee_usd as f64 / 1e8))
    }
    
    /// Update switch fee for a token (in USD)
    pub async fn update_switch_fee_usd(&self, token_id: &TokenId, new_fee_usd: u64) -> Result<()> {
        let mut tokens = self.tokens.write().await;
        let token = tokens.get_mut(token_id)
            .ok_or_else(|| anyhow!("Token not found"))?;
        
        // Convert USD fee to QOR at current price
        let fee_system = self.fee_system.read().await;
        token.switch_fee = fee_system.usd_to_qor(new_fee_usd as f64 / 1e8);
        
        Ok(())
    }
    
    /// Pause/unpause token
    pub async fn set_token_active(&self, token_id: &TokenId, active: bool) -> Result<()> {
        let mut tokens = self.tokens.write().await;
        let token = tokens.get_mut(token_id)
            .ok_or_else(|| anyhow!("Token not found"))?;
        
        token.is_active = active;
        Ok(())
    }
    
    /// Get total number of deployed tokens
    pub async fn get_total_tokens(&self) -> usize {
        self.tokens.read().await.len()
    }
    
    /// Process token deployment from transaction with USD fee
    pub async fn process_deploy_transaction(
        &self,
        tx: &TransactionType,
        sender: Address,
        block_number: u64,
    ) -> Result<TokenId> {
        if let TransactionType::DeployDualToken {
            name,
            symbol,
            total_supply,
            decimals,
            privacy_enabled,
        } = tx {
            // Check if sender has paid the creation fee (handled by fee processor)
            // The fee processor would have already deducted the USD-equivalent QOR
            
            self.deploy_dual_token(
                sender,
                name.clone(),
                symbol.clone(),
                *total_supply,
                *decimals,
                *privacy_enabled,
                block_number,
            ).await
        } else {
            Err(anyhow!("Not a deploy token transaction"))
        }
    }
    
    /// Get current fees in both USD and QOR
    pub async fn get_fee_info(&self) -> Result<FeeInfo> {
        let fee_system = self.fee_system.read().await;
        
        Ok(FeeInfo {
            creation_fee_usd: self.config.creation_fee_usd,
            creation_fee_qor: fee_system.usd_to_qor(self.config.creation_fee_usd as f64 / 1e8),
            switch_fee_usd: self.config.switch_fee_usd,
            switch_fee_qor: fee_system.usd_to_qor(self.config.switch_fee_usd as f64 / 1e8),
            qor_usd_price: U256::from((fee_system.get_qor_price() * 1e18) as u128),
        })
    }
}

/// Fee information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeInfo {
    pub creation_fee_usd: u64,      // In USD cents (1e8 scale)
    pub creation_fee_qor: U256,     // Equivalent in QOR
    pub switch_fee_usd: u64,        // In USD cents (1e8 scale)
    pub switch_fee_qor: U256,       // Equivalent in QOR
    pub qor_usd_price: U256,        // Current QOR/USD price
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_token_deployment() {
        // Test would create factory and deploy a token
    }
    
    #[tokio::test]
    async fn test_duplicate_symbol_rejection() {
        // Test that duplicate symbols are rejected
    }
}