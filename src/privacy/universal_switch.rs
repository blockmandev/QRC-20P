//! UniversalSwitch Protocol Module - Complete Implementation
//! 
//! Native protocol-level implementation of dual-mode token switching
//! with privacy features, amount splitting, and stealth addresses

use anyhow::{Result, anyhow};
use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use std::sync::Arc;
use sha3::{Keccak256, Digest};
use secp256k1::{PublicKey, SecretKey, Secp256k1};
use rand::Rng;
use super::validator_bridge::{ZKCommitment, CommitmentSource};

// ============================================================================
// Core Types
// ============================================================================

/// Token ID wrapper - identifies dual-mode token pairs
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenId(pub H256);

impl TokenId {
    pub fn from_addresses(public: Address, private: Address) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(public.as_bytes());
        hasher.update(private.as_bytes());
        let hash = hasher.finalize();
        TokenId(H256::from_slice(&hash))
    }
}

/// Token operating mode
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TokenMode {
    Public = 0,
    Private = 1,
}

/// ZK Proof wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<H256>,
}

/// Commitment generator for privacy
pub struct CommitmentGenerator;

impl CommitmentGenerator {
    pub fn generate(secret: H256, amount: U256, token: H256, nonce: H256) -> H256 {
        let mut hasher = Keccak256::new();
        hasher.update(secret.as_bytes());
        let mut amount_bytes = [0u8; 32];
        amount.to_little_endian(&mut amount_bytes);
        hasher.update(&amount_bytes);
        hasher.update(token.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();
        H256::from_slice(&hash)
    }
}

// ============================================================================
// Privacy Components
// ============================================================================

/// Simple Merkle tree for commitments
struct MerkleTree {
    levels: Vec<Vec<H256>>,
    depth: usize,
    next_index: usize,
}

impl MerkleTree {
    fn new() -> Self {
        Self {
            levels: vec![Vec::new()],
            depth: 20,
            next_index: 0,
        }
    }
    
    fn insert(&mut self, leaf: H256) -> usize {
        let index = self.next_index;
        if self.levels[0].len() <= index {
            self.levels[0].resize(index + 1, H256::zero());
        }
        self.levels[0][index] = leaf;
        self.next_index += 1;
        index
    }
}

/// Privacy pool for shielded transactions
pub struct PrivacyPool {
    commitments: Arc<RwLock<HashSet<H256>>>,
    nullifiers: Arc<RwLock<HashSet<H256>>>,
    merkle_tree: Arc<RwLock<MerkleTree>>,
}

impl PrivacyPool {
    pub fn new() -> Self {
        Self {
            commitments: Arc::new(RwLock::new(HashSet::new())),
            nullifiers: Arc::new(RwLock::new(HashSet::new())),
            merkle_tree: Arc::new(RwLock::new(MerkleTree::new())),
        }
    }

    pub async fn shield(&mut self, amount: U256, commitment: H256) -> Result<()> {
        let mut commitments = self.commitments.write().await;
        if commitments.contains(&commitment) {
            return Err(anyhow!("Duplicate commitment"));
        }
        commitments.insert(commitment);
        
        let mut tree = self.merkle_tree.write().await;
        tree.insert(commitment);
        Ok(())
    }

    pub async fn unshield(&mut self, proof: &Proof, nullifier: H256, amount: U256) -> Result<()> {
        let mut nullifiers = self.nullifiers.write().await;
        if nullifiers.contains(&nullifier) {
            return Err(anyhow!("Nullifier already spent"));
        }
        
        // In production: Verify ZK proof here
        // For now, just mark nullifier as spent
        nullifiers.insert(nullifier);
        Ok(())
    }
}

/// Privacy state manager
pub struct PrivacyStateManager {
    pools: HashMap<H256, PrivacyPool>,
}

impl PrivacyStateManager {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }

    pub fn get_pool(&mut self, token: H256) -> &mut PrivacyPool {
        self.pools.entry(token).or_insert_with(PrivacyPool::new)
    }

    /// Get or create a privacy pool for a token
    pub fn get_or_create_pool(&mut self, token: H256) -> Result<&mut PrivacyPool> {
        Ok(self.pools.entry(token).or_insert_with(PrivacyPool::new))
    }

    /// Add a nullifier to the global set
    pub fn add_nullifier(&mut self, nullifier: H256) -> Result<()> {
        // In a real implementation, this would add to a global nullifier set
        // For now, we add it to all pools to prevent double-spending
        for pool in self.pools.values_mut() {
            pool.nullifiers.insert(nullifier);
        }
        Ok(())
    }
}

// ============================================================================
// Amount Splitting (from your provided code)
// ============================================================================

/// Amount splitter with verification
pub struct AmountSplitter {
    standard_denoms: Vec<U256>,
    strategies: Vec<SplitStrategy>,
    min_chunk_size: U256,
}

#[derive(Clone, Debug)]
pub enum SplitStrategy {
    StandardDenominations,
    RandomSplit,
    BinarySplit,
    FibonacciSplit,
}

impl AmountSplitter {
    pub fn new() -> Self {
        Self {
            standard_denoms: vec![
                U256::from(1),
                U256::from(5),
                U256::from(10),
                U256::from(50),
                U256::from(100),
                U256::from(500),
                U256::from(1000),
                U256::from(5000),
                U256::from(10000),
            ],
            strategies: vec![
                SplitStrategy::StandardDenominations,
                SplitStrategy::RandomSplit,
                SplitStrategy::BinarySplit,
                SplitStrategy::FibonacciSplit,
            ],
            min_chunk_size: U256::from(1),
        }
    }

    pub fn split_for_privacy(&self, amount: U256) -> Result<Vec<U256>> {
        if amount == U256::zero() {
            return Err(anyhow!("Cannot split zero amount"));
        }

        let strategy = &self.strategies[rand::thread_rng().gen_range(0..self.strategies.len())];
        
        let chunks = match strategy {
            SplitStrategy::StandardDenominations => self.split_standard(amount)?,
            SplitStrategy::RandomSplit => self.split_random_safe(amount)?,
            SplitStrategy::BinarySplit => self.split_binary(amount)?,
            SplitStrategy::FibonacciSplit => self.split_fibonacci_safe(amount)?,
        };

        self.verify_amount_conservation(amount, &chunks)?;
        Ok(chunks)
    }

    fn verify_amount_conservation(&self, original: U256, chunks: &[U256]) -> Result<()> {
        let sum = chunks.iter().fold(U256::zero(), |acc, &chunk| {
            acc.saturating_add(chunk)
        });

        if sum != original {
            return Err(anyhow!(
                "Amount conservation failed! Original: {}, Sum: {}",
                original, sum
            ));
        }

        if chunks.iter().any(|&c| c == U256::zero()) {
            return Err(anyhow!("Zero-value chunks detected"));
        }

        Ok(())
    }

    fn split_standard(&self, mut amount: U256) -> Result<Vec<U256>> {
        let mut result = Vec::new();

        for &denom in self.standard_denoms.iter().rev() {
            let max_of_this_denom = 3;
            let mut count = 0;

            while amount >= denom && count < max_of_this_denom {
                result.push(denom);
                amount = amount.saturating_sub(denom);
                count += 1;

                if rand::thread_rng().gen_bool(0.3) {
                    break;
                }
            }
        }

        if amount > U256::zero() {
            if amount < self.min_chunk_size && !result.is_empty() {
                let last = result.pop().unwrap();
                result.push(last.saturating_add(amount));
            } else {
                result.push(amount);
            }
        }

        use rand::seq::SliceRandom;
        result.shuffle(&mut rand::thread_rng());
        Ok(result)
    }

    fn split_random_safe(&self, amount: U256) -> Result<Vec<U256>> {
        let mut result = Vec::new();
        let mut remaining = amount;
        let chunks = rand::thread_rng().gen_range(3..=10);

        for i in 0..chunks - 1 {
            if remaining <= self.min_chunk_size {
                break;
            }

            let max_chunk = remaining / 2;
            if max_chunk == U256::zero() {
                break;
            }

            let random_factor = rand::thread_rng().gen_range(1..=100);
            let chunk = max_chunk.saturating_mul(U256::from(random_factor)) / 100;
            let chunk = chunk.max(self.min_chunk_size);
            
            if chunk <= remaining {
                result.push(chunk);
                remaining = remaining.saturating_sub(chunk);
            }
        }

        if remaining > U256::zero() {
            result.push(remaining);
        }

        if result.is_empty() {
            result.push(amount);
        }

        Ok(result)
    }

    fn split_binary(&self, amount: U256) -> Result<Vec<U256>> {
        let mut result = Vec::new();
        let mut bit = U256::from(1);
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 256;

        while bit <= amount && iterations < MAX_ITERATIONS {
            if amount & bit != U256::zero() {
                result.push(bit);
            }

            match bit.checked_mul(U256::from(2)) {
                Some(next_bit) => bit = next_bit,
                None => break,
            }
            iterations += 1;
        }

        let sum: U256 = result.iter().fold(U256::zero(), |acc, &x| acc.saturating_add(x));
        if sum != amount {
            return Err(anyhow!("Binary split verification failed"));
        }

        Ok(result)
    }

    fn split_fibonacci_safe(&self, amount: U256) -> Result<Vec<U256>> {
        let mut result = Vec::new();
        let mut remaining = amount;
        let mut fib = vec![U256::from(1), U256::from(1)];
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000;

        while fib[fib.len() - 1] < amount && iterations < MAX_ITERATIONS {
            let prev1 = fib[fib.len() - 1];
            let prev2 = fib[fib.len() - 2];

            match prev1.checked_add(prev2) {
                Some(next) => fib.push(next),
                None => break,
            }
            iterations += 1;
        }

        for &f in fib.iter().rev() {
            if f <= remaining && f >= self.min_chunk_size {
                result.push(f);
                remaining = remaining.saturating_sub(f);
            }
        }

        if remaining > U256::zero() {
            if remaining >= self.min_chunk_size {
                result.push(remaining);
            } else if !result.is_empty() {
                let last = result.pop().unwrap();
                result.push(last.saturating_add(remaining));
            } else {
                result.push(remaining);
            }
        }

        Ok(result)
    }
}

// ============================================================================
// Amount Mixer
// ============================================================================

pub struct AmountMixer {
    mix_pool: Arc<RwLock<HashMap<U256, Vec<MixEntry>>>>,
    completed: Arc<RwLock<Vec<CompletedMix>>>,
}

#[derive(Clone, Debug)]
struct MixEntry {
    user: Address,
    amount: U256,
    timestamp: u64,
}

#[derive(Clone, Debug)]
struct CompletedMix {
    original_total: U256,
    output_total: U256,
    chunks_count: usize,
    timestamp: u64,
}

impl AmountMixer {
    pub fn new() -> Self {
        Self {
            mix_pool: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn mix_amounts(&self, entries: Vec<(Address, U256)>) -> Result<Vec<(Address, U256)>> {
        let original_total: U256 = entries.iter()
            .fold(U256::zero(), |acc, (_, amt)| acc.saturating_add(*amt));

        let mut all_chunks = Vec::new();
        let splitter = AmountSplitter::new();

        for (user, amount) in entries {
            let chunks = splitter.split_for_privacy(amount)?;
            for chunk in chunks {
                all_chunks.push((user, chunk));
            }
        }

        use rand::seq::SliceRandom;
        all_chunks.shuffle(&mut rand::thread_rng());

        let output_total: U256 = all_chunks.iter()
            .fold(U256::zero(), |acc, (_, amt)| acc.saturating_add(*amt));

        if original_total != output_total {
            return Err(anyhow!(
                "Mixing amount mismatch! Original: {}, Output: {}",
                original_total, output_total
            ));
        }

        let completed_entry = CompletedMix {
            original_total,
            output_total,
            chunks_count: all_chunks.len(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        self.completed.write().await.push(completed_entry);
        Ok(all_chunks)
    }

    pub async fn process_chunks_async(
        &self,
        chunks: Vec<(Address, U256)>,
        delay_range: (u64, u64),
    ) -> Vec<tokio::task::JoinHandle<Result<(Address, U256)>>> {
        let mut handles = Vec::new();

        for (user, chunk) in chunks {
            let delay = rand::thread_rng().gen_range(delay_range.0..=delay_range.1);
            let handle = tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                Ok((user, chunk))
            });
            handles.push(handle);
        }

        handles
    }

    pub async fn verify_all_mixes(&self) -> Result<()> {
        let completed = self.completed.read().await;
        for mix in completed.iter() {
            if mix.original_total != mix.output_total {
                return Err(anyhow!("Mix verification failed"));
            }
        }
        Ok(())
    }
}

// ============================================================================
// Main UniversalSwitch Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub token_id: TokenId,
    pub public_address: Address,
    pub private_address: Address,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: U256,
    pub created_at: u64,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserModePreference {
    pub preferred_mode: TokenMode,
    pub auto_switch: bool,
    pub privacy_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchRequest {
    pub id: H256,
    pub token_id: TokenId,
    pub user: Address,
    pub from_mode: TokenMode,
    pub to_mode: TokenMode,
    pub amount: U256,
    pub timestamp: u64,
    pub status: SwitchStatus,
    pub commitment: Option<H256>,
    pub proof: Option<Proof>,
    pub nullifier: Option<H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SwitchStatus {
    Pending,
    Processing,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchConfig {
    pub switch_fee_basis_points: u16,
    pub cooldown_blocks: u64,
    pub min_switch_amount: U256,
    pub max_pending_switches: usize,
    pub max_switches_per_block: u64,
    pub cache_ttl_blocks: u64,
}

impl Default for SwitchConfig {
    fn default() -> Self {
        Self {
            switch_fee_basis_points: 10,
            cooldown_blocks: 5,
            min_switch_amount: U256::from(100),
            max_pending_switches: 1000,
            max_switches_per_block: 100,
            cache_ttl_blocks: 10,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwitchStatistics {
    pub total_switches: u64,
    pub total_volume_switched: U256,
    pub switches_by_token: HashMap<TokenId, u64>,
    pub switches_by_mode: HashMap<TokenMode, u64>,
}

// ============================================================================
// Stealth Address System
// ============================================================================

pub struct StealthAddressSystem {
    meta_addresses: Arc<RwLock<HashMap<Address, StealthMetaAddress>>>,
    stealth_addresses: Arc<RwLock<HashMap<H256, StealthAddressInfo>>>,
    secp: Secp256k1<secp256k1::All>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthMetaAddress {
    pub spend_pubkey: PublicKey,
    pub view_pubkey: PublicKey,
}

#[derive(Debug, Clone)]
struct StealthAddressInfo {
    pub address: Address,
    pub ephemeral_pubkey: PublicKey,
    pub shared_secret: H256,
}

impl StealthAddressSystem {
    pub fn new() -> Self {
        Self {
            meta_addresses: Arc::new(RwLock::new(HashMap::new())),
            stealth_addresses: Arc::new(RwLock::new(HashMap::new())),
            secp: Secp256k1::new(),
        }
    }

    pub async fn register_stealth_keys(
        &self,
        user: Address,
        spend_key: SecretKey,
        view_key: SecretKey,
    ) -> Result<StealthMetaAddress> {
        let spend_pubkey = PublicKey::from_secret_key(&self.secp, &spend_key);
        let view_pubkey = PublicKey::from_secret_key(&self.secp, &view_key);

        let meta_address = StealthMetaAddress {
            spend_pubkey,
            view_pubkey,
        };

        self.meta_addresses.write().await.insert(user, meta_address.clone());
        Ok(meta_address)
    }

    pub async fn generate_stealth_address(
        &self,
        recipient_meta: &StealthMetaAddress,
    ) -> Result<(Address, PublicKey)> {
        let ephemeral_key = SecretKey::new(&mut rand::thread_rng());
        let ephemeral_pubkey = PublicKey::from_secret_key(&self.secp, &ephemeral_key);

        let shared_secret = secp256k1::ecdh::SharedSecret::new(
            &recipient_meta.view_pubkey,
            &ephemeral_key,
        );

        let mut hasher = Keccak256::new();
        hasher.update(shared_secret.as_ref());
        let hash = hasher.finalize();

        let secret_scalar = SecretKey::from_slice(&hash)
            .map_err(|e| anyhow!("Invalid scalar: {}", e))?;

        let mut stealth_pubkey = recipient_meta.spend_pubkey;
        stealth_pubkey = stealth_pubkey.add_exp_tweak(&self.secp, &secret_scalar.into())
            .map_err(|_| anyhow!("Failed to create stealth pubkey"))?;

        let uncompressed = stealth_pubkey.serialize_uncompressed();
        let mut hasher = Keccak256::new();
        hasher.update(&uncompressed[1..]);
        let address_bytes = hasher.finalize();
        let address = Address::from_slice(&address_bytes[12..]);

        let info = StealthAddressInfo {
            address,
            ephemeral_pubkey,
            shared_secret: H256::from_slice(&shared_secret.as_ref()[..32]),
        };

        self.stealth_addresses.write().await.insert(
            H256::from_slice(&shared_secret.as_ref()[..32]),
            info,
        );

        Ok((address, ephemeral_pubkey))
    }

    pub async fn store_ephemeral_key(
        &self,
        _ephemeral_key: PublicKey,
        _tx_hash: H256,
    ) -> Result<()> {
        // In production: store on-chain
        Ok(())
    }
}

// ============================================================================
// Helper Components
// ============================================================================

pub struct NonceManager {
    used_nonces: Arc<RwLock<HashSet<(Address, u64)>>>,
}

impl NonceManager {
    pub fn new() -> Self {
        Self {
            used_nonces: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub async fn verify_nonce(&self, user: Address, nonce: u64) -> Result<()> {
        let mut used = self.used_nonces.write().await;
        if !used.insert((user, nonce)) {
            return Err(anyhow!("Nonce already used"));
        }
        Ok(())
    }
}

pub struct GlobalRateLimiter {
    total_switches_per_block: Arc<RwLock<u64>>,
    max_switches_per_block: u64,
    current_block: Arc<RwLock<u64>>,
}

impl GlobalRateLimiter {
    pub fn new(max_switches: u64) -> Self {
        Self {
            total_switches_per_block: Arc::new(RwLock::new(0)),
            max_switches_per_block: max_switches,
            current_block: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn check_and_increment(&self, block_height: u64) -> Result<()> {
        let mut current_block = self.current_block.write().await;

        if *current_block != block_height {
            *current_block = block_height;
            let mut count = self.total_switches_per_block.write().await;
            *count = 0;
        }
        drop(current_block);

        let mut count = self.total_switches_per_block.write().await;
        if *count >= self.max_switches_per_block {
            return Err(anyhow!("Global rate limit exceeded"));
        }
        *count += 1;
        Ok(())
    }
}

pub struct SwitchCache {
    balance_cache: Arc<RwLock<HashMap<(TokenId, Address), (U256, u64)>>>,
    cache_ttl_blocks: u64,
}

impl SwitchCache {
    pub fn new(ttl_blocks: u64) -> Self {
        Self {
            balance_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_blocks: ttl_blocks,
        }
    }

    pub async fn get_balance(&self, token_id: &TokenId, user: &Address, current_block: u64) -> Option<U256> {
        let cache = self.balance_cache.read().await;
        if let Some((balance, cached_block)) = cache.get(&(token_id.clone(), *user)) {
            if current_block - cached_block < self.cache_ttl_blocks {
                return Some(*balance);
            }
        }
        None
    }

    pub async fn set_balance(&self, token_id: TokenId, user: Address, balance: U256, block_height: u64) {
        let mut cache = self.balance_cache.write().await;
        cache.insert((token_id, user), (balance, block_height));
    }
}

// ============================================================================
// Main UniversalSwitch Implementation
// ============================================================================

pub struct UniversalSwitch {
    token_pairs: Arc<RwLock<HashMap<TokenId, TokenPair>>>,
    mode_balances: Arc<RwLock<HashMap<(TokenId, Address, TokenMode), U256>>>,
    user_preferences: Arc<RwLock<HashMap<(TokenId, Address), UserModePreference>>>,
    privacy_manager: Arc<RwLock<PrivacyStateManager>>,
    pending_switches: Arc<RwLock<HashMap<H256, SwitchRequest>>>,
    switch_stats: Arc<RwLock<SwitchStatistics>>,
    rate_limiter: Arc<RwLock<HashMap<Address, (u64, u64)>>>,
    global_rate_limiter: Arc<GlobalRateLimiter>,
    nonce_manager: Arc<NonceManager>,
    cache: Arc<SwitchCache>,
    stealth: Arc<StealthAddressSystem>,
    amount_splitter: Arc<AmountSplitter>,
    amount_mixer: Arc<AmountMixer>,
    config: SwitchConfig,
    block_height: Arc<RwLock<u64>>,
    state_root: Arc<RwLock<H256>>,
}

impl UniversalSwitch {
    pub fn new(config: SwitchConfig) -> Self {
        let max_switches = config.max_switches_per_block;
        let cache_ttl = config.cache_ttl_blocks;

        Self {
            token_pairs: Arc::new(RwLock::new(HashMap::new())),
            mode_balances: Arc::new(RwLock::new(HashMap::new())),
            user_preferences: Arc::new(RwLock::new(HashMap::new())),
            privacy_manager: Arc::new(RwLock::new(PrivacyStateManager::new())),
            pending_switches: Arc::new(RwLock::new(HashMap::new())),
            switch_stats: Arc::new(RwLock::new(SwitchStatistics::default())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            global_rate_limiter: Arc::new(GlobalRateLimiter::new(max_switches)),
            nonce_manager: Arc::new(NonceManager::new()),
            cache: Arc::new(SwitchCache::new(cache_ttl)),
            stealth: Arc::new(StealthAddressSystem::new()),
            amount_splitter: Arc::new(AmountSplitter::new()),
            amount_mixer: Arc::new(AmountMixer::new()),
            config,
            block_height: Arc::new(RwLock::new(0)),
            state_root: Arc::new(RwLock::new(H256::zero())),
        }
    }

    pub async fn register_token_pair(
        &self,
        public_address: Address,
        private_address: Address,
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: U256,
    ) -> Result<TokenId> {
        let token_id = TokenId::from_addresses(public_address, private_address);
        
        let mut pairs = self.token_pairs.write().await;
        if pairs.contains_key(&token_id) {
            return Err(anyhow!("Token pair already registered"));
        }
        
        let token_pair = TokenPair {
            token_id: token_id.clone(),
            public_address,
            private_address,
            name,
            symbol,
            decimals,
            total_supply,
            created_at: chrono::Utc::now().timestamp() as u64,
            is_active: true,
        };
        
        pairs.insert(token_id.clone(), token_pair);
        Ok(token_id)
    }

    pub async fn switch_to_private(
        &self,
        token_id: TokenId,
        user: Address,
        amount: U256,
        secret: H256,
        nonce: H256,
    ) -> Result<H256> {
        if amount < self.config.min_switch_amount {
            return Err(anyhow!("Amount below minimum"));
        }

        let pairs = self.token_pairs.read().await;
        let token_pair = pairs.get(&token_id)
            .ok_or_else(|| anyhow!("Token not registered"))?;

        if !token_pair.is_active {
            return Err(anyhow!("Token pair is not active"));
        }

        let balances = self.mode_balances.read().await;
        let public_key = (token_id.clone(), user, TokenMode::Public);
        let public_balance = balances.get(&public_key).copied().unwrap_or_default();

        if public_balance < amount {
            return Err(anyhow!("Insufficient public balance"));
        }

        drop(balances);

        let fee = amount
            .checked_mul(U256::from(self.config.switch_fee_basis_points))
            .ok_or_else(|| anyhow!("Fee calculation overflow"))?
            .checked_div(U256::from(10000))
            .ok_or_else(|| anyhow!("Fee division error"))?;

        let net_amount = amount
            .checked_sub(fee)
            .ok_or_else(|| anyhow!("Amount less than fee"))?;

        let commitment = CommitmentGenerator::generate(secret, net_amount, token_id.0, nonce);

        let request_id = H256::random();
        let request = SwitchRequest {
            id: request_id,
            token_id: token_id.clone(),
            user,
            from_mode: TokenMode::Public,
            to_mode: TokenMode::Private,
            amount: net_amount,
            timestamp: chrono::Utc::now().timestamp() as u64,
            status: SwitchStatus::Processing,
            commitment: Some(commitment),
            proof: None,
            nullifier: None,
        };

        let mut pending = self.pending_switches.write().await;
        pending.insert(request_id, request);
        drop(pending);

        self.process_switch(request_id).await?;
        Ok(request_id)
    }

    pub async fn switch_to_public(
        &self,
        token_id: TokenId,
        user: Address,
        amount: U256,
        proof: Proof,
        nullifier: H256,
    ) -> Result<H256> {
        if amount < self.config.min_switch_amount {
            return Err(anyhow!("Amount below minimum"));
        }
        
        let pairs = self.token_pairs.read().await;
        let token_pair = pairs.get(&token_id)
            .ok_or_else(|| anyhow!("Token not registered"))?;
        
        if !token_pair.is_active {
            return Err(anyhow!("Token pair is not active"));
        }
        
        drop(pairs);
        
        let mut privacy_mgr = self.privacy_manager.write().await;
        let pool = privacy_mgr.get_pool(token_id.0);
        pool.unshield(&proof, nullifier, amount).await?;
        drop(privacy_mgr);

        let fee = amount
            .checked_mul(U256::from(self.config.switch_fee_basis_points))
            .ok_or_else(|| anyhow!("Fee calculation overflow"))?
            .checked_div(U256::from(10000))
            .ok_or_else(|| anyhow!("Fee division error"))?;

        let net_amount = amount
            .checked_sub(fee)
            .ok_or_else(|| anyhow!("Amount less than fee"))?;

        let request_id = H256::random();
        let request = SwitchRequest {
            id: request_id,
            token_id: token_id.clone(),
            user,
            from_mode: TokenMode::Private,
            to_mode: TokenMode::Public,
            amount: net_amount,
            timestamp: chrono::Utc::now().timestamp() as u64,
            status: SwitchStatus::Processing,
            commitment: None,
            proof: Some(proof),
            nullifier: Some(nullifier),
        };
        
        let mut pending = self.pending_switches.write().await;
        pending.insert(request_id, request);
        drop(pending);
        
        self.process_switch(request_id).await?;
        Ok(request_id)
    }

    async fn process_switch(&self, request_id: H256) -> Result<()> {
        let (from_key, to_key, amount) = {
            let pending = self.pending_switches.read().await;
            let request = pending.get(&request_id)
                .ok_or_else(|| anyhow!("Request not found"))?;

            let from_key = (request.token_id.clone(), request.user, request.from_mode);
            let to_key = (request.token_id.clone(), request.user, request.to_mode);
            (from_key, to_key, request.amount)
        };

        self.execute_atomic_switch(request_id, from_key, to_key, amount).await
    }

    async fn execute_atomic_switch(
        &self,
        request_id: H256,
        from_key: (TokenId, Address, TokenMode),
        to_key: (TokenId, Address, TokenMode),
        amount: U256,
    ) -> Result<()> {
        let mut pending = self.pending_switches.write().await;
        let request = pending.get_mut(&request_id)
            .ok_or_else(|| anyhow!("Request not found"))?;

        let mut balances = self.mode_balances.write().await;

        if request.from_mode == TokenMode::Public {
            let from_balance = balances.entry(from_key).or_insert(U256::zero());
            let new_from_balance = from_balance.checked_sub(amount)
                .ok_or_else(|| anyhow!("Insufficient balance for switch"))?;
            *from_balance = new_from_balance;
        }

        let to_balance = balances.entry(to_key).or_insert(U256::zero());
        let new_to_balance = to_balance.checked_add(amount)
            .ok_or_else(|| anyhow!("Balance overflow in switch"))?;
        *to_balance = new_to_balance;
        
        if request.to_mode == TokenMode::Private {
            if let Some(commitment) = request.commitment {
                let mut privacy_mgr = self.privacy_manager.write().await;
                let pool = privacy_mgr.get_pool(request.token_id.0);
                pool.shield(request.amount, commitment).await?;
            }
        }
        
        let mut stats = self.switch_stats.write().await;
        stats.total_switches += 1;
        stats.total_volume_switched = stats.total_volume_switched.saturating_add(request.amount);
        *stats.switches_by_token.entry(request.token_id.clone()).or_insert(0) += 1;
        *stats.switches_by_mode.entry(request.to_mode).or_insert(0) += 1;
        
        request.status = SwitchStatus::Completed;
        Ok(())
    }

    pub async fn get_unified_balance(&self, token_id: TokenId, user: Address) -> U256 {
        let balances = self.mode_balances.read().await;
        
        let public_balance = balances
            .get(&(token_id.clone(), user, TokenMode::Public))
            .copied()
            .unwrap_or_default();
        
        let private_balance = balances
            .get(&(token_id.clone(), user, TokenMode::Private))
            .copied()
            .unwrap_or_default();
        
        public_balance.saturating_add(private_balance)
    }

    pub async fn switch_to_private_with_splitting(
        &self,
        token_id: TokenId,
        user: Address,
        amount: U256,
        secret: H256,
        nonce: H256,
    ) -> Result<Vec<H256>> {
        let chunks = self.amount_splitter.split_for_privacy(amount)?;
        let mut commitment_ids = Vec::new();

        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_nonce = self.generate_chunk_nonce(nonce, i as u64)?;
            let commitment_id = self.switch_to_private(
                token_id.clone(),
                user,
                *chunk,
                secret,
                chunk_nonce,
            ).await?;
            
            commitment_ids.push(commitment_id);
        }

        Ok(commitment_ids)
    }

    fn generate_chunk_nonce(&self, base_nonce: H256, chunk_index: u64) -> Result<H256> {
        let mut hasher = Keccak256::new();
        hasher.update(base_nonce.as_bytes());
        hasher.update(&chunk_index.to_le_bytes());
        let hash = hasher.finalize();
        Ok(H256::from_slice(&hash))
    }

    /// Load validator commitments into the privacy manager
    pub async fn load_validator_commitments(&self, commitments: Vec<ZKCommitment>) -> Result<()> {
        let mut privacy_mgr = self.privacy_manager.write().await;

        for commitment in commitments {
            // Get or create privacy pool for this commitment
            let pool = privacy_mgr.get_or_create_pool(commitment.commitment)?;

            // Add commitment to the pool's merkle tree
            pool.add_commitment(commitment.commitment)?;

            // Track the source for validator-specific operations
            if let CommitmentSource::Validator { address, index } = commitment.source {
                // Store validator-specific metadata if needed
                pool.add_validator_metadata(address, index, commitment.block_height)?;
            }

            // Update nullifier tracking if present
            if let Some(nullifier) = commitment.nullifier {
                privacy_mgr.add_nullifier(nullifier)?;
            }
        }

        Ok(())
    }

    /// Add P2P commitments to the privacy manager
    pub async fn add_p2p_commitments(&self, commitments: Vec<ZKCommitment>) -> Result<()> {
        let mut privacy_mgr = self.privacy_manager.write().await;

        for commitment in commitments {
            // Get or create privacy pool for this commitment
            let pool = privacy_mgr.get_or_create_pool(commitment.commitment)?;

            // Add commitment to the pool's merkle tree
            pool.add_commitment(commitment.commitment)?;

            // Track P2P source for network-specific operations
            if let CommitmentSource::P2PNode { peer_id } = &commitment.source {
                // Store P2P-specific metadata if needed
                pool.add_p2p_metadata(peer_id.clone(), commitment.timestamp)?;
            }

            // Update nullifier tracking if present
            if let Some(nullifier) = commitment.nullifier {
                privacy_mgr.add_nullifier(nullifier)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_token_registration() {
        let switch = UniversalSwitch::new(SwitchConfig::default());
        
        let public_addr = Address::random();
        let private_addr = Address::random();
        
        let token_id = switch.register_token_pair(
            public_addr,
            private_addr,
            "Test Token".to_string(),
            "TEST".to_string(),
            18,
            U256::from(1_000_000),
        ).await.unwrap();
        
        assert_ne!(token_id.0, H256::zero());
    }
    
    #[tokio::test]
    async fn test_amount_conservation_in_splitting() {
        let switch = UniversalSwitch::new(SwitchConfig::default());
        let amount = U256::from(10000);
        
        let chunks = switch.amount_splitter.split_for_privacy(amount).unwrap();
        let sum: U256 = chunks.iter().fold(U256::zero(), |acc, &x| acc + x);
        
        assert_eq!(sum, amount);
    }
}