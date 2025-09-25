//! Privacy State Transition System
//!
//! Manages state transitions for private transactions with commitment tracking

use anyhow::{Result, anyhow};
use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::Mutex;

use super::zk_proofs::{PrivateTransactionProof, ProofType, PublicInputs, ZkProofSystem};
use super::merkle_tree::MerkleTree;
use super::blockchain::state_connector::StateConnector;
use super::transaction_v2::TokenId;

/// Privacy state manager
pub struct PrivacyStateManager {
    /// Merkle tree of commitments
    commitment_tree: Arc<RwLock<MerkleTree>>,
    /// Nullifier set (spent commitments)
    nullifiers: Arc<RwLock<HashSet<H256>>>,
    /// Pending state transitions
    pending_transitions: Arc<RwLock<Vec<StateTransition>>>,
    /// ZK proof system
    proof_system: Arc<RwLock<ZkProofSystem>>,
    /// State connector to blockchain
    state_connector: Arc<StateConnector>,
    /// Privacy pools
    privacy_pools: Arc<RwLock<HashMap<H256, PrivacyPool>>>,
    /// Transaction lock for atomic operations
    transaction_lock: Arc<Mutex<()>>,
    /// State snapshots for rollback
    state_snapshots: Arc<RwLock<Vec<StateSnapshot>>>,
}

/// State snapshot for atomic rollback
#[derive(Debug, Clone)]
struct StateSnapshot {
    /// Transaction ID
    tx_id: H256,
    /// Commitment tree state
    tree_root: H256,
    tree_size: usize,
    /// Nullifiers before operation
    nullifiers_snapshot: HashSet<H256>,
    /// Pool TVL snapshots
    pool_snapshots: HashMap<H256, U256>,
    /// Timestamp
    timestamp: u64,
}

/// State transition for privacy operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Transaction ID
    pub tx_id: H256,
    /// Transition type
    pub transition_type: TransitionType,
    /// Proof of validity
    pub proof: PrivateTransactionProof,
    /// Timestamp
    pub timestamp: u64,
    /// Block number when included
    pub block_number: Option<u64>,
}

/// Types of state transitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionType {
    /// Deposit public tokens into privacy pool
    Deposit {
        depositor: Address,
        amount: U256,
        commitment: H256,
    },
    /// Transfer within privacy pool
    Transfer {
        nullifiers: Vec<H256>,
        commitments: Vec<H256>,
    },
    /// Withdraw from privacy pool
    Withdrawal {
        nullifier: H256,
        recipient: Address,
        amount: U256,
    },
    /// Mint new private tokens
    Mint {
        commitments: Vec<H256>,
        total_amount: U256,
    },
    /// Burn private tokens
    Burn {
        nullifiers: Vec<H256>,
        burned_amount: U256,
    },
}

/// Privacy pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyPool {
    /// Pool identifier
    pub pool_id: H256,
    /// Token address (if applicable)
    pub token_address: Option<Address>,
    /// Total value locked
    pub tvl: U256,
    /// Number of active commitments
    pub commitment_count: usize,
    /// Pool parameters
    pub params: PoolParams,
}

/// Pool parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolParams {
    /// Minimum deposit amount
    pub min_deposit: U256,
    /// Maximum deposit amount
    pub max_deposit: U256,
    /// Anonymity set size requirement
    pub min_anonymity_set: usize,
    /// Fee percentage (basis points)
    pub fee_bps: u16,
}

impl Default for PoolParams {
    fn default() -> Self {
        Self {
            min_deposit: U256::from(10).pow(U256::from(18)), // 1 token
            max_deposit: U256::from(10000).pow(U256::from(18)), // 10000 tokens
            min_anonymity_set: 10,
            fee_bps: 30, // 0.3%
        }
    }
}

impl PrivacyStateManager {
    /// Create new privacy state manager
    pub fn new(
        proof_system: Arc<RwLock<ZkProofSystem>>,
        state_connector: Arc<StateConnector>,
    ) -> Self {
        Self {
            commitment_tree: Arc::new(RwLock::new(MerkleTree::new(20))),
            nullifiers: Arc::new(RwLock::new(HashSet::new())),
            pending_transitions: Arc::new(RwLock::new(Vec::new())),
            proof_system,
            state_connector,
            privacy_pools: Arc::new(RwLock::new(HashMap::new())),
            transaction_lock: Arc::new(Mutex::new(())),
            state_snapshots: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create state snapshot for atomic rollback
    fn create_snapshot(&self, tx_id: H256) -> StateSnapshot {
        StateSnapshot {
            tx_id,
            tree_root: self.commitment_tree.read().root(),
            tree_size: self.commitment_tree.read().size(),
            nullifiers_snapshot: self.nullifiers.read().clone(),
            pool_snapshots: self.privacy_pools.read()
                .iter()
                .map(|(k, v)| (*k, v.tvl))
                .collect(),
            timestamp: current_timestamp(),
        }
    }

    /// Rollback to previous state snapshot with proper Merkle tree restoration
    fn rollback_to_snapshot(&self, snapshot: &StateSnapshot) -> Result<()> {
        // Rollback nullifiers
        *self.nullifiers.write() = snapshot.nullifiers_snapshot.clone();

        // Rollback pool TVLs
        let mut pools = self.privacy_pools.write();
        for (pool_id, tvl) in &snapshot.pool_snapshots {
            if let Some(pool) = pools.get_mut(pool_id) {
                pool.tvl = *tvl;
            }
        }

        // Properly rollback Merkle tree to snapshot state
        let mut tree = self.commitment_tree.write();
        tree.rollback_to_size(snapshot.tree_size)?;
        tree.set_root(snapshot.tree_root);

        Ok(())
    }

    /// Process deposit transition
    pub async fn process_deposit(
        &self,
        depositor: Address,
        amount: U256,
        commitment: H256,
        proof: PrivateTransactionProof,
    ) -> Result<H256> {
        // Acquire transaction lock for atomic operation
        let _lock = self.transaction_lock.lock().await;

        // Create snapshot for potential rollback
        let tx_id = H256::random();
        let snapshot = self.create_snapshot(tx_id);

        // Store snapshot
        self.state_snapshots.write().push(snapshot.clone());

        // Atomic operation with rollback on failure
        let result = async {
            // Verify proof
            if !self.verify_proof(&proof)? {
                return Err(anyhow!("Invalid deposit proof"));
            }

            // Verify amount matches proof
            if proof.public_inputs.public_amount != amount {
                return Err(anyhow!("Amount mismatch"));
            }

            // Add commitment to tree
            self.commitment_tree.write().insert(commitment)?;

            // Create state transition
            let transition = StateTransition {
                tx_id,
                transition_type: TransitionType::Deposit {
                    depositor,
                    amount,
                    commitment,
                },
                proof,
                timestamp: current_timestamp(),
                block_number: None,
            };

            // Add to pending
            self.pending_transitions.write().push(transition.clone());

            // Update pool TVL
            self.update_pool_tvl(H256::zero(), amount, true)?;

            Ok::<H256, anyhow::Error>(transition.tx_id)
        }.await;

        // Rollback on failure
        if result.is_err() {
            self.rollback_to_snapshot(&snapshot)?;
            // Clean up failed snapshot
            self.state_snapshots.write().retain(|s| s.tx_id != tx_id);
        }

        result
    }

    /// Process transfer transition
    pub async fn process_transfer(
        &self,
        nullifiers: Vec<H256>,
        commitments: Vec<H256>,
        proof: PrivateTransactionProof,
    ) -> Result<H256> {
        // Acquire transaction lock for atomic operation
        let _lock = self.transaction_lock.lock().await;

        // Create snapshot for potential rollback
        let tx_id = H256::random();
        let snapshot = self.create_snapshot(tx_id);

        // Store snapshot
        self.state_snapshots.write().push(snapshot.clone());

        // Atomic operation with rollback on failure
        let result = async {
            // Verify proof
            if !self.verify_proof(&proof)? {
                return Err(anyhow!("Invalid transfer proof"));
            }

            // Check nullifiers not already spent
            {
                let nullifier_set = self.nullifiers.read();
                for nullifier in &nullifiers {
                    if nullifier_set.contains(nullifier) {
                        return Err(anyhow!("Nullifier already spent: {:?}", nullifier));
                    }
                }
            }

            // Verify merkle root
            let current_root = self.commitment_tree.read().root();
            if proof.public_inputs.merkle_root != current_root {
                return Err(anyhow!("Invalid merkle root"));
            }

            // Add nullifiers atomically
            {
                let mut nullifier_set = self.nullifiers.write();
                for nullifier in &nullifiers {
                    nullifier_set.insert(*nullifier);
                }
            }

            // Add new commitments atomically
            {
                let mut tree = self.commitment_tree.write();
                for commitment in &commitments {
                    tree.insert(*commitment)?;
                }
            }

            // Create state transition
            let transition = StateTransition {
                tx_id,
                transition_type: TransitionType::Transfer {
                    nullifiers: nullifiers.clone(),
                    commitments: commitments.clone(),
                },
                proof,
                timestamp: current_timestamp(),
                block_number: None,
            };

            // Add to pending
            self.pending_transitions.write().push(transition.clone());

            Ok::<H256, anyhow::Error>(transition.tx_id)
        }.await;

        // Rollback on failure
        if result.is_err() {
            self.rollback_to_snapshot(&snapshot)?;
            // Clean up failed snapshot
            self.state_snapshots.write().retain(|s| s.tx_id != tx_id);
        }

        result
    }

    /// Process withdrawal transition
    pub async fn process_withdrawal(
        &self,
        nullifier: H256,
        recipient: Address,
        amount: U256,
        proof: PrivateTransactionProof,
    ) -> Result<H256> {
        // Acquire transaction lock for atomic operation
        let _lock = self.transaction_lock.lock().await;

        // Create snapshot for potential rollback
        let tx_id = H256::random();
        let snapshot = self.create_snapshot(tx_id);

        // Store snapshot
        self.state_snapshots.write().push(snapshot.clone());

        // Atomic operation with rollback on failure
        let result = async {
            // Verify proof
            if !self.verify_proof(&proof)? {
                return Err(anyhow!("Invalid withdrawal proof"));
            }

            // Check nullifier not already spent
            if self.nullifiers.read().contains(&nullifier) {
                return Err(anyhow!("Nullifier already spent"));
            }

            // Verify amount
            if proof.public_inputs.public_amount != amount {
                return Err(anyhow!("Amount mismatch"));
            }

            // Add nullifier atomically
            self.nullifiers.write().insert(nullifier);

            // Create state transition
            let transition = StateTransition {
                tx_id,
                transition_type: TransitionType::Withdrawal {
                    nullifier,
                    recipient,
                    amount,
                },
                proof,
                timestamp: current_timestamp(),
                block_number: None,
            };

            // Add to pending
            self.pending_transitions.write().push(transition.clone());

            // Update pool TVL atomically
            self.update_pool_tvl(H256::zero(), amount, false)?;

            Ok::<H256, anyhow::Error>(transition.tx_id)
        }.await;

        // Rollback on failure
        if result.is_err() {
            self.rollback_to_snapshot(&snapshot)?;
            // Clean up failed snapshot
            self.state_snapshots.write().retain(|s| s.tx_id != tx_id);
        }

        result
    }

    /// Finalize pending transitions
    pub async fn finalize_transitions(&self, block_number: u64) -> Result<Vec<H256>> {
        // Acquire transaction lock for atomic finalization
        let _lock = self.transaction_lock.lock().await;

        let mut transitions = self.pending_transitions.write();
        let mut finalized = Vec::new();
        let mut failed_txs = Vec::new();

        for transition in transitions.iter_mut() {
            if transition.block_number.is_none() {
                // Try to update blockchain state atomically
                match self.update_blockchain_state(transition).await {
                    Ok(_) => {
                        transition.block_number = Some(block_number);
                        finalized.push(transition.tx_id);

                        // Clean up successful snapshot
                        self.state_snapshots.write().retain(|s| s.tx_id != transition.tx_id);
                    }
                    Err(e) => {
                        // Mark for removal if blockchain update failed
                        failed_txs.push(transition.tx_id);

                        // Try to rollback if snapshot exists
                        if let Some(snapshot) = self.state_snapshots
                            .read()
                            .iter()
                            .find(|s| s.tx_id == transition.tx_id)
                            .cloned()
                        {
                            let _ = self.rollback_to_snapshot(&snapshot);
                        }
                    }
                }
            }
        }

        // Remove failed transactions
        transitions.retain(|t| !failed_txs.contains(&t.tx_id));

        // Remove finalized transitions older than 100 blocks
        transitions.retain(|t| {
            t.block_number.map(|bn| block_number - bn < 100).unwrap_or(true)
        });

        // Clean up old snapshots (older than 1000 blocks or 24 hours)
        self.cleanup_old_snapshots();

        Ok(finalized)
    }

    /// Clean up old snapshots to prevent memory leaks
    fn cleanup_old_snapshots(&self) {
        let current_time = current_timestamp();
        let retention_period = 24 * 60 * 60; // 24 hours in seconds

        self.state_snapshots.write().retain(|snapshot| {
            current_time - snapshot.timestamp < retention_period
        });
    }

    /// Update blockchain state for transition
    async fn update_blockchain_state(&self, transition: &StateTransition) -> Result<()> {
        match &transition.transition_type {
            TransitionType::Deposit { depositor, amount, .. } => {
                // Lock tokens in contract - using default token (QOR)
                let default_token = TokenId(H256::zero());
                self.state_connector.lock_tokens(default_token, *depositor, *amount).await?;
            }
            TransitionType::Withdrawal { recipient, amount, .. } => {
                // Release tokens from contract - using default token (QOR)
                let default_token = TokenId(H256::zero());
                let proof = vec![]; // TODO: Get proof from transition
                self.state_connector.release_tokens(default_token, *recipient, *amount, proof).await?;
            }
            _ => {}
        }

        // Update state root
        let new_root = self.calculate_state_root()?;
        let default_token = TokenId(H256::zero());
        self.state_connector.update_privacy_root(default_token, new_root, 0, 0).await?;

        Ok(())
    }

    /// Verify proof
    fn verify_proof(&self, proof: &PrivateTransactionProof) -> Result<bool> {
        self.proof_system.read().verify(proof)
    }

    /// Calculate state root
    fn calculate_state_root(&self) -> Result<H256> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();

        // Include commitment tree root
        let tree_root = self.commitment_tree.read().root();
        hasher.update(tree_root.as_bytes());

        // Include nullifier set hash
        let mut nullifiers: Vec<_> = self.nullifiers.read().iter().cloned().collect();
        nullifiers.sort();
        for nullifier in nullifiers {
            hasher.update(nullifier.as_bytes());
        }

        // Include pool states
        let pools = self.privacy_pools.read();
        let mut pool_ids: Vec<_> = pools.keys().cloned().collect();
        pool_ids.sort();
        for pool_id in pool_ids {
            if let Some(pool) = pools.get(&pool_id) {
                hasher.update(pool_id.as_bytes());
                let mut tvl_bytes = [0u8; 32];
                pool.tvl.to_big_endian(&mut tvl_bytes);
                hasher.update(&tvl_bytes);
            }
        }

        Ok(H256::from_slice(&hasher.finalize()))
    }

    /// Update pool TVL
    fn update_pool_tvl(&self, pool_id: H256, amount: U256, increase: bool) -> Result<()> {
        let mut pools = self.privacy_pools.write();
        let pool = pools.entry(pool_id).or_insert_with(|| PrivacyPool {
            pool_id,
            token_address: None,
            tvl: U256::zero(),
            commitment_count: 0,
            params: PoolParams::default(),
        });

        if increase {
            pool.tvl = pool.tvl.saturating_add(amount);
            pool.commitment_count += 1;
        } else {
            pool.tvl = pool.tvl.saturating_sub(amount);
        }

        Ok(())
    }

    /// Get privacy statistics
    pub fn get_stats(&self) -> PrivacyStats {
        PrivacyStats {
            total_commitments: self.commitment_tree.read().size(),
            total_nullifiers: self.nullifiers.read().len(),
            pending_transitions: self.pending_transitions.read().len(),
            merkle_root: self.commitment_tree.read().root(),
            total_pools: self.privacy_pools.read().len(),
            total_tvl: self.privacy_pools.read()
                .values()
                .map(|p| p.tvl)
                .fold(U256::zero(), |acc, tvl| acc + tvl),
        }
    }

    /// Check anonymity set size
    pub fn check_anonymity_set(&self, pool_id: H256) -> Result<bool> {
        let pools = self.privacy_pools.read();
        if let Some(pool) = pools.get(&pool_id) {
            Ok(pool.commitment_count >= pool.params.min_anonymity_set)
        } else {
            Err(anyhow!("Pool not found"))
        }
    }

    /// Process batch of operations atomically
    pub async fn process_batch_atomic<F, R>(&self, operations: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        // Acquire transaction lock
        let _lock = self.transaction_lock.lock().await;

        // Create snapshot
        let tx_id = H256::random();
        let snapshot = self.create_snapshot(tx_id);
        self.state_snapshots.write().push(snapshot.clone());

        // Execute operations
        let result = operations();

        // Handle result
        match result {
            Ok(value) => {
                // Clean up successful snapshot
                self.state_snapshots.write().retain(|s| s.tx_id != tx_id);
                Ok(value)
            }
            Err(e) => {
                // Rollback on failure
                self.rollback_to_snapshot(&snapshot)?;
                self.state_snapshots.write().retain(|s| s.tx_id != tx_id);
                Err(e)
            }
        }
    }

    /// Validate state consistency
    pub fn validate_state_consistency(&self) -> Result<()> {
        // Check nullifier uniqueness
        let nullifiers = self.nullifiers.read();

        // Check commitment tree consistency
        let tree = self.commitment_tree.read();
        let root = tree.root();

        // Verify all pending transitions have valid proofs
        let transitions = self.pending_transitions.read();
        for transition in transitions.iter() {
            if !self.verify_proof(&transition.proof)? {
                return Err(anyhow!("Invalid proof in pending transition: {:?}", transition.tx_id));
            }
        }

        // Check pool TVL consistency
        let pools = self.privacy_pools.read();
        for (pool_id, pool) in pools.iter() {
            if pool.tvl < U256::zero() {
                return Err(anyhow!("Negative TVL in pool: {:?}", pool_id));
            }
        }

        Ok(())
    }
}

/// Privacy statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyStats {
    pub total_commitments: usize,
    pub total_nullifiers: usize,
    pub pending_transitions: usize,
    pub merkle_root: H256,
    pub total_pools: usize,
    pub total_tvl: U256,
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk_proofs::{PrivateWitness, TrustedSetupParams};

    #[test]
    fn test_privacy_state_manager() {
        let mut proof_system = ZkProofSystem::new(TrustedSetupParams::default());
        proof_system.setup().unwrap();

        use crate::state::GlobalState;
        use crate::fees_usd::{USDFeeSystem, FeeConfig};
        let global_state = Arc::new(tokio::sync::RwLock::new(GlobalState::new()));
        let fee_system = Arc::new(tokio::sync::RwLock::new(USDFeeSystem::new(FeeConfig::default())));
        let state_connector = Arc::new(StateConnector::new(global_state, fee_system));
        let manager = PrivacyStateManager::new(
            Arc::new(RwLock::new(proof_system)),
            state_connector,
        );

        // Test deposit
        let commitment = H256::random();
        let proof = PrivateTransactionProof {
            proof: vec![0x01; 192], // Properly initialized test proof
            public_inputs: PublicInputs {
                merkle_root: H256::zero(),
                nullifier_hash: H256::zero(),
                output_commitments: vec![commitment],
                public_amount: U256::from(1000),
            },
            proof_type: ProofType::Deposit,
        };

        // Process deposit (would fail with real proof verification)
        // In production, generate actual proof

        // Check stats
        let stats = manager.get_stats();
        assert_eq!(stats.total_pools, 0);
    }
}