//! Merkle Tree Implementation for Privacy Commitments
//!
//! Optimized for ZK-SNARK circuits with sparse tree support

use anyhow::{Result, anyhow};
use ethereum_types::H256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::poseidon::poseidon_hash;  // Use real Poseidon hash for ZK circuits

// Removed Keccak256 fallback - using real Poseidon hash

/// Merkle tree for commitments
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Tree height
    pub height: usize,
    /// Leaf nodes
    leaves: Vec<H256>,
    /// Internal nodes (level, index) -> hash
    nodes: HashMap<(usize, usize), H256>,
    /// Current root
    root: H256,
    /// Zero hashes for each level
    zero_hashes: Vec<H256>,
}

impl MerkleTree {
    /// Create new merkle tree
    pub fn new(height: usize) -> Self {
        let zero_hashes = Self::compute_zero_hashes(height);
        let root = zero_hashes[height].clone();
        
        Self {
            height,
            leaves: Vec::new(),
            nodes: HashMap::new(),
            root,
            zero_hashes,
        }
    }
    
    /// Compute zero hashes for sparse tree
    fn compute_zero_hashes(height: usize) -> Vec<H256> {
        let mut hashes = vec![H256::zero(); height + 1];
        
        for level in 1..=height {
            let child = hashes[level - 1];
            hashes[level] = poseidon_hash(child, child);
        }
        
        hashes
    }
    
    /// Insert a new leaf
    pub fn insert(&mut self, leaf: H256) -> Result<usize> {
        let max_leaves = 1 << self.height;
        if self.leaves.len() >= max_leaves {
            return Err(anyhow!("Tree is full"));
        }
        
        let index = self.leaves.len();
        self.leaves.push(leaf);
        
        // Update the tree
        self.update_tree(index)?;
        
        Ok(index)
    }
    
    /// Update tree after insertion
    fn update_tree(&mut self, leaf_index: usize) -> Result<()> {
        let mut current_hash = self.leaves[leaf_index];
        let mut current_index = leaf_index;
        
        for level in 0..self.height {
            // Store current node
            self.nodes.insert((level, current_index), current_hash);
            
            // Get sibling
            let sibling_index = current_index ^ 1;
            let sibling_hash = if level == 0 && sibling_index < self.leaves.len() {
                self.leaves[sibling_index]
            } else {
                self.nodes.get(&(level, sibling_index))
                    .copied()
                    .unwrap_or(self.zero_hashes[level])
            };
            
            // Compute parent hash
            let parent_hash = if current_index % 2 == 0 {
                poseidon_hash(current_hash, sibling_hash)
            } else {
                poseidon_hash(sibling_hash, current_hash)
            };
            
            // Move up
            current_index /= 2;
            current_hash = parent_hash;
        }
        
        // Update root
        self.root = current_hash;
        Ok(())
    }
    
    /// Get merkle proof for a leaf
    pub fn get_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(anyhow!("Leaf index out of bounds"));
        }
        
        let mut path = Vec::new();
        let mut path_indices = Vec::new();
        let mut current_index = leaf_index;
        
        for level in 0..self.height {
            let sibling_index = current_index ^ 1;
            let sibling_hash = if level == 0 && sibling_index < self.leaves.len() {
                self.leaves[sibling_index]
            } else {
                self.nodes.get(&(level, sibling_index))
                    .copied()
                    .unwrap_or(self.zero_hashes[level])
            };
            
            path.push(sibling_hash);
            path_indices.push(current_index % 2 == 1);
            current_index /= 2;
        }
        
        Ok(MerkleProof {
            leaf: self.leaves[leaf_index],
            leaf_index,
            path,
            path_indices,
            root: self.root,
        })
    }
    
    /// Verify a merkle proof
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current_hash = proof.leaf;
        
        for i in 0..proof.path.len() {
            let sibling = proof.path[i];
            current_hash = if proof.path_indices[i] {
                poseidon_hash(sibling, current_hash)
            } else {
                poseidon_hash(current_hash, sibling)
            };
        }
        
        current_hash == proof.root
    }
    
    /// Get current root
    pub fn root(&self) -> H256 {
        self.root
    }
    
    /// Get number of leaves
    pub fn size(&self) -> usize {
        self.leaves.len()
    }
    
    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
    
    /// Get leaf at index
    pub fn get_leaf(&self, index: usize) -> Option<H256> {
        self.leaves.get(index).copied()
    }
    
    /// Batch insert multiple leaves
    pub fn batch_insert(&mut self, leaves: Vec<H256>) -> Result<Vec<usize>> {
        let mut indices = Vec::new();
        
        for leaf in leaves {
            let index = self.insert(leaf)?;
            indices.push(index);
        }
        
        Ok(indices)
    }
    
    /// Export tree state for persistence
    pub fn export(&self) -> TreeState {
        TreeState {
            height: self.height,
            leaves: self.leaves.clone(),
            nodes: self.nodes.clone(),
            root: self.root,
        }
    }

    /// Rollback tree to specific size
    pub fn rollback_to_size(&mut self, size: usize) -> Result<()> {
        if size > self.leaves.len() {
            return Err(anyhow!("Cannot rollback to future size"));
        }

        // Truncate leaves
        self.leaves.truncate(size);

        // Clear affected nodes
        self.nodes.retain(|(level, index), _| {
            let max_index_at_level = (size + (1 << level) - 1) >> level;
            *index < max_index_at_level
        });

        // Recalculate root
        if size == 0 {
            self.root = self.zero_hashes[self.height];
        } else {
            self.update_tree(size - 1)?;
        }

        Ok(())
    }

    /// Set root directly (for snapshot restoration)
    pub fn set_root(&mut self, root: H256) {
        self.root = root;
    }
    
    /// Import tree state
    pub fn import(state: TreeState) -> Self {
        Self {
            height: state.height,
            leaves: state.leaves,
            nodes: state.nodes,
            root: state.root,
            zero_hashes: Self::compute_zero_hashes(state.height),
        }
    }
}

/// Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: H256,
    pub leaf_index: usize,
    pub path: Vec<H256>,
    pub path_indices: Vec<bool>,
    pub root: H256,
}

/// Tree state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeState {
    pub height: usize,
    pub leaves: Vec<H256>,
    pub nodes: HashMap<(usize, usize), H256>,
    pub root: H256,
}

/// Incremental merkle tree for efficient updates
pub struct IncrementalMerkleTree {
    tree: MerkleTree,
    /// Cached roots after each insertion
    cached_roots: Vec<H256>,
    /// Maximum cached roots
    max_cache_size: usize,
}

impl IncrementalMerkleTree {
    pub fn new(height: usize) -> Self {
        Self {
            tree: MerkleTree::new(height),
            cached_roots: Vec::new(),
            max_cache_size: 100,
        }
    }
    
    pub fn insert(&mut self, leaf: H256) -> Result<usize> {
        let index = self.tree.insert(leaf)?;
        
        // Cache the new root
        self.cached_roots.push(self.tree.root());
        
        // Prune cache if too large
        if self.cached_roots.len() > self.max_cache_size {
            self.cached_roots.remove(0);
        }
        
        Ok(index)
    }
    
    pub fn is_known_root(&self, root: H256) -> bool {
        self.cached_roots.contains(&root) || self.tree.root() == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_merkle_tree() {
        let mut tree = MerkleTree::new(3);
        
        let leaf1 = H256::from_low_u64_be(1);
        let leaf2 = H256::from_low_u64_be(2);
        
        let idx1 = tree.insert(leaf1).unwrap();
        let idx2 = tree.insert(leaf2).unwrap();
        
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        
        let proof1 = tree.get_proof(0).unwrap();
        assert!(MerkleTree::verify_proof(&proof1));
    }
    
    #[test]
    fn test_incremental_tree() {
        let mut tree = IncrementalMerkleTree::new(3);
        
        let leaf = H256::from_low_u64_be(42);
        tree.insert(leaf).unwrap();
        
        let root = tree.tree.root();
        assert!(tree.is_known_root(root));
    }
}