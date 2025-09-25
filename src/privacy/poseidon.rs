//! Poseidon hash function implementation for privacy pools
//! Using Halo2's Poseidon implementation for consistency

use ethereum_types::H256;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, Spec};
use halo2curves::bn256::Fr;
use ff::Field;

/// Poseidon hasher wrapper using Halo2
pub struct Poseidon {
    /// Poseidon specification
    spec: poseidon::P128Pow5T3,
}

impl Poseidon {
    /// Create new Poseidon hasher with Halo2 spec
    pub fn new() -> Self {
        Self {
            spec: poseidon::P128Pow5T3,
        }
    }

    /// Hash two field elements using Halo2 Poseidon
    pub fn hash2(&mut self, left: H256, right: H256) -> H256 {
        // Convert H256 to field elements
        let left_fr = h256_to_field(left);
        let right_fr = h256_to_field(right);

        // Use Halo2's Poseidon hash
        let message = [left_fr, right_fr];
        let output = poseidon::Hash::<_, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init()
            .hash(message);

        // Convert back to H256
        field_to_h256(output)
    }

    /// Hash multiple field elements
    pub fn hash_n(&mut self, inputs: &[H256]) -> H256 {
        if inputs.is_empty() {
            return H256::zero();
        }
        if inputs.len() == 1 {
            return inputs[0];
        }

        // For multiple inputs, chain hashes
        let mut result = inputs[0];
        for input in &inputs[1..] {
            result = self.hash2(result, *input);
        }
        result
    }
}

/// Convert H256 to field element
fn h256_to_field(h: H256) -> Fr {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(h.as_bytes());
    // Use from_bytes for halo2curves
    Fr::from_bytes(&bytes).unwrap_or(Fr::zero())
}

/// Convert field element to H256
fn field_to_h256(f: Fr) -> H256 {
    let bytes = f.to_bytes();
    H256::from_slice(&bytes)
}

/// Public function for hashing two H256 values using Poseidon
pub fn poseidon_hash(left: H256, right: H256) -> H256 {
    let mut hasher = Poseidon::new();
    hasher.hash2(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash2() {
        let mut poseidon = Poseidon::new();

        let left = H256::from_low_u64_be(100);
        let right = H256::from_low_u64_be(200);

        let hash1 = poseidon.hash2(left, right);
        let hash2 = poseidon.hash2(left, right);

        // Should be deterministic
        assert_eq!(hash1, hash2);

        // Should not be zero
        assert_ne!(hash1, H256::zero());

        // Different inputs should produce different outputs
        let hash3 = poseidon.hash2(right, left);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_n_empty() {
        let mut poseidon = Poseidon::new();
        let result = poseidon.hash_n(&[]);
        assert_eq!(result, H256::zero());
    }

    #[test]
    fn test_hash_n_single() {
        let mut poseidon = Poseidon::new();
        let input = H256::from_low_u64_be(42);
        let result = poseidon.hash_n(&[input]);
        assert_eq!(result, input);
    }

    #[test]
    fn test_hash_n_multiple() {
        let mut poseidon = Poseidon::new();

        let inputs = vec![
            H256::from_low_u64_be(1),
            H256::from_low_u64_be(2),
            H256::from_low_u64_be(3),
            H256::from_low_u64_be(4),
        ];

        let hash = poseidon.hash_n(&inputs);

        // Should not be zero
        assert_ne!(hash, H256::zero());

        // Should be different from any input
        for input in &inputs {
            assert_ne!(hash, *input);
        }
    }

    #[test]
    fn test_public_hash() {
        let left = H256::from_low_u64_be(111);
        let right = H256::from_low_u64_be(222);

        let hash1 = poseidon_hash(left, right);
        let hash2 = poseidon_hash(left, right);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, H256::zero());
    }
}