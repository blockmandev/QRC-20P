//! Poseidon hash function implementation for privacy pools
//! Using Halo2's Poseidon implementation for consistency

use ethereum_types::H256;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, Spec};
use halo2curves::bn256::Fr;
use ff::Field;

/// Poseidon hasher wrapper using Halo2
pub struct Poseidon {
    /// Poseidon specification
    spec: Spec<Fr, 3, 2>,
}

impl Poseidon {
    /// Create new Poseidon hasher with Halo2 spec
    pub fn new() -> Self {
        Self {
            spec: Spec::new(8, 57), // Standard parameters for BN256
        }
    }

    /// Hash two field elements using Halo2's Poseidon
    pub fn hash2(&mut self, left: H256, right: H256) -> H256 {
        // Convert H256 to Fr (BN256 field element)
        let left_fr = h256_to_fr(&left);
        let right_fr = h256_to_fr(&right);

        // Use Halo2's Poseidon with ConstantLength domain
        let message = [left_fr, right_fr];
        let hasher = poseidon::Hash::<_, _, ConstantLength<2>, 3, 2>::init(&self.spec);
        let result = hasher.hash(message);

        // Convert result back to H256
        fr_to_h256(&result)
    }

    /// Hash multiple field elements
    pub fn hash_n(&mut self, inputs: &[H256]) -> H256 {
        if inputs.is_empty() {
            return H256::zero();
        }
        if inputs.len() == 1 {
            return inputs[0];
        }

        // Convert all inputs to Fr elements
        let frs: Vec<Fr> = inputs.iter()
            .map(|h| h256_to_fr(h))
            .collect();

        // Hash using Halo2's Poseidon
        // For variable length, we hash in pairs recursively
        let result = if frs.len() == 2 {
            let hasher = poseidon::Hash::<_, _, ConstantLength<2>, 3, 2>::init(&self.spec);
            hasher.hash([frs[0], frs[1]])
        } else if frs.len() == 3 {
            let hasher = poseidon::Hash::<_, _, ConstantLength<3>, 4, 3>::init(&self.spec);
            hasher.hash([frs[0], frs[1], frs[2]])
        } else {
            // For larger inputs, hash in pairs recursively
            let mut current = frs[0];
            for fr in frs.iter().skip(1) {
                let hasher = poseidon::Hash::<_, _, ConstantLength<2>, 3, 2>::init(&self.spec);
                current = hasher.hash([current, *fr]);
            }
            current
        };

        fr_to_h256(&result)
    }
}

/// Convert H256 to Fr (BN256 field element) for hashing
fn h256_to_fr(h: &H256) -> Fr {
    // Convert H256 bytes to a field element
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(h.as_bytes());

    // Create a 64-byte array for from_bytes_wide
    let mut wide_bytes = [0u8; 64];
    wide_bytes[..32].copy_from_slice(&bytes);

    // Use from_bytes_wide which properly reduces modulo the field order
    Fr::from_bytes_wide(&wide_bytes)
}

/// Convert Fr back to H256
fn fr_to_h256(fr: &Fr) -> H256 {
    let bytes = fr.to_repr();
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
    fn test_poseidon_hash2() {
        let mut hasher = Poseidon::new();

        let left = H256::from_low_u64_be(123);
        let right = H256::from_low_u64_be(456);

        let hash1 = hasher.hash2(left, right);
        let hash2 = hasher.hash2(left, right);

        // Should be deterministic
        assert_eq!(hash1, hash2);

        // Should not be zero
        assert_ne!(hash1, H256::zero());

        // Should be different from inputs
        assert_ne!(hash1, left);
        assert_ne!(hash1, right);
    }

    #[test]
    fn test_poseidon_hash_n() {
        let mut hasher = Poseidon::new();

        let inputs = vec![
            H256::from_low_u64_be(1),
            H256::from_low_u64_be(2),
            H256::from_low_u64_be(3),
        ];

        let hash = hasher.hash_n(&inputs);

        // Should not be zero
        assert_ne!(hash, H256::zero());

        // Should be different from any input
        for input in &inputs {
            assert_ne!(hash, *input);
        }
    }
}