//! BN256-specific Poseidon spec for halo2_gadgets
//!
//! Since P128Pow5T3 only works with Pasta curves, we need a custom spec for BN256

use halo2curves_axiom::bn256::Fr;
use ff::PrimeField;

// Custom Spec trait for Poseidon since halo2-axiom doesn't have halo2_gadgets
pub trait Spec<F: PrimeField, const WIDTH: usize, const RATE: usize> {
    fn full_rounds() -> usize;
    fn partial_rounds() -> usize;
    fn sbox(val: F) -> F;
    fn constants() -> (Vec<[F; WIDTH]>, [[F; WIDTH]; WIDTH]);
}

type Mds<F, const WIDTH: usize> = [[F; WIDTH]; WIDTH];

/// Custom Poseidon specification for BN256 curve
#[derive(Clone, Copy, Debug)]
pub struct Bn256Spec<const WIDTH: usize, const RATE: usize>;

// Implementation for WIDTH=3, RATE=2 (for 2-to-1 hash)
impl Spec<Fr, 3, 2> for Bn256Spec<3, 2> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        57
    }

    fn sbox(val: Fr) -> Fr {
        // x^5 S-box
        val * val * val * val * val
    }

    fn constants() -> (Vec<[Fr; 3]>, Mds<Fr, 3>) {
        // Generate simple round constants
        // In production, use properly generated constants
        let mut round_constants = Vec::new();
        for i in 0..65 {
            let mut round = [Fr::zero(); 3];
            for j in 0..3 {
                // Simple deterministic generation
                let val = Fr::from((i * 3 + j + 1) as u64);
                round[j] = val;
            }
            round_constants.push(round);
        }

        // Simple MDS matrix for width 3
        // In production, use a properly generated MDS matrix
        let mds = [
            [Fr::from(2), Fr::from(1), Fr::from(1)],
            [Fr::from(1), Fr::from(2), Fr::from(1)],
            [Fr::from(1), Fr::from(1), Fr::from(2)],
        ];

        (round_constants, mds)
    }
}

// Implementation for WIDTH=2, RATE=1
impl Spec<Fr, 2, 1> for Bn256Spec<2, 1> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fr) -> Fr {
        // x^5 S-box
        val * val * val * val * val
    }

    fn constants() -> (Vec<[Fr; 2]>, Mds<Fr, 2>) {
        // Generate simple round constants for width=2
        let mut round_constants = Vec::new();
        for i in 0..64 {
            let mut round = [Fr::zero(); 2];
            for j in 0..2 {
                let val = Fr::from((i * 2 + j + 1) as u64);
                round[j] = val;
            }
            round_constants.push(round);
        }

        // Simple MDS matrix for width 2
        let mds = [
            [Fr::from(2), Fr::from(1)],
            [Fr::from(1), Fr::from(2)],
        ];

        (round_constants, mds)
    }
}

// Type alias for convenience
pub type Bn256PoseidonSpec = Bn256Spec<3, 2>;
pub type Bn256PoseidonSpec2 = Bn256Spec<2, 1>;