//! Halo2 Circuit Implementation for Privacy Features
//!
//! Implements ZK proofs using BN256 curve for EVM compatibility

use anyhow::{Result, anyhow};
use ethereum_types::{H256, U256};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    dev::{FailureLocation, MockProver, VerifyFailure},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed,
        Instance, Selector, create_proof, keygen_pk, keygen_vk, verify_proof,
        ProvingKey, VerifyingKey,
    },
    poly::{
        Rotation,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGV21, VerifierGV21},
            strategy::SingleStrategy,
        },
        commitment::ParamsProver,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand::rngs::OsRng;
use ff::PrimeField;

/// Privacy circuit configuration
#[derive(Clone, Debug)]
pub struct PrivacyConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    fixed: Column<Fixed>,
    s_add: Selector,
    s_mul: Selector,
    s_poseidon: Selector,
}

/// Privacy chip for circuit operations
pub struct PrivacyChip {
    config: PrivacyConfig,
}

impl Chip<Fr> for PrivacyChip {
    type Config = PrivacyConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl PrivacyChip {
    pub fn construct(config: PrivacyConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
        fixed: Column<Fixed>,
    ) -> PrivacyConfig {
        for column in &advice {
            meta.enable_equality(*column);
        }
        meta.enable_equality(instance);

        let s_add = meta.selector();
        let s_mul = meta.selector();
        let s_poseidon = meta.selector();

        // Addition constraint: a + b = c
        meta.create_gate("add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a + b - c)]
        });

        // Multiplication constraint: a * b = c
        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a * b - c)]
        });

        // Poseidon S-box constraint (x^5 for BN256)
        meta.create_gate("poseidon", |meta| {
            let s = meta.query_selector(s_poseidon);
            let input = meta.query_advice(advice[0], Rotation::cur());
            let output = meta.query_advice(advice[2], Rotation::cur());
            
            let x2 = input.clone() * input.clone();
            let x4 = x2.clone() * x2;
            let x5 = x4 * input;
            
            vec![s * (x5 - output)]
        });

        PrivacyConfig {
            advice,
            instance,
            fixed,
            s_add,
            s_mul,
            s_poseidon,
        }
    }

    pub fn commit(
        &self,
        mut layouter: impl Layouter<Fr>,
        secret: Value<Fr>,
        amount: Value<Fr>,
        blinding: Value<Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        layouter.assign_region(
            || "commitment",
            |mut region| {
                self.config.s_add.enable(&mut region, 0)?;
                self.config.s_add.enable(&mut region, 1)?;

                let secret_cell = region.assign_advice(
                    || "secret",
                    self.config.advice[0],
                    0,
                    || secret,
                )?;

                let amount_cell = region.assign_advice(
                    || "amount",
                    self.config.advice[1],
                    0,
                    || amount,
                )?;

                let sum = secret.and_then(|s| amount.map(|a| s + a));
                let sum_cell = region.assign_advice(
                    || "sum",
                    self.config.advice[2],
                    0,
                    || sum,
                )?;

                let blinding_cell = region.assign_advice(
                    || "blinding",
                    self.config.advice[1],
                    1,
                    || blinding,
                )?;

                let commitment = sum.and_then(|s| blinding.map(|b| s + b));
                let commitment_cell = region.assign_advice(
                    || "commitment",
                    self.config.advice[2],
                    1,
                    || commitment,
                )?;

                Ok(commitment_cell)
            },
        )
    }

    pub fn nullifier(
        &self,
        mut layouter: impl Layouter<Fr>,
        secret: Value<Fr>,
        index: Value<Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        layouter.assign_region(
            || "nullifier",
            |mut region| {
                self.config.s_poseidon.enable(&mut region, 0)?;

                let secret_cell = region.assign_advice(
                    || "secret",
                    self.config.advice[0],
                    0,
                    || secret,
                )?;

                // Apply Poseidon S-box to secret
                let secret_sbox = secret.map(|s| {
                    let s2 = s * s;
                    let s4 = s2 * s2;
                    s4 * s  // s^5
                });

                let nullifier_cell = region.assign_advice(
                    || "nullifier",
                    self.config.advice[2],
                    0,
                    || secret_sbox,
                )?;

                Ok(nullifier_cell)
            },
        )
    }
}

/// Private transfer circuit
#[derive(Default, Clone)]
pub struct PrivateTransferCircuit {
    pub secret: Value<Fr>,
    pub amount: Value<Fr>,
    pub blinding: Value<Fr>,
    pub leaf_index: Value<Fr>,
    pub commitment: Value<Fr>,
    pub nullifier: Value<Fr>,
}

impl Circuit<Fr> for PrivateTransferCircuit {
    type Config = PrivacyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();

        PrivacyChip::configure(meta, advice, instance, fixed)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = PrivacyChip::construct(config.clone());

        let commitment = chip.commit(
            layouter.namespace(|| "compute commitment"),
            self.secret,
            self.amount,
            self.blinding,
        )?;

        let nullifier = chip.nullifier(
            layouter.namespace(|| "compute nullifier"),
            self.secret,
            self.leaf_index,
        )?;

        layouter.constrain_instance(commitment.cell(), config.instance, 0)?;
        layouter.constrain_instance(nullifier.cell(), config.instance, 1)?;

        Ok(())
    }
}

/// Halo2 proof system for BN256
pub struct Halo2ProofSystem {
    params: ParamsKZG<Bn256>,
    pk: Option<ProvingKey<G1Affine>>,
    vk: Option<VerifyingKey<G1Affine>>,
}

impl Halo2ProofSystem {
    pub fn new(k: u32) -> Self {
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        Self {
            params,
            pk: None,
            vk: None,
        }
    }

    pub fn setup(&mut self, circuit: &PrivateTransferCircuit) -> Result<()> {
        let vk = keygen_vk(&self.params, circuit)
            .map_err(|e| anyhow!("VK generation failed: {:?}", e))?;

        let pk = keygen_pk(&self.params, vk.clone(), circuit)
            .map_err(|e| anyhow!("PK generation failed: {:?}", e))?;

        self.vk = Some(vk);
        self.pk = Some(pk);

        Ok(())
    }

    pub fn prove(
        &self,
        circuit: PrivateTransferCircuit,
        public_inputs: &[Fr],
    ) -> Result<Vec<u8>> {
        let pk = self.pk.as_ref()
            .ok_or_else(|| anyhow!("Proving key not initialized"))?;

        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        create_proof::<KZGCommitmentScheme<Bn256>, ProverGV21<_>, _, _, _, _>(
            &self.params,
            pk,
            &[circuit],
            &[&[public_inputs]],
            OsRng,
            &mut transcript,
        ).map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;

        Ok(transcript.finalize())
    }

    pub fn verify(&self, proof: &[u8], public_inputs: &[Fr]) -> Result<bool> {
        let vk = self.vk.as_ref()
            .ok_or_else(|| anyhow!("Verifying key not initialized"))?;

        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof);
        let strategy = SingleStrategy::new(&self.params);

        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierGV21<_>, _, _, _>(
            &self.params,
            vk,
            strategy,
            &[&[public_inputs]],
            &mut transcript,
        ).map_err(|e| anyhow!("Verification failed: {:?}", e))?;

        Ok(true)
    }

    /// Create proof from UniversalSwitch parameters
    pub fn create_switch_proof(
        &self,
        secret: H256,
        amount: U256,
        blinding: H256,
    ) -> Result<(Vec<u8>, H256, H256)> {
        let secret_fr = h256_to_field(secret);
        let amount_fr = u256_to_field(amount);
        let blinding_fr = h256_to_field(blinding);
        
        // Calculate commitment and nullifier
        let commitment_fr = secret_fr + amount_fr + blinding_fr;
        let nullifier_fr = {
            let s2 = secret_fr * secret_fr;
            let s4 = s2 * s2;
            s4 * secret_fr  // s^5 (Poseidon S-box)
        };
        
        let circuit = PrivateTransferCircuit {
            secret: Value::known(secret_fr),
            amount: Value::known(amount_fr),
            blinding: Value::known(blinding_fr),
            leaf_index: Value::known(Fr::zero()),
            commitment: Value::known(commitment_fr),
            nullifier: Value::known(nullifier_fr),
        };
        
        let public_inputs = vec![commitment_fr, nullifier_fr];
        let proof = self.prove(circuit, &public_inputs)?;
        
        Ok((
            proof,
            field_to_h256(commitment_fr),
            field_to_h256(nullifier_fr),
        ))
    }
}

/// Convert H256 to BN256 field element
pub fn h256_to_field(h: H256) -> Fr {
    let bytes = h.as_bytes();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(bytes);
    Fr::from_bytes_wide(&wide)
}

/// Convert U256 to field element
pub fn u256_to_field(u: U256) -> Fr {
    let mut bytes = [0u8; 32];
    u.to_little_endian(&mut bytes);
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&bytes);
    Fr::from_bytes_wide(&wide)
}

/// Convert field element to H256
pub fn field_to_h256(f: Fr) -> H256 {
    let bytes = f.to_bytes();
    H256::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bn256_circuit() {
        let k = 4;

        let circuit = PrivateTransferCircuit {
            secret: Value::known(Fr::from(42)),
            amount: Value::known(Fr::from(1000)),
            blinding: Value::known(Fr::from(123)),
            leaf_index: Value::known(Fr::zero()),
            commitment: Value::known(Fr::from(1165)),
            nullifier: Value::known(Fr::from(130691232)), // 42^5
        };

        let public_inputs = vec![
            Fr::from(1165),
            Fr::from(130691232),
        ];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn test_proof_generation() {
        let mut proof_system = Halo2ProofSystem::new(11);
        let circuit = PrivateTransferCircuit::default();
        proof_system.setup(&circuit).unwrap();

        let secret = H256::random();
        let amount = U256::from(1000);
        let blinding = H256::random();

        let (proof, commitment, nullifier) = proof_system
            .create_switch_proof(secret, amount, blinding)
            .unwrap();

        assert!(!proof.is_empty());
        assert_ne!(commitment, H256::zero());
        assert_ne!(nullifier, H256::zero());
    }
}