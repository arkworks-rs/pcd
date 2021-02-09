#![allow(clippy::op_ref, clippy::type_complexity)]

use ark_ed_on_mnt4_298::EdwardsParameters;
use ark_ff::{One, PrimeField};
use ark_groth16::{constraints::Groth16VerifierGadget, Groth16};
use ark_mnt4_298::constraints::PairingVar as MNT4PairingVar;
use ark_mnt4_298::{Fq, Fr, MNT4_298};
use ark_mnt6_298::constraints::PairingVar as MNT6PairingVar;
use ark_mnt6_298::MNT6_298;
use ark_pcd::ec_cycle_pcd::{ECCyclePCD, ECCyclePCDConfig};
use ark_pcd::variable_length_crh::bowe_hopwood::constraints::VariableLengthBoweHopwoodCompressedCRHGadget;
use ark_pcd::variable_length_crh::bowe_hopwood::VariableLengthBoweHopwoodCompressedCRH;
use ark_pcd::{PCDPredicate, PCD};
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;
use core::marker::PhantomData;
use rand_chacha::ChaChaRng;

pub struct PCDGroth16Mnt4;
impl ECCyclePCDConfig<Fr, Fq> for PCDGroth16Mnt4 {
    type CRH = VariableLengthBoweHopwoodCompressedCRH<ChaChaRng, EdwardsParameters>;
    type CRHGadget = VariableLengthBoweHopwoodCompressedCRHGadget<ChaChaRng, EdwardsParameters>;
    type MainSNARK = Groth16<MNT4_298>;
    type HelpSNARK = Groth16<MNT6_298>;
    type MainSNARKGadget = Groth16VerifierGadget<MNT4_298, MNT4PairingVar>;
    type HelpSNARKGadget = Groth16VerifierGadget<MNT6_298, MNT6PairingVar>;
}

pub struct TestPredicate<F: PrimeField> {
    pub field_phantom: PhantomData<F>,
}

impl<F: PrimeField> TestPredicate<F> {
    fn new() -> Self {
        Self {
            field_phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> Clone for TestPredicate<F> {
    fn clone(&self) -> Self {
        Self {
            field_phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> PCDPredicate<F> for TestPredicate<F> {
    type Message = F;
    type MessageVar = FpVar<F>;
    type LocalWitness = F;
    type LocalWitnessVar = FpVar<F>;

    const PRIOR_MSG_LEN: usize = 1;

    fn generate_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        msg: &Self::MessageVar,
        witness: &Self::LocalWitnessVar,
        prior_msgs: &[Self::MessageVar],
        _base_case: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        let msg_supposed = &prior_msgs[0] + witness;
        msg_supposed.enforce_equal(&msg)?;

        Ok(())
    }
}

type TestPCD = ECCyclePCD<Fr, Fq, PCDGroth16Mnt4>;

#[test]
fn test_mnt4_groth16_pcd() {
    let val_1 = Fr::one();

    let circ = TestPredicate::<Fr>::new();
    let mut rng = ark_std::test_rng();

    let (pk, vk) = TestPCD::circuit_specific_setup(&circ, &mut rng).unwrap();

    let proof_1 = TestPCD::prove(&pk, &circ, &val_1, &val_1, &[], &[], &mut rng).unwrap();
    assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_1, &proof_1).unwrap());

    #[cfg(not(ci))]
    {
        let val_2 = val_1 + &val_1;

        let proof_2 = TestPCD::prove(
            &pk,
            &circ,
            &val_2,
            &val_1,
            &[val_1],
            &vec![proof_1],
            &mut rng,
        )
        .unwrap();
        assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_2, &proof_2).unwrap());

        let val_3 = val_1 + &val_2;

        let proof_3 = TestPCD::prove(
            &pk,
            &circ,
            &val_3,
            &val_1,
            &[val_2],
            &vec![proof_2],
            &mut rng,
        )
        .unwrap();
        assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_3, &proof_3).unwrap());

        assert!(!TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_1, &proof_3).unwrap());
    }
}
