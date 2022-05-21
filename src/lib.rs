#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_imports)]
#![allow(clippy::op_ref, clippy::type_complexity)]

use ark_ff::{PrimeField, ToBytes};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_sponge::constraints::AbsorbGadget;
use ark_sponge::Absorb;
use ark_std::rand::{CryptoRng, RngCore};
use ark_std::{boxed::Box, fmt::Debug};

#[macro_use]
extern crate derivative;

pub type Error = Box<dyn ark_std::error::Error + 'static>;

pub trait PCDPredicate<F: PrimeField>: Clone {
    type Message: Absorb + ToBytes + Sized + Clone + Default;
    type MessageVar: AbsorbGadget<F> + ToBytesGadget<F> + AllocVar<Self::Message, F>;

    type LocalWitness: Sized + Clone + Default;
    type LocalWitnessVar: AllocVar<Self::LocalWitness, F>;

    const PRIOR_MSG_LEN: usize;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        msg: &Self::MessageVar,
        witness: &Self::LocalWitnessVar,
        prior_msgs: &[Self::MessageVar],
        base_case: &Boolean<F>,
    ) -> Result<(), SynthesisError>;
}

pub trait PCD<F: PrimeField> {
    type ProvingKey: Clone;
    type VerifyingKey: Clone;
    type Proof: Clone;

    fn circuit_specific_setup<P: PCDPredicate<F>, R: RngCore + CryptoRng>(
        predicate: &P,
        rng: &mut R,
    ) -> Result<(<Self as PCD<F>>::ProvingKey, <Self as PCD<F>>::VerifyingKey), Error>;

    fn prove<P: PCDPredicate<F>, R: RngCore + CryptoRng>(
        predicate_pk: &Self::ProvingKey,
        predicate: &P,
        msg: &P::Message,
        witness: &P::LocalWitness,
        prior_msgs: &[P::Message],
        prior_proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<Self::Proof, Error>;

    fn verify<P: PCDPredicate<F>>(
        predicate_vk: &Self::VerifyingKey,
        msg: &P::Message,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
}

pub trait CircuitSpecificSetupPCD<F: PrimeField>: PCD<F> {}

pub trait UniversalSetupPCD<F: PrimeField>: PCD<F> {
    type PredicateBound: Clone + Default + Debug;
    type PublicParameters: Clone;

    fn universal_setup<R: RngCore + CryptoRng>(
        predicate_bound: &Self::PredicateBound,
        rng: &mut R,
    ) -> Result<Self::PublicParameters, Error>;

    fn index<P: PCDPredicate<F>, R: RngCore + CryptoRng>(
        pp: &Self::PublicParameters,
        predicate: &P,
        rng: &mut R,
    ) -> Result<(<Self as PCD<F>>::ProvingKey, <Self as PCD<F>>::VerifyingKey), Error>;
}

/// Common errors that PCD schemes may throw.
pub mod error;

pub mod ec_cycle_pcd;
pub mod variable_length_crh;

/// A PCD that does not rely on SNARKs but instead builds on an R1CS NARK construction and its
/// accumulation scheme.
/// The implementation is based on the construction detailed in Section 5 of [\[BCLMS20\]][bclms20].
///
/// [bclms20]: https://eprint.iacr.org/2020/1618
pub mod r1cs_nark_pcd;

#[cfg(test)]
pub mod tests {
    use crate::{PCDPredicate, PCD};
    use ark_ff::PrimeField;
    use ark_r1cs_std::bits::boolean::Boolean;
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
    use ark_sponge::Absorb;
    use ark_std::marker::PhantomData;

    #[derive(Clone)]
    pub struct TestIVCPredicate<F: PrimeField + Absorb> {
        pub field_phantom: PhantomData<F>,
    }

    impl<F: PrimeField + Absorb> TestIVCPredicate<F> {
        fn new() -> Self {
            Self {
                field_phantom: PhantomData,
            }
        }
    }

    impl<F: PrimeField + Absorb> PCDPredicate<F> for TestIVCPredicate<F> {
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

    #[derive(Clone)]
    pub struct TestPCDPredicate<F: PrimeField + Absorb> {
        pub field_phantom: PhantomData<F>,
    }

    impl<F: PrimeField + Absorb> TestPCDPredicate<F> {
        fn new() -> Self {
            Self {
                field_phantom: PhantomData,
            }
        }
    }

    impl<F: PrimeField + Absorb> PCDPredicate<F> for TestPCDPredicate<F> {
        type Message = F;
        type MessageVar = FpVar<F>;
        type LocalWitness = F;
        type LocalWitnessVar = FpVar<F>;

        const PRIOR_MSG_LEN: usize = 2;

        fn generate_constraints(
            &self,
            _cs: ConstraintSystemRef<F>,
            msg: &Self::MessageVar,
            witness: &Self::LocalWitnessVar,
            prior_msgs: &[Self::MessageVar],
            _base_case: &Boolean<F>,
        ) -> Result<(), SynthesisError> {
            let msg_supposed = &prior_msgs[0] + &prior_msgs[1] + witness;
            msg_supposed.enforce_equal(&msg)?;

            Ok(())
        }
    }

    pub fn test_ivc_base_case<F: PrimeField + Absorb, TestPCD: PCD<F>>() {
        let mut rng = ark_std::test_rng();

        let witness = F::one();
        let msg_0 = F::one();

        let circ = TestIVCPredicate::<F>::new();
        let (pk, vk) = TestPCD::circuit_specific_setup(&circ, &mut rng).unwrap();

        let proof_0 = TestPCD::prove(&pk, &circ, &msg_0, &witness, &[], &[], &mut rng).unwrap();
        assert!(TestPCD::verify::<TestIVCPredicate<F>>(&vk, &msg_0, &proof_0).unwrap());
    }

    pub fn test_ivc<F: PrimeField + Absorb, TestPCD: PCD<F>>() {
        let mut rng = ark_std::test_rng();

        let witness = F::one();
        let msg_0 = F::one();
        let msg_1 = msg_0 + &witness;
        let msg_2 = msg_1 + &witness;

        let circ = TestIVCPredicate::<F>::new();
        let (pk, vk) = TestPCD::circuit_specific_setup(&circ, &mut rng).unwrap();

        let proof_0 = TestPCD::prove(&pk, &circ, &msg_0, &witness, &[], &[], &mut rng).unwrap();
        assert!(TestPCD::verify::<TestIVCPredicate<F>>(&vk, &msg_0, &proof_0).unwrap());

        let proof_1 = TestPCD::prove(
            &pk,
            &circ,
            &msg_1,
            &witness,
            &[msg_0],
            &vec![proof_0],
            &mut rng,
        )
        .unwrap();
        assert!(TestPCD::verify::<TestIVCPredicate<F>>(&vk, &msg_1, &proof_1).unwrap());

        let proof_2 = TestPCD::prove(
            &pk,
            &circ,
            &msg_2,
            &witness,
            &[msg_1],
            &vec![proof_1],
            &mut rng,
        )
        .unwrap();
        assert!(TestPCD::verify::<TestIVCPredicate<F>>(&vk, &msg_2, &proof_2).unwrap());
    }

    pub fn test_pcd<F: PrimeField + Absorb, TestPCD: PCD<F>>() {
        let mut rng = ark_std::test_rng();

        let witness = F::one();
        let msg_0 = F::one();
        let msg_1 = msg_0 + &msg_0 + &witness;
        let msg_2 = msg_1 + &msg_1 + &witness;

        let circ = TestPCDPredicate::<F>::new();
        let (pk, vk) = TestPCD::circuit_specific_setup(&circ, &mut rng).unwrap();

        let proof_0 = TestPCD::prove(&pk, &circ, &msg_0, &witness, &[], &[], &mut rng).unwrap();
        assert!(TestPCD::verify::<TestPCDPredicate<F>>(&vk, &msg_0, &proof_0).unwrap());

        let proof_1 = TestPCD::prove(
            &pk,
            &circ,
            &msg_1,
            &witness,
            &[msg_0, msg_0],
            &vec![proof_0.clone(), proof_0],
            &mut rng,
        )
        .unwrap();
        assert!(TestPCD::verify::<TestPCDPredicate<F>>(&vk, &msg_1, &proof_1).unwrap());

        let proof_2 = TestPCD::prove(
            &pk,
            &circ,
            &msg_2,
            &witness,
            &[msg_1, msg_1],
            &vec![proof_1.clone(), proof_1],
            &mut rng,
        )
        .unwrap();
        assert!(TestPCD::verify::<TestPCDPredicate<F>>(&vk, &msg_2, &proof_2).unwrap());
    }
}
