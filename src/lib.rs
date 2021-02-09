#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_imports)]
#![allow(clippy::op_ref, clippy::type_complexity)]

use ark_ff::{PrimeField, ToBytes};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::rand::{CryptoRng, RngCore};
use ark_std::{boxed::Box, fmt::Debug};

pub type Error = Box<dyn ark_std::error::Error + 'static>;

pub trait PCDPredicate<F: PrimeField>: Clone {
    type Message: ToBytes + Sized + Clone + Default;
    type MessageVar: ToBytesGadget<F> + AllocVar<Self::Message, F>;

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

pub mod ec_cycle_pcd;
pub mod variable_length_crh;
