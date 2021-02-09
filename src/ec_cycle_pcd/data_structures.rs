use crate::{
    ec_cycle_pcd::ECCyclePCDConfig,
    variable_length_crh::{constraints::VariableLengthCRHGadget, VariableLengthCRH},
    PCDPredicate,
};
use ark_crypto_primitives::snark::{FromFieldElementsGadget, SNARKGadget, SNARK};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, bits::boolean::Boolean, bits::uint8::UInt8, fields::fp::FpVar, prelude::*,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

pub struct ECCyclePCDPK<
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
> {
    pub crh_pp: <IC::CRH as VariableLengthCRH<MainField>>::Parameters,
    pub main_pk: <IC::MainSNARK as SNARK<MainField>>::ProvingKey,
    pub main_pvk: <IC::MainSNARK as SNARK<MainField>>::ProcessedVerifyingKey,
    pub help_pk: <IC::HelpSNARK as SNARK<HelpField>>::ProvingKey,
    pub help_vk: <IC::HelpSNARK as SNARK<HelpField>>::VerifyingKey,
}

impl<MainField: PrimeField, HelpField: PrimeField, IC: ECCyclePCDConfig<MainField, HelpField>> Clone
    for ECCyclePCDPK<MainField, HelpField, IC>
{
    fn clone(&self) -> Self {
        Self {
            crh_pp: self.crh_pp.clone(),
            main_pk: self.main_pk.clone(),
            main_pvk: self.main_pvk.clone(),
            help_pk: self.help_pk.clone(),
            help_vk: self.help_vk.clone(),
        }
    }
}

pub struct ECCyclePCDVK<
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
> {
    pub crh_pp: <IC::CRH as VariableLengthCRH<MainField>>::Parameters,
    pub help_vk: <IC::HelpSNARK as SNARK<HelpField>>::VerifyingKey,
}

impl<MainField: PrimeField, HelpField: PrimeField, IC: ECCyclePCDConfig<MainField, HelpField>> Clone
    for ECCyclePCDVK<MainField, HelpField, IC>
{
    fn clone(&self) -> Self {
        Self {
            crh_pp: self.crh_pp.clone(),
            help_vk: self.help_vk.clone(),
        }
    }
}

pub struct DefaultCircuit {
    pub public_input_size: usize,
}

impl Clone for DefaultCircuit {
    fn clone(&self) -> Self {
        Self {
            public_input_size: self.public_input_size,
        }
    }
}

impl Copy for DefaultCircuit {}

impl<F: PrimeField> ConstraintSynthesizer<F> for DefaultCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        for _ in 0..self.public_input_size {
            let gadget = FpVar::<F>::new_input(ark_relations::ns!(cs, "alloc"), || Ok(F::one()))?;
            gadget.to_bits_le()?;
        }

        Ok(())
    }
}

pub struct MainCircuit<
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
    P: PCDPredicate<MainField>,
> {
    pub crh_pp: <IC::CRH as VariableLengthCRH<MainField>>::Parameters,
    pub predicate: P,
    pub input_hash: Option<<IC::CRH as VariableLengthCRH<MainField>>::Output>,
    pub help_vk: Option<<IC::HelpSNARK as SNARK<HelpField>>::VerifyingKey>,
    pub msg: Option<P::Message>,
    pub witness: Option<P::LocalWitness>,
    pub prior_msgs: Vec<P::Message>,
    pub prior_proofs: Vec<<IC::HelpSNARK as SNARK<HelpField>>::Proof>,
    pub base_case_bit: Option<bool>,
}

impl<
        MainField: PrimeField,
        HelpField: PrimeField,
        IC: ECCyclePCDConfig<MainField, HelpField>,
        P: PCDPredicate<MainField>,
    > ConstraintSynthesizer<MainField> for MainCircuit<MainField, HelpField, IC, P>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<MainField>,
    ) -> Result<(), SynthesisError> {
        assert!(self.base_case_bit != Some(false) || self.prior_msgs.len() == P::PRIOR_MSG_LEN);
        assert!(self.base_case_bit != Some(false) || self.prior_proofs.len() == P::PRIOR_MSG_LEN);

        /*
         * allocation
         */

        let input_hash_gadget =
            <IC::CRHGadget as VariableLengthCRHGadget<IC::CRH, MainField>>::OutputVar::new_input(
                ark_relations::ns!(cs, "alloc#x"),
                || Ok(self.input_hash.clone().unwrap_or_default()),
            )?;

        let main_public_input =
            IC::CRH::convert_output_to_field_elements(self.input_hash.unwrap_or_default()).unwrap();

        let help_public_input = <IC::MainSNARKGadget as SNARKGadget<
            MainField,
            HelpField,
            IC::MainSNARK,
        >>::InputVar::repack_input(&main_public_input);

        let default_circ = DefaultCircuit {
            public_input_size: help_public_input.len(),
        };
        let mut default_rng = ark_std::test_rng();
        let (default_pk, default_vk) =
            IC::HelpSNARK::circuit_specific_setup(default_circ, &mut default_rng).unwrap();
        let default_proof =
            <IC::HelpSNARK as SNARK<HelpField>>::prove(&default_pk, default_circ, &mut default_rng)
                .unwrap();

        let crh_pp_gadget = <IC::CRHGadget as VariableLengthCRHGadget<
            IC::CRH,
            MainField,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs,  "alloc_crh_for_cycle_ivc"),
            self.crh_pp.clone(),
        )?;

        let help_vk = self.help_vk.unwrap_or(default_vk);
        let help_vk_gadget = <IC::HelpSNARKGadget as SNARKGadget<
            HelpField,
            MainField,
            IC::HelpSNARK,
        >>::VerifyingKeyVar::new_witness(
            ark_relations::ns!(cs, "alloc#vk"), || Ok(help_vk)
        )?;

        let msg = self.msg.unwrap_or_default();
        let msg_gadget = P::MessageVar::new_witness(ark_relations::ns!(cs, "alloc_z"), || Ok(msg))?;

        let witness = self.witness.unwrap_or_default();
        let witness_gadget =
            P::LocalWitnessVar::new_witness(ark_relations::ns!(cs, "alloc_z_loc"), || Ok(witness))?;

        let mut prior_msg_gadgets = Vec::new();
        if self.base_case_bit != Some(false) {
            let default_msg = P::Message::default();
            for _ in 0..P::PRIOR_MSG_LEN {
                prior_msg_gadgets.push(P::MessageVar::new_witness(
                    ark_relations::ns!(cs, "alloc_z_in"),
                    || Ok(default_msg.clone()),
                )?);
            }
        } else {
            for prior_msg in self.prior_msgs.iter() {
                prior_msg_gadgets.push(P::MessageVar::new_witness(
                    ark_relations::ns!(cs, "alloc_z_in"),
                    || Ok(prior_msg),
                )?);
            }
        }

        let mut prior_proof_gadgets = Vec::new();
        if self.base_case_bit != Some(false) {
            for _ in 0..P::PRIOR_MSG_LEN {
                prior_proof_gadgets.push(<IC::HelpSNARKGadget as SNARKGadget<
                    HelpField,
                    MainField,
                    IC::HelpSNARK,
                >>::ProofVar::new_witness(
                    ark_relations::ns!(cs, "alloc_prior_proof"),
                    || Ok(default_proof.clone()),
                )?);
            }
        } else {
            for prior_proof in self.prior_proofs.iter() {
                prior_proof_gadgets.push(<IC::HelpSNARKGadget as SNARKGadget<
                    HelpField,
                    MainField,
                    IC::HelpSNARK,
                >>::ProofVar::new_witness(
                    ark_relations::ns!(cs, "alloc_prior_proof"),
                    || Ok(prior_proof),
                )?);
            }
        }

        let base_case_bit = self.base_case_bit.unwrap_or_default();
        let b_base_gadget =
            Boolean::new_witness(ark_relations::ns!(cs, "alloc_b_base"), || Ok(base_case_bit))?;

        /*
         * compute vk hash
         */

        let help_vk_bytes_gadget = help_vk_gadget.to_bytes()?;

        let mut committed_vk = Vec::<UInt8<MainField>>::new();
        for byte in &help_vk_bytes_gadget {
            committed_vk.push(byte.clone());
        }

        let vk_hash_gadget = IC::CRHGadget::check_evaluation_gadget(&crh_pp_gadget, &committed_vk)?;

        let vk_hash_bytes_gadget = vk_hash_gadget.to_bytes()?;

        /*
         * check input
         */

        let msg_bytes_gadget = msg_gadget.to_bytes()?;

        let mut committed_input = Vec::<UInt8<MainField>>::new();
        for byte in &vk_hash_bytes_gadget {
            committed_input.push(byte.clone());
        }
        for byte in &msg_bytes_gadget {
            committed_input.push(byte.clone());
        }
        let input_hash_supposed_gadget =
            IC::CRHGadget::check_evaluation_gadget(&crh_pp_gadget, &committed_input)?;

        input_hash_supposed_gadget.enforce_equal(&input_hash_gadget)?;

        /*
         * check the predicate
         */

        self.predicate.generate_constraints(
            ark_relations::ns!(cs, "check_predicate").cs(),
            &msg_gadget,
            &witness_gadget,
            &prior_msg_gadgets,
            &b_base_gadget,
        )?;

        /*
         * check each prior proof
         */

        let mut prior_proofs_verified = Boolean::Constant(true);

        for (prior_msg_gadget, prior_proof_gadget) in
            prior_msg_gadgets.iter().zip(prior_proof_gadgets.iter())
        {
            let prior_msg_bytes_gadget = prior_msg_gadget.to_bytes()?;

            let mut committed_prior_input = Vec::<UInt8<MainField>>::new();
            for byte in vk_hash_bytes_gadget.iter() {
                committed_prior_input.push(byte.clone());
            }
            for byte in &prior_msg_bytes_gadget {
                committed_prior_input.push(byte.clone());
            }

            let prior_input_hash_gadget =
                IC::CRHGadget::check_evaluation_gadget(&crh_pp_gadget, &committed_prior_input)?;

            let prior_input_hash_gadget_field_gadgets =
                IC::CRHGadget::convert_output_to_field_gadgets(&prior_input_hash_gadget)?;

            let prior_input_hash_converted_gadget = <IC::HelpSNARKGadget as SNARKGadget<
                HelpField,
                MainField,
                IC::HelpSNARK,
            >>::InputVar::from_field_elements(
                &prior_input_hash_gadget_field_gadgets
            )?;

            let verification_result =
                <IC::HelpSNARKGadget as SNARKGadget<HelpField, MainField, IC::HelpSNARK>>::verify(
                    &help_vk_gadget,
                    &prior_input_hash_converted_gadget,
                    &prior_proof_gadget,
                )?;

            prior_proofs_verified = prior_proofs_verified.and(&verification_result)?;
        }

        b_base_gadget
            .or(&prior_proofs_verified)?
            .enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}

pub struct HelpCircuit<
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
> {
    pub main_pvk: <IC::MainSNARK as SNARK<MainField>>::ProcessedVerifyingKey,

    pub input_hash: Option<<IC::CRH as VariableLengthCRH<MainField>>::Output>,
    pub main_proof: Option<<IC::MainSNARK as SNARK<MainField>>::Proof>,
}

impl<MainField: PrimeField, HelpField: PrimeField, IC: ECCyclePCDConfig<MainField, HelpField>>
    ConstraintSynthesizer<HelpField> for HelpCircuit<MainField, HelpField, IC>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<HelpField>,
    ) -> Result<(), SynthesisError> {
        let input_hash = self.input_hash.unwrap_or_default();

        let main_public_input_num_of_field_elements =
            IC::CRH::convert_output_to_field_elements(input_hash.clone())
                .unwrap()
                .len();

        let default_circ = DefaultCircuit {
            public_input_size: main_public_input_num_of_field_elements,
        };
        let mut default_rng = ark_std::test_rng();
        let (default_pk, _) = <IC::MainSNARK as SNARK<MainField>>::circuit_specific_setup(
            default_circ,
            &mut default_rng,
        )
        .unwrap();
        let default_proof =
            <IC::MainSNARK as SNARK<MainField>>::prove(&default_pk, default_circ, &mut default_rng)
                .unwrap();

        let main_proof = self.main_proof.unwrap_or(default_proof);
        let hash_field_elements = IC::CRH::convert_output_to_field_elements(input_hash).unwrap();

        let input_hash_gadget = <IC::MainSNARKGadget as SNARKGadget<
            MainField,
            HelpField,
            IC::MainSNARK,
        >>::InputVar::new_input(
            ark_relations::ns!(cs, "verifier"),
            || Ok(hash_field_elements),
        )?;

        let main_pvk_gadget = <IC::MainSNARKGadget as SNARKGadget<
            MainField,
            HelpField,
            IC::MainSNARK,
        >>::ProcessedVerifyingKeyVar::new_constant(
            ark_relations::ns!(cs, "alloc_pvk"),
            self.main_pvk,
        )?;

        let main_proof_gadget = <IC::MainSNARKGadget as SNARKGadget<
            MainField,
            HelpField,
            IC::MainSNARK,
        >>::ProofVar::new_witness(
            ark_relations::ns!(cs, "alloc_pi_alpha"), || Ok(main_proof)
        )?;

        <IC::MainSNARKGadget as SNARKGadget<
            MainField,
            HelpField,
            IC::MainSNARK,
        >>::verify_with_processed_vk(
            &main_pvk_gadget,
            &input_hash_gadget,
            &main_proof_gadget,
        )?.enforce_equal(&Boolean::Constant(true))?;

        Ok(())
    }
}
