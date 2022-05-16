use crate::{
    ec_cycle_pcd::data_structures::{ECCyclePCDPK, ECCyclePCDVK, HelpCircuit, MainCircuit},
    variable_length_crh::{constraints::VariableLengthCRHGadget, VariableLengthCRH},
    CircuitSpecificSetupPCD, Error, PCDPredicate, UniversalSetupPCD, PCD,
};
use ark_crypto_primitives::snark::{
    constraints::{SNARKGadget, UniversalSetupSNARKGadget},
    CircuitSpecificSetupSNARK, FromFieldElementsGadget,
    UniversalSetupIndexError::{NeedLargerBound, Other},
    UniversalSetupSNARK, SNARK,
};
use ark_ff::{prelude::*, to_bytes};
use ark_r1cs_std::{
    alloc::AllocVar, bits::boolean::Boolean, fields::fp::FpVar, prelude::*, R1CSVar,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
use ark_sponge::Absorb;
use ark_std::rand::{CryptoRng, Rng, RngCore};
use ark_std::{boxed::Box, marker::PhantomData, vec::Vec};

pub mod data_structures;

pub trait ECCyclePCDConfig<MainField: PrimeField, HelpField: PrimeField> {
    type CRH: VariableLengthCRH<MainField>;
    type CRHGadget: VariableLengthCRHGadget<Self::CRH, MainField>;

    type MainSNARK: SNARK<MainField>;
    type HelpSNARK: SNARK<HelpField>;

    type MainSNARKGadget: SNARKGadget<MainField, HelpField, Self::MainSNARK>;
    type HelpSNARKGadget: SNARKGadget<HelpField, MainField, Self::HelpSNARK>;
}

pub struct ECCyclePCD<
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
> {
    pub main_field_phantom: PhantomData<MainField>,
    pub help_field_phantom: PhantomData<HelpField>,
    pub ivc_config: PhantomData<IC>,
}

impl<MainField: PrimeField, HelpField: PrimeField, IC: ECCyclePCDConfig<MainField, HelpField>>
    PCD<MainField> for ECCyclePCD<MainField, HelpField, IC>
{
    type ProvingKey = ECCyclePCDPK<MainField, HelpField, IC>;
    type VerifyingKey = ECCyclePCDVK<MainField, HelpField, IC>;
    type Proof = <IC::HelpSNARK as SNARK<HelpField>>::Proof;

    fn circuit_specific_setup<P: PCDPredicate<MainField>, R: Rng + CryptoRng>(
        predicate: &P,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Error> {
        let crh_pp = IC::CRH::setup(rng)?;

        let main_circuit = MainCircuit::<MainField, HelpField, IC, P> {
            crh_pp: crh_pp.clone(),
            predicate: predicate.clone(),
            input_hash: None,
            help_vk: None,
            msg: None,
            witness: None,
            prior_msgs: Vec::new(),
            prior_proofs: Vec::new(),
            base_case_bit: None,
        };
        let (main_pk, main_vk) = IC::MainSNARK::circuit_specific_setup(main_circuit, rng)?;

        let main_pvk = IC::MainSNARK::process_vk(&main_vk)?;

        let help_circuit = HelpCircuit::<MainField, HelpField, IC> {
            main_pvk: main_pvk.clone(),
            input_hash: None,
            main_proof: None,
        };
        let (help_pk, help_vk) = IC::HelpSNARK::circuit_specific_setup(help_circuit, rng)?;

        let pk = ECCyclePCDPK::<MainField, HelpField, IC> {
            crh_pp: crh_pp.clone(),
            main_pk,
            help_pk,
            help_vk: help_vk.clone(),
            main_pvk,
        };
        let vk = ECCyclePCDVK::<MainField, HelpField, IC> { crh_pp, help_vk };

        Ok((pk, vk))
    }

    fn prove<P: PCDPredicate<MainField>, R: Rng + CryptoRng>(
        pk: &ECCyclePCDPK<MainField, HelpField, IC>,
        predicate: &P,
        msg: &P::Message,
        witness: &P::LocalWitness,
        prior_msgs: &[P::Message],
        prior_proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<Self::Proof, Error> {
        /*
         ** Compute the input hash.
         ** To avoid issues when the verifying key's native has different ToBytes compared with the gadgets',
         ** here we simulate the computation inside the gadget
         */
        let input_hash = {
            let tcs_sys = ConstraintSystem::<MainField>::new();
            let tcs = ConstraintSystemRef::new(tcs_sys);
            tcs.set_optimization_goal(OptimizationGoal::Weight);

            let help_vk_gadget = <IC::HelpSNARKGadget as SNARKGadget<
                HelpField,
                MainField,
                IC::HelpSNARK,
            >>::VerifyingKeyVar::new_witness(
                ark_relations::ns!(tcs, "vk"),
                || Ok(pk.help_vk.clone()),
            )?;

            let msg_gadget =
                P::MessageVar::new_witness(ark_relations::ns!(tcs, "msg"), || Ok(msg.clone()))?;

            let help_vk_bytes_gadget = help_vk_gadget.to_bytes()?;
            let mut committed_vk = Vec::<u8>::new();
            for byte in &help_vk_bytes_gadget {
                committed_vk.push(byte.value().unwrap_or_default());
            }
            let vk_hash = IC::CRH::evaluate(&pk.crh_pp, &committed_vk)?;
            let vk_hash_bytes = to_bytes!(vk_hash)?;

            let msg_bytes_gadget = msg_gadget.to_bytes()?;

            let mut committed_input = Vec::<u8>::new();
            for byte in vk_hash_bytes.iter() {
                committed_input.push(*byte);
            }
            for byte in &msg_bytes_gadget {
                committed_input.push(byte.value().unwrap_or_default());
            }

            IC::CRH::evaluate(&pk.crh_pp, &committed_input)?
        };

        let main_circuit: MainCircuit<MainField, HelpField, IC, P>;
        if prior_msgs.is_empty() {
            main_circuit = MainCircuit::<MainField, HelpField, IC, P> {
                crh_pp: pk.crh_pp.clone(),
                predicate: (*predicate).clone(),
                input_hash: Some(input_hash.clone()),
                help_vk: Some(pk.help_vk.clone()),
                msg: Some(msg.clone()),
                witness: Some(witness.clone()),
                prior_msgs: Vec::new(),
                prior_proofs: Vec::new(),
                base_case_bit: Some(true),
            };
        } else {
            main_circuit = MainCircuit::<MainField, HelpField, IC, P> {
                crh_pp: pk.crh_pp.clone(),
                predicate: (*predicate).clone(),
                input_hash: Some(input_hash.clone()),
                help_vk: Some(pk.help_vk.clone()),
                msg: Some(msg.clone()),
                witness: Some(witness.clone()),
                prior_msgs: prior_msgs.to_vec(),
                prior_proofs: prior_proofs.to_vec(),
                base_case_bit: Some(false),
            };
        }

        let main_proof = IC::MainSNARK::prove(&pk.main_pk, main_circuit, rng)?;

        let help_circuit = HelpCircuit::<MainField, HelpField, IC> {
            main_pvk: pk.main_pvk.clone(),
            input_hash: Some(input_hash),
            main_proof: Some(main_proof),
        };

        let help_proof = IC::HelpSNARK::prove(&pk.help_pk, help_circuit, rng)?;
        Ok(help_proof)
    }

    fn verify<P: PCDPredicate<MainField>>(
        vk: &Self::VerifyingKey,
        msg: &P::Message,
        proof: &Self::Proof,
    ) -> Result<bool, Error> {
        /*
         ** Compute the input hash.
         ** To avoid issues when the verifying key's native has different ToBytes compared with the gadgets',
         ** here we simulate the computation inside the gadget
         */
        let input_hash = {
            let tcs_sys = ConstraintSystem::<MainField>::new();
            let tcs = ConstraintSystemRef::new(tcs_sys);
            tcs.set_optimization_goal(OptimizationGoal::Weight);

            let help_vk_gadget = <IC::HelpSNARKGadget as SNARKGadget<
                HelpField,
                MainField,
                IC::HelpSNARK,
            >>::VerifyingKeyVar::new_witness(
                ark_relations::ns!(tcs, "vk"),
                || Ok(vk.help_vk.clone()),
            )?;

            let msg_gadget =
                P::MessageVar::new_witness(ark_relations::ns!(tcs, "msg"), || Ok(msg.clone()))?;

            let help_vk_bytes_gadget = help_vk_gadget.to_bytes()?;
            let mut committed_vk = Vec::<u8>::new();
            for byte in &help_vk_bytes_gadget {
                committed_vk.push(byte.value().unwrap_or_default());
            }
            let vk_hash = IC::CRH::evaluate(&vk.crh_pp, &committed_vk)?;
            let vk_hash_bytes = to_bytes!(vk_hash)?;

            let msg_bytes_gadget = msg_gadget.to_bytes()?;

            let mut committed_input = Vec::<u8>::new();
            for byte in vk_hash_bytes.iter() {
                committed_input.push(*byte);
            }
            for byte in &msg_bytes_gadget {
                committed_input.push(byte.value().unwrap_or_default());
            }

            IC::CRH::evaluate(&vk.crh_pp, &committed_input)?
        };

        let main_public_input = IC::CRH::convert_output_to_field_elements(input_hash).unwrap();

        let help_public_input = <IC::MainSNARKGadget as SNARKGadget<
            MainField,
            HelpField,
            IC::MainSNARK,
        >>::InputVar::repack_input(&main_public_input);

        let verify_result = IC::HelpSNARK::verify(&vk.help_vk, &help_public_input, &proof);

        match verify_result {
            Ok(res) => Ok(res),
            Err(err) => Err(Box::new(err)),
        }
    }
}

impl<MainField: PrimeField, HelpField: PrimeField, IC: ECCyclePCDConfig<MainField, HelpField>>
    CircuitSpecificSetupPCD<MainField> for ECCyclePCD<MainField, HelpField, IC>
where
    IC::MainSNARK: CircuitSpecificSetupSNARK<MainField>,
    IC::HelpSNARK: CircuitSpecificSetupSNARK<HelpField>,
{
}

pub struct BoundTestingPredicate<
    F: PrimeField + Absorb,
    BoundCircuit: ConstraintSynthesizer<F> + Clone,
> {
    pub bound_circuit: BoundCircuit,
    pub field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb, BoundCircuit: ConstraintSynthesizer<F> + Clone> Clone
    for BoundTestingPredicate<F, BoundCircuit>
{
    fn clone(&self) -> Self {
        Self {
            bound_circuit: self.bound_circuit.clone(),
            field_phantom: PhantomData,
        }
    }
}

impl<F: PrimeField + Absorb, BoundCircuit: ConstraintSynthesizer<F> + Clone> PCDPredicate<F>
    for BoundTestingPredicate<F, BoundCircuit>
{
    type Message = F;
    type MessageVar = FpVar<F>;
    type LocalWitness = F;
    type LocalWitnessVar = FpVar<F>;

    const PRIOR_MSG_LEN: usize = 1;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        msg: &Self::MessageVar,
        witness: &Self::LocalWitnessVar,
        prior_msgs: &[Self::MessageVar],
        _base_case: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        assert!(prior_msgs.len() == Self::PRIOR_MSG_LEN);

        // if base_core = 0, the prior_msgs[0] would be the default message, which is zero.
        let msg_supposed = witness + &prior_msgs[0];
        msg.enforce_equal(&msg_supposed)?;

        self.bound_circuit
            .clone()
            .generate_constraints(ark_relations::ns!(cs, "bound").cs())?;

        Ok(())
    }
}

impl<MainField, HelpField, IC> UniversalSetupPCD<MainField> for ECCyclePCD<MainField, HelpField, IC>
where
    MainField: PrimeField + Absorb,
    HelpField: PrimeField + Absorb,
    IC: ECCyclePCDConfig<MainField, HelpField>,
    IC::MainSNARK: UniversalSetupSNARK<MainField>,
    IC::HelpSNARK: UniversalSetupSNARK<HelpField>,
    IC::MainSNARKGadget: UniversalSetupSNARKGadget<MainField, HelpField, IC::MainSNARK>,
{
    type PredicateBound = <IC::MainSNARK as UniversalSetupSNARK<MainField>>::ComputationBound;
    type PublicParameters = (
        Self::PredicateBound,
        <IC::CRH as VariableLengthCRH<MainField>>::Parameters,
        <IC::MainSNARK as UniversalSetupSNARK<MainField>>::PublicParameters,
        <IC::HelpSNARK as UniversalSetupSNARK<HelpField>>::PublicParameters,
    );

    fn universal_setup<R: RngCore + CryptoRng>(
        predicate_bound: &Self::PredicateBound,
        rng: &mut R,
    ) -> Result<Self::PublicParameters, Error> {
        let crh_pp = IC::CRH::setup(rng)?;

        let bound_testing_predicate = BoundTestingPredicate::<
            MainField,
            <IC::MainSNARKGadget as UniversalSetupSNARKGadget<
                MainField,
                HelpField,
                IC::MainSNARK,
            >>::BoundCircuit,
        > {
            bound_circuit: <IC::MainSNARKGadget as UniversalSetupSNARKGadget<
                MainField,
                HelpField,
                IC::MainSNARK,
            >>::BoundCircuit::from(predicate_bound.clone()),
            field_phantom: PhantomData,
        };

        let mut main_bound = predicate_bound.clone();
        let mut help_bound =
            <IC::HelpSNARK as UniversalSetupSNARK<HelpField>>::ComputationBound::default();

        loop {
            let main_pp = <IC::MainSNARK as UniversalSetupSNARK<MainField>>::universal_setup(
                &main_bound,
                rng,
            )?;

            let help_pp = <IC::HelpSNARK as UniversalSetupSNARK<HelpField>>::universal_setup(
                &help_bound,
                rng,
            )?;

            let main_circuit_bound_index_result =
                <IC::MainSNARK as UniversalSetupSNARK<MainField>>::index(
                    &main_pp,
                    <IC::MainSNARKGadget as UniversalSetupSNARKGadget<
                        MainField,
                        HelpField,
                        IC::MainSNARK,
                    >>::BoundCircuit::from(main_bound.clone()),
                    rng,
                );

            let help_vk_placeholder: Option<<IC::HelpSNARK as SNARK<HelpField>>::VerifyingKey>;

            match main_circuit_bound_index_result {
                Ok(main_keypair) => {
                    let main_pvk = IC::MainSNARK::process_vk(&main_keypair.1)?;

                    let help_circuit = HelpCircuit::<MainField, HelpField, IC> {
                        main_pvk: main_pvk.clone(),
                        input_hash: None,
                        main_proof: None,
                    };

                    let help_circuit_index_result = <IC::HelpSNARK as UniversalSetupSNARK<
                        HelpField,
                    >>::index(
                        &help_pp, help_circuit, rng
                    );

                    match help_circuit_index_result {
                        Ok(keypair) => help_vk_placeholder = Some(keypair.1),
                        Err(NeedLargerBound(bound)) => {
                            help_bound = bound;
                            continue;
                        }
                        Err(Other(err)) => return Err(Box::new(err)),
                    }
                }
                Err(NeedLargerBound(bound)) => {
                    main_bound = bound;
                    continue;
                }
                Err(Other(err)) => return Err(Box::new(err)),
            }

            let main_circuit = MainCircuit::<
                MainField,
                HelpField,
                IC,
                BoundTestingPredicate<
                    MainField,
                    <IC::MainSNARKGadget as UniversalSetupSNARKGadget<
                        MainField,
                        HelpField,
                        IC::MainSNARK,
                    >>::BoundCircuit,
                >,
            > {
                crh_pp: crh_pp.clone(),
                predicate: bound_testing_predicate.clone(),
                input_hash: None,
                help_vk: Some(help_vk_placeholder.unwrap()),
                msg: None,
                witness: None,
                prior_msgs: Vec::new(),
                prior_proofs: Vec::new(),
                base_case_bit: None,
            };

            let main_circuit_index_result =
                <IC::MainSNARK as UniversalSetupSNARK<MainField>>::index(
                    &main_pp,
                    main_circuit,
                    rng,
                );

            let main_vk: Option<<IC::MainSNARK as SNARK<MainField>>::VerifyingKey>;

            match main_circuit_index_result {
                Ok(keypair) => {
                    main_vk = Some(keypair.1);
                }
                Err(NeedLargerBound(bound)) => {
                    main_bound = bound;
                    continue;
                }
                Err(Other(err)) => return Err(Box::new(err)),
            }

            let main_pvk = IC::MainSNARK::process_vk(&main_vk.unwrap())?;

            let help_circuit = HelpCircuit::<MainField, HelpField, IC> {
                main_pvk: main_pvk.clone(),
                input_hash: None,
                main_proof: None,
            };

            let help_circuit_index_result =
                <IC::HelpSNARK as UniversalSetupSNARK<HelpField>>::index(
                    &help_pp,
                    help_circuit,
                    rng,
                );

            match help_circuit_index_result {
                Ok(_) => {
                    return Ok((main_bound, crh_pp, main_pp, help_pp));
                }
                Err(NeedLargerBound(bound)) => {
                    help_bound = bound;
                    continue;
                }
                Err(Other(err)) => return Err(Box::new(err)),
            }
        }
    }

    fn index<P: PCDPredicate<MainField>, R: Rng + CryptoRng>(
        pp: &Self::PublicParameters,
        predicate: &P,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Error> {
        let (main_bound, crh_pp, main_pp, help_pp) = pp;

        let main_circuit_bound_index_result =
            <IC::MainSNARK as UniversalSetupSNARK<MainField>>::index(
                &main_pp,
                <IC::MainSNARKGadget as UniversalSetupSNARKGadget<
                    MainField,
                    HelpField,
                    IC::MainSNARK,
                >>::BoundCircuit::from(main_bound.clone()),
                rng,
            );

        let help_vk_placeholder: Option<<IC::HelpSNARK as SNARK<HelpField>>::VerifyingKey>;

        match main_circuit_bound_index_result {
            Ok(main_keypair) => {
                let main_pvk = IC::MainSNARK::process_vk(&main_keypair.1)?;

                let help_circuit = HelpCircuit::<MainField, HelpField, IC> {
                    main_pvk,
                    input_hash: None,
                    main_proof: None,
                };

                let help_circuit_index_result =
                    <IC::HelpSNARK as UniversalSetupSNARK<HelpField>>::index(
                        &help_pp,
                        help_circuit,
                        rng,
                    );

                match help_circuit_index_result {
                    Ok(keypair) => help_vk_placeholder = Some(keypair.1),
                    Err(NeedLargerBound(_)) => {
                        panic!("The bound is not correctly chosen.");
                    }
                    Err(Other(err)) => return Err(Box::new(err)),
                }
            }
            Err(NeedLargerBound(_)) => {
                panic!("The bound is not correctly chosen.");
            }
            Err(Other(err)) => return Err(Box::new(err)),
        }

        let main_circuit = MainCircuit::<MainField, HelpField, IC, P> {
            crh_pp: crh_pp.clone(),
            predicate: predicate.clone(),
            input_hash: None,
            help_vk: Some(help_vk_placeholder.unwrap()),
            msg: None,
            witness: None,
            prior_msgs: Vec::new(),
            prior_proofs: Vec::new(),
            base_case_bit: None,
        };

        let main_circuit_index_result =
            <IC::MainSNARK as UniversalSetupSNARK<MainField>>::index(&main_pp, main_circuit, rng);

        let main_pk: Option<<IC::MainSNARK as SNARK<MainField>>::ProvingKey>;
        let main_vk: Option<<IC::MainSNARK as SNARK<MainField>>::VerifyingKey>;

        match main_circuit_index_result {
            Ok(keypair) => {
                main_pk = Some(keypair.0);
                main_vk = Some(keypair.1);
            }
            Err(NeedLargerBound(_)) => {
                panic!("The bound is not correctly chosen.");
            }
            Err(Other(err)) => return Err(Box::new(err)),
        }

        let main_pvk = IC::MainSNARK::process_vk(&main_vk.unwrap())?;

        let help_circuit = HelpCircuit::<MainField, HelpField, IC> {
            main_pvk: main_pvk.clone(),
            input_hash: None,
            main_proof: None,
        };

        let help_circuit_index_result =
            <IC::HelpSNARK as UniversalSetupSNARK<HelpField>>::index(&help_pp, help_circuit, rng);

        match help_circuit_index_result {
            Ok(help_keypair) => {
                let ivc_pk = ECCyclePCDPK::<MainField, HelpField, IC> {
                    crh_pp: crh_pp.clone(),
                    main_pk: main_pk.unwrap(),
                    main_pvk,
                    help_pk: help_keypair.0.clone(),
                    help_vk: help_keypair.1.clone(),
                };

                let ivc_vk = ECCyclePCDVK::<MainField, HelpField, IC> {
                    crh_pp: crh_pp.clone(),
                    help_vk: help_keypair.1,
                };

                Ok((ivc_pk, ivc_vk))
            }
            Err(NeedLargerBound(_)) => panic!("The bound is not correctly chosen."),
            Err(Other(err)) => Err(Box::new(err)),
        }
    }
}
