use crate::r1cs_nark_pcd::data_structures::{HelpAffine, HelpField, MainAffine, MainField};
use crate::r1cs_nark_pcd::help_circuit::HelpCircuit;
use crate::r1cs_nark_pcd::{R1CSNarkPCDConfig, MAKE_ZK};
use crate::PCDPredicate;
use ark_accumulation::constraints::ASVerifierGadget;
use ark_accumulation::r1cs_nark_as;
use ark_accumulation::r1cs_nark_as::constraints::{
    ASForR1CSNarkVerifierGadget, AccumulatorInstanceVar, InputInstanceVar,
};
use ark_accumulation::r1cs_nark_as::{AccumulatorInstance, InputInstance};
use ark_ec::CurveCycle;
use ark_ff::{PrimeField, Zero};
use ark_marlin::ahp::{CryptographicSpongeVarNonNative, CryptographicSpongeWithDefault};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::ns;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::{absorb, absorb_gadget, Absorb, CryptographicSponge};
use ark_std::marker::PhantomData;

/// A circuit used to verify that the accumulation of arguments about the help circuit was computed
/// correctly and that the PCD predicate holds for the new message.
#[derive(Derivative)]
#[derivative(Clone(bound = "E: CurveCycle"))]
pub(crate) struct MainCircuit<E, PC, P>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
    P: PCDPredicate<MainField<E>>,
{
    /// The PCD predicate.
    pub(crate) predicate: P,

    /// The new PCD message.
    pub(crate) msg: P::Message,

    /// The local PCD witness.
    pub(crate) witness: P::LocalWitness,

    /// PCD messages from the previous step.
    pub(crate) prior_msgs: Option<Vec<P::Message>>,

    /// The key for verifying the accumulation of arguments about the help circuit.
    pub(crate) help_avk: r1cs_nark_as::VerifierKey,

    /// The accumulation input instances of the arguments about the help circuit in the previous
    /// step.
    pub(crate) help_accumulation_input_instances: Option<Vec<InputInstance<HelpAffine<E>>>>,

    /// The old accumulators that have accumulated arguments about the help circuit in the previous
    /// step.
    pub(crate) help_old_accumulator_instances: Option<Vec<AccumulatorInstance<HelpAffine<E>>>>,

    /// The new accumulator computed from accumulating arguments and accumulators of the help
    /// circuit of the previous step.
    pub(crate) help_new_accumulator_instance: AccumulatorInstance<HelpAffine<E>>,

    /// The new proof computed from accumulating arguments and accumulators of the help
    /// circuit of the previous step.
    pub(crate) help_accumulation_proof: r1cs_nark_as::Proof<HelpAffine<E>>,

    #[doc(hidden)]
    pub(crate) _config_phantom: PhantomData<PC>,
}

impl<E, PC, P> MainCircuit<E, PC, P>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
    P: PCDPredicate<MainField<E>>,
{
    /// Returns the public input size of the main circuit.
    pub(crate) fn public_input_size() -> usize {
        let cs = ConstraintSystem::<MainField<E>>::new_ref();
        let _hash = FpVar::new_input(cs.clone(), || Ok(MainField::<E>::zero())).unwrap();
        return cs.num_instance_variables();
    }

    /// Computes a hash of the following elements.
    pub(crate) fn compute_hash(
        help_avk: &r1cs_nark_as::VerifierKey,
        help_accumulator_instance: &AccumulatorInstance<HelpAffine<E>>,
        msg: &P::Message,
    ) -> MainField<E> {
        let params = PC::MainSponge::default_params();
        let mut sponge = PC::MainSponge::new(&params);
        absorb!(&mut sponge, help_avk, help_accumulator_instance, msg);
        sponge.squeeze_field_elements(1).pop().unwrap()
    }

    /// Computes a hash of the following elements in the constraint system.
    pub(crate) fn compute_hash_var(
        cs: ConstraintSystemRef<MainField<E>>,
        help_avk_var: &r1cs_nark_as::constraints::VerifierKeyVar<MainField<E>>,
        help_accumulator_instance_var: &AccumulatorInstanceVar<HelpAffine<E>, PC::HelpCurveVar>,
        msg_var: &P::MessageVar,
    ) -> Result<FpVar<MainField<E>>, SynthesisError> {
        let params = PC::MainSpongeVar::default_params();
        let mut sponge = PC::MainSpongeVar::new(cs, &params);
        absorb_gadget!(
            &mut sponge,
            help_avk_var,
            help_accumulator_instance_var,
            msg_var
        );
        Ok(sponge.squeeze_field_elements(1)?.pop().unwrap())
    }

    /// Computes the public input of the main circuit.
    pub(crate) fn compute_public_input(
        help_avk: &r1cs_nark_as::VerifierKey,
        help_accumulator_instance: &AccumulatorInstance<HelpAffine<E>>,
        msg: &P::Message,
    ) -> Result<Vec<MainField<E>>, SynthesisError> {
        let cs = ConstraintSystem::<MainField<E>>::new_ref();

        let _hash = FpVar::new_input(cs.clone(), || {
            Ok(Self::compute_hash(help_avk, help_accumulator_instance, msg))
        })?;

        let r1cs_input = cs.borrow().unwrap().instance_assignment.clone();
        Ok(r1cs_input)
    }
}

impl<E, PC, P> ConstraintSynthesizer<MainField<E>> for MainCircuit<E, PC, P>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
    P: PCDPredicate<MainField<E>>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<MainField<E>>,
    ) -> Result<(), SynthesisError> {
        let MainCircuit {
            predicate,
            msg,
            witness,
            prior_msgs,
            help_avk,
            help_accumulation_input_instances: help_input_instances,
            help_old_accumulator_instances,
            help_new_accumulator_instance,
            mut help_accumulation_proof,
            _config_phantom,
        } = self;

        // Ensure that prior data exist together.
        assert_eq!(help_input_instances.is_some(), prior_msgs.is_some());

        assert_eq!(
            help_input_instances.is_some(),
            help_old_accumulator_instances.is_some()
        );

        // Ensure that prior data has the correct length.
        assert!(prior_msgs.is_none() || prior_msgs.as_ref().unwrap().len() == P::PRIOR_MSG_LEN);

        assert!(
            help_input_instances.is_none()
                || help_input_instances.as_ref().unwrap().len() == P::PRIOR_MSG_LEN
        );

        assert!(
            help_old_accumulator_instances.is_none()
                || help_old_accumulator_instances.as_ref().unwrap().len() == P::PRIOR_MSG_LEN
        );

        // Process the inputs

        let base_case = help_input_instances.is_none();
        let help_circuit_input_len = HelpCircuit::<E, PC, P>::public_input_size();
        let (help_input_instances, help_old_accumulator_instances, prior_msgs) = if base_case {
            // Populate the prior data with default data.
            (
                vec![InputInstance::zero(help_circuit_input_len, MAKE_ZK); P::PRIOR_MSG_LEN],
                vec![AccumulatorInstance::placeholder(help_circuit_input_len); P::PRIOR_MSG_LEN],
                vec![P::Message::default(); P::PRIOR_MSG_LEN],
            )
        } else {
            (
                help_input_instances.unwrap(),
                help_old_accumulator_instances.unwrap(),
                prior_msgs.unwrap(),
            )
        };

        // In the base case, the size of the proof will be incorrect due to the low and high
        // T commitments in the underlying HP_AS proof. We substitute the base case proof with a
        // dummy proof to ensure the size of the circuit remains constant. We are able to do so
        // because the result of the r1cs_nark_as verify does not matter in the base case.
        if base_case {
            help_accumulation_proof = r1cs_nark_as::Proof::placeholder(
                help_circuit_input_len,
                P::PRIOR_MSG_LEN * 2,
                MAKE_ZK,
            );
        };

        let claimed_input_hash: MainField<E> =
            Self::compute_hash(&help_avk, &help_new_accumulator_instance, &msg);

        // Allocation

        let claimed_input_hash_var = FpVar::new_input(ns!(cs, "alloc_claimed_input_hash"), || {
            Ok(claimed_input_hash)
        })?;

        let base_case_var = Boolean::new_witness(ns!(cs, "alloc_base_case_bit"), || Ok(base_case))?;

        let help_avk_var = r1cs_nark_as::constraints::VerifierKeyVar::new_witness(
            ns!(cs, "alloc_help_avk"),
            || Ok(help_avk),
        )?;

        let msg_var = P::MessageVar::new_witness(ns!(cs, "alloc_msg"), || Ok(msg))?;

        let witness_var =
            P::LocalWitnessVar::new_witness(ns!(cs, "alloc_witness"), || Ok(witness))?;

        let prior_msg_vars = prior_msgs
            .into_iter()
            .map(|prior_msg| {
                P::MessageVar::new_witness(ns!(cs, "alloc_prior_msg"), || Ok(prior_msg))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let help_input_instance_vars = help_input_instances
            .into_iter()
            .map(|input_instance| {
                InputInstanceVar::<HelpAffine<E>, PC::HelpCurveVar>::new_witness(
                    ns!(cs, "alloc_help_input_instances"),
                    || Ok(input_instance),
                )
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let help_old_accumulator_instance_vars = help_old_accumulator_instances
            .into_iter()
            .map(|accumulator_instance| {
                AccumulatorInstanceVar::<HelpAffine<E>, PC::HelpCurveVar>::new_witness(
                    ns!(cs, "alloc_help_old_accumulator_instances"),
                    || Ok(accumulator_instance),
                )
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let help_new_accumulator_instance_var =
            AccumulatorInstanceVar::<HelpAffine<E>, PC::HelpCurveVar>::new_witness(
                ns!(cs, "alloc_help_new_accumulator_instance"),
                || Ok(help_new_accumulator_instance),
            )?;

        let help_accumulation_proof_var =
            r1cs_nark_as::constraints::ProofVar::<HelpAffine<E>, PC::HelpCurveVar>::new_witness(
                ns!(cs, "alloc_help_accumulation_proof"),
                || Ok(help_accumulation_proof),
            )?;

        // Verification

        predicate.generate_constraints(
            ark_relations::ns!(cs, "check_predicate").cs(),
            &msg_var,
            &witness_var,
            &prior_msg_vars,
            &base_case_var,
        )?;

        let input_hash_var: FpVar<MainField<E>> = Self::compute_hash_var(
            ns!(cs, "input_hash_sponge").cs(),
            &help_avk_var,
            &help_new_accumulator_instance_var,
            &msg_var,
        )?;

        input_hash_var.enforce_equal(&claimed_input_hash_var)?;

        let as_verify = ASForR1CSNarkVerifierGadget::<
            HelpAffine<E>,
            PC::HelpCurveVar,
            PC::MainSponge,
            PC::MainSpongeVar,
        >::verify(
            ns!(cs, "help_accumulation_verify").cs(),
            &help_avk_var,
            &help_input_instance_vars,
            &help_old_accumulator_instance_vars,
            &help_new_accumulator_instance_var,
            &help_accumulation_proof_var,
            None,
        )?;

        base_case_var
            .or(&as_verify)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}
