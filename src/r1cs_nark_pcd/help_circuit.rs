use crate::r1cs_nark_pcd::data_structures::{HelpAffine, HelpField, MainAffine, MainField, SPONGE_RATE};
use crate::r1cs_nark_pcd::main_circuit::MainCircuit;
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
use ark_marlin::sponge::{CryptographicSpongeParameters, CryptographicSpongeWithRate};
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

/// A circuit used to verify that the accumulation of arguments about the main circuit was computed
/// correctly.
#[derive(Derivative)]
#[derivative(Clone(bound = "E: CurveCycle"))]
pub(crate) struct HelpCircuit<E, PC, P>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
    P: PCDPredicate<MainField<E>>,
    <PC::MainSponge as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
    <PC::HelpSponge as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
{
    /// The key for verifying the accumulation of arguments about the main circuit.
    pub(crate) main_avk: r1cs_nark_as::VerifierKey,

    /// The accumulation input instances of the arguments about the main circuit in the previous
    /// step.
    pub(crate) main_accumulation_input_instances: Option<Vec<InputInstance<MainAffine<E>>>>,

    /// The old accumulators that have accumulated arguments about the main circuit in the previous
    /// step.
    pub(crate) main_old_accumulator_instances: Option<Vec<AccumulatorInstance<MainAffine<E>>>>,

    /// The new accumulator computed from accumulating arguments and accumulators of the main
    /// circuit of the previous step.
    pub(crate) main_new_accumulator_instance: AccumulatorInstance<MainAffine<E>>,

    /// The new proof computed from accumulating arguments and accumulators of the main
    /// circuit of the previous step.
    pub(crate) main_accumulation_proof: r1cs_nark_as::Proof<MainAffine<E>>,

    #[doc(hidden)]
    pub(crate) _config_phantom: PhantomData<PC>,

    #[doc(hidden)]
    pub(crate) _predicate_phantom: PhantomData<P>,
}

impl<E, PC, P> HelpCircuit<E, PC, P>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
    P: PCDPredicate<MainField<E>>,
    <PC::MainSponge as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
    <PC::HelpSponge as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
{
    /// Returns the public input size of the help circuit.
    pub(crate) fn public_input_size() -> usize {
        let cs = ConstraintSystem::<HelpField<E>>::new_ref();
        let _hash = FpVar::new_input(cs.clone(), || Ok(HelpField::<E>::zero())).unwrap();
        return cs.num_instance_variables();
    }

    /// Computes a hash of the following elements.
    pub(crate) fn compute_hash(
        main_avk: &r1cs_nark_as::VerifierKey,
        main_accumulator_instance: &AccumulatorInstance<MainAffine<E>>,
    ) -> HelpField<E> {
        let mut sponge = PC::HelpSponge::from_rate(SPONGE_RATE);
        absorb!(&mut sponge, main_avk, main_accumulator_instance);
        sponge.squeeze_field_elements(1).pop().unwrap()
    }

    /// Computes a hash of the following elements in the constraint system.
    pub(crate) fn compute_hash_var(
        cs: ConstraintSystemRef<HelpField<E>>,
        main_avk_var: &r1cs_nark_as::constraints::VerifierKeyVar<HelpField<E>>,
        main_accumulator_instance_var: &AccumulatorInstanceVar<MainAffine<E>, PC::MainCurveVar>,
    ) -> Result<FpVar<HelpField<E>>, SynthesisError> {
        let sponge_params = <PC::HelpSponge as CryptographicSponge>::Parameters::from_rate(SPONGE_RATE);
        let mut sponge = PC::HelpSpongeVar::new(cs, &sponge_params);
        absorb_gadget!(&mut sponge, main_avk_var, main_accumulator_instance_var);
        Ok(sponge.squeeze_field_elements(1)?.pop().unwrap())
    }

    /// Computes the public input of the help circuit.
    pub(crate) fn compute_public_input(
        main_avk: &r1cs_nark_as::VerifierKey,
        main_accumulator_instance: &AccumulatorInstance<MainAffine<E>>,
    ) -> Result<Vec<HelpField<E>>, SynthesisError> {
        let cs = ConstraintSystem::<HelpField<E>>::new_ref();

        let _hash = FpVar::new_input(cs.clone(), || {
            Ok(Self::compute_hash(main_avk, main_accumulator_instance))
        })?;

        let r1cs_input = cs.borrow().unwrap().instance_assignment.clone();
        Ok(r1cs_input)
    }
}

impl<E, PC, P> ConstraintSynthesizer<HelpField<E>> for HelpCircuit<E, PC, P>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
    P: PCDPredicate<MainField<E>>,
    <PC::MainSponge as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
    <PC::HelpSponge as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<HelpField<E>>,
    ) -> Result<(), SynthesisError> {
        let HelpCircuit {
            main_avk,
            main_accumulation_input_instances: main_input_instances,
            main_old_accumulator_instances,
            main_new_accumulator_instance,
            mut main_accumulation_proof,
            _config_phantom,
            _predicate_phantom,
        } = self;

        // Ensure that prior data exist together.
        assert_eq!(
            main_input_instances.is_some(),
            main_old_accumulator_instances.is_some()
        );

        // Ensure that prior data has the correct length.
        assert!(
            main_input_instances.is_none()
                || main_input_instances.as_ref().unwrap().len() == P::PRIOR_MSG_LEN
        );

        assert!(
            main_old_accumulator_instances.is_none()
                || main_old_accumulator_instances.as_ref().unwrap().len() == P::PRIOR_MSG_LEN
        );

        // Process the inputs

        let base_case = main_input_instances.is_none();
        let main_circuit_input_len = MainCircuit::<E, PC, P>::public_input_size();
        let (main_input_instances, main_old_accumulator_instances) = if base_case {
            (
                vec![InputInstance::zero(main_circuit_input_len, MAKE_ZK); P::PRIOR_MSG_LEN],
                vec![AccumulatorInstance::placeholder(main_circuit_input_len); P::PRIOR_MSG_LEN],
            )
        } else {
            (
                main_input_instances.unwrap(),
                main_old_accumulator_instances.unwrap(),
            )
        };

        let claimed_input_hash: HelpField<E> =
            Self::compute_hash(&main_avk, &main_new_accumulator_instance);

        // In the base case, the size of the proof will be incorrect due to the low and high
        // T commitments in the underlying HP_AS proof. We substitute the base case proof with a
        // dummy proof to ensure the size of the circuit remains constant. We are able to do so
        // because the result of the r1cs_nark_as verify does not matter in the base case.
        if base_case {
            main_accumulation_proof = r1cs_nark_as::Proof::placeholder(
                main_circuit_input_len,
                P::PRIOR_MSG_LEN * 2,
                MAKE_ZK,
            );
        };

        //  Allocation

        let claimed_input_hash_var = FpVar::new_input(ns!(cs, "alloc_claimed_input_hash"), || {
            Ok(claimed_input_hash)
        })?;

        let base_case_var = Boolean::new_witness(ns!(cs, "alloc_base_case_bit"), || Ok(base_case))?;

        let main_avk_var = r1cs_nark_as::constraints::VerifierKeyVar::new_witness(
            ns!(cs, "alloc_main_avk"),
            || Ok(main_avk),
        )?;

        let main_input_instance_vars = main_input_instances
            .into_iter()
            .map(|input_instance| {
                InputInstanceVar::<MainAffine<E>, PC::MainCurveVar>::new_witness(
                    ns!(cs, "alloc_main_input_instances"),
                    || Ok(input_instance),
                )
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let main_old_accumulator_instance_vars = main_old_accumulator_instances
            .into_iter()
            .map(|accumulator_instance| {
                AccumulatorInstanceVar::<MainAffine<E>, PC::MainCurveVar>::new_witness(
                    ns!(cs, "alloc_main_old_accumulator_instances"),
                    || Ok(accumulator_instance),
                )
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let main_new_accumulator_instance_var =
            AccumulatorInstanceVar::<MainAffine<E>, PC::MainCurveVar>::new_witness(
                ns!(cs, "alloc_main_new_accumulator_instance"),
                || Ok(main_new_accumulator_instance),
            )?;

        let main_accumulation_proof_var =
            r1cs_nark_as::constraints::ProofVar::<MainAffine<E>, PC::MainCurveVar>::new_witness(
                ns!(cs, "alloc_main_accumulation_proof"),
                || Ok(main_accumulation_proof),
            )?;

        // Verification

        let input_hash_var: FpVar<HelpField<E>> = Self::compute_hash_var(
            ns!(cs, "input_hash_sponge").cs(),
            &main_avk_var,
            &main_new_accumulator_instance_var,
        )?;

        input_hash_var.enforce_equal(&claimed_input_hash_var)?;

        let sponge_params = <PC::HelpSponge as CryptographicSponge>::Parameters::from_rate(SPONGE_RATE);
        let help_sponge = PC::HelpSpongeVar::new(cs.clone(), &sponge_params);
        let as_verify = ASForR1CSNarkVerifierGadget::<
            MainAffine<E>,
            PC::MainCurveVar,
            PC::HelpSponge,
            PC::HelpSpongeVar,
        >::verify(
            ns!(cs, "main_accumulation_verify").cs(),
            &main_avk_var,
            &main_input_instance_vars,
            &main_old_accumulator_instance_vars,
            &main_new_accumulator_instance_var,
            &main_accumulation_proof_var,
            Some(help_sponge),
        )?;

        base_case_var
            .or(&as_verify)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}
