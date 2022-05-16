use crate::error::PCDError;
use crate::{CircuitSpecificSetupPCD, Error, PCDPredicate, PCD};
use ark_accumulation::r1cs_nark_as::r1cs_nark::R1CSNark;
use ark_accumulation::r1cs_nark_as::{ASForR1CSNark, AccumulatorInstance, InputInstance};
use ark_accumulation::{
    r1cs_nark_as, AccumulationScheme, Accumulator, AccumulatorRef, InputRef, MakeZK,
};
use ark_ec::CurveCycle;
use ark_ff::PrimeField;
use ark_marlin::ahp::{CryptographicSpongeVarNonNative, CryptographicSpongeWithDefault};
use ark_r1cs_std::groups::CurveVar;
use ark_sponge::constraints::AbsorbGadget;
use ark_sponge::{Absorb, CryptographicSponge};
use ark_std::marker::PhantomData;
use ark_std::rand::{CryptoRng, Rng};
use help_circuit::HelpCircuit;
use main_circuit::MainCircuit;

/// Defines the public data structures that the [R1CSNarkPCD] uses.
pub mod data_structures;
use data_structures::*;

/// The help circuit of the recursion.
mod help_circuit;

/// The main circuit of the recursion.
mod main_circuit;

pub(crate) const MAKE_ZK: bool = true;

/// The different types needed by the [`R1CSNarkPCD`][nark_pcd] construction.
///
/// [nark_pcd]: crate::r1cs_nark_pcd::R1CSNarkPCD
pub trait R1CSNarkPCDConfig<E: CurveCycle>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
{
    /// The curve var for the main affine.
    type MainCurveVar: CurveVar<MainProjective<E>, HelpField<E>> + AbsorbGadget<HelpField<E>>;

    /// The curve var for the help affine.
    type HelpCurveVar: CurveVar<HelpProjective<E>, MainField<E>> + AbsorbGadget<MainField<E>>;

    /// The sponge that the main circuit uses.
    type MainSponge: CryptographicSpongeWithDefault;

    /// The sponge var that the main circuit uses.
    type MainSpongeVar: CryptographicSpongeVarNonNative<
        HelpField<E>,
        MainField<E>,
        Self::MainSponge,
    >;

    /// The sponge that the help circuit uses.
    type HelpSponge: CryptographicSpongeWithDefault;

    /// The sponge var that the help circuit uses.
    type HelpSpongeVar: CryptographicSpongeVarNonNative<
        MainField<E>,
        HelpField<E>,
        Self::HelpSponge,
    >;
}

/// A PCD that does not rely on SNARKs but instead builds on an R1CS NARK construction and its
/// accumulation scheme.
///
/// The implementation is based on the construction detailed in Section 5 of [\[BCLMS20\]][bclms20]
/// but slightly differs:
///
/// 1. To generalize for different R1CS NARK constructions and their respective accumulation
/// schemes, the implementation hashes the verifier key, messages, and accumulator instances and
/// allocates them as witnesses rather than inputs.
///
/// 2. There are now two circuits used in the recursion: the main circuit and help circuit. The main
/// circuit ensures that the accumulation of arguments about the help circuit is computed correctly
/// and that the PCD predicate holds. The help circuit ensures that the accumulation of arguments
/// about the main circuit is computed correctly.
///
/// [bclms20]: https://eprint.iacr.org/2020/1618
///
/// The scheme is as follows on a high level.
/// Assume the PCD messages and witness are already passed into the main circuit and the operations
/// related to arguments about the main circuit whenever possible.
///
/// ```rust,ignore
/// prove (old_help_nark_pf, old_main_nark_pf, old_help_acc, old_main_acc):
///     accumulate  ((old_main_acc, old_help_nark_pf), old_help_acc)
///                 -> new_help_acc, new_help_acc_pf
///     MainCircuit ((old_main_acc, old_help_nark_pf), old_help_acc, new_help_acc,
///                   new_help_acc_pf)
///                 -> main_circuit
///     nark_prove  (main_circuit)
///                 -> new_main_nark_pf
///
///     accumulate  ((old_help_acc, old_main_nark_pf), old_main_acc)
///                 -> new_main_acc, new_main_acc_pf
///     HelpCircuit ((old_help_acc, old_main_nark_pf), old_main_acc, new_main_acc,
///                   new_main_acc_pf)
///                 -> help_circuit
///     nark_prove  (help_circuit)
///                 -> new_help_nark_pf
///
///     return new_main_nark_pf, new_help_nark_pf, new_main_acc, new_help_acc
///
/// verify (main_nark_pf, help_nark_pf, main_acc, help_acc):
///     return nark_verify (main_nark_pf)
///            && nark_verify (help_nark_pf)
///            && acc_decide (main_acc)
///            && acc_decide (help_acc)
/// ```
pub struct R1CSNarkPCD<E, PC>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
{
    _curve_cycle_phantom: PhantomData<E>,
    _config_phantom: PhantomData<PC>,
}

impl<E, PC> PCD<MainField<E>> for R1CSNarkPCD<E, PC>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
{
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;

    fn circuit_specific_setup<P: PCDPredicate<MainField<E>>, R: Rng + CryptoRng>(
        predicate: &P,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Error> {
        let (main_apk, main_avk, main_adk) = {
            let help_public_inputs = HelpCircuit::<E, PC, P>::public_input_size();
            let placeholder_main_circuit = MainCircuit::<E, PC, P> {
                predicate: predicate.clone(),
                msg: P::Message::default(),
                witness: P::LocalWitness::default(),
                prior_msgs: None,
                help_avk: r1cs_nark_as::VerifierKey::placeholder(help_public_inputs),
                help_accumulation_input_instances: None,
                help_old_accumulator_instances: None,
                help_new_accumulator_instance: AccumulatorInstance::placeholder(help_public_inputs),
                help_accumulation_proof: r1cs_nark_as::Proof::placeholder(
                    help_public_inputs,
                    P::PRIOR_MSG_LEN * 2,
                    MAKE_ZK,
                ),
                _config_phantom: PhantomData,
            };

            let main_nark_pp = R1CSNark::<MainAffine<E>, PC::HelpSponge>::setup();
            let main_nark_index = R1CSNark::<MainAffine<E>, PC::HelpSponge>::index(
                &main_nark_pp,
                placeholder_main_circuit,
            )?;

            let main_as_pp = ASForR1CSNark::<MainAffine<E>, PC::HelpSponge>::setup(rng)?;

            let (main_apk, main_avk, main_adk) =
                ASForR1CSNark::<MainAffine<E>, PC::HelpSponge>::index(
                    &main_as_pp,
                    &(),
                    &main_nark_index,
                )?;

            (main_apk, main_avk, main_adk)
        };

        let (help_apk, help_avk, help_adk) = {
            let main_public_inputs = MainCircuit::<E, PC, P>::public_input_size();

            let placeholder_help_circuit = HelpCircuit::<E, PC, P> {
                main_avk: main_avk.clone(),
                main_accumulation_input_instances: None,
                main_old_accumulator_instances: None,
                main_new_accumulator_instance: AccumulatorInstance::placeholder(main_public_inputs),
                main_accumulation_proof: r1cs_nark_as::Proof::placeholder(
                    main_public_inputs,
                    P::PRIOR_MSG_LEN * 2,
                    MAKE_ZK,
                ),
                _config_phantom: PhantomData,
                _predicate_phantom: PhantomData,
            };

            let help_nark_pp = R1CSNark::<HelpAffine<E>, PC::MainSponge>::setup();
            let help_nark_index = R1CSNark::<HelpAffine<E>, PC::MainSponge>::index(
                &help_nark_pp,
                placeholder_help_circuit,
            )?;

            let help_as_pp = ASForR1CSNark::<HelpAffine<E>, PC::MainSponge>::setup(rng)?;

            let (help_apk, help_avk, help_adk) =
                ASForR1CSNark::<HelpAffine<E>, PC::MainSponge>::index(
                    &help_as_pp,
                    &(),
                    &help_nark_index,
                )?;

            (help_apk, help_avk, help_adk)
        };

        let pk = ProvingKey {
            main_apk,
            main_avk: main_avk.clone(),
            help_apk,
            help_avk: help_avk.clone(),
        };

        let vk = VerifyingKey {
            main_avk,
            help_avk,
            main_ivk: main_adk,
            help_ivk: help_adk,
        };

        Ok((pk, vk))
    }

    fn prove<P: PCDPredicate<MainField<E>>, R: Rng + CryptoRng>(
        pk: &Self::ProvingKey,
        predicate: &P,
        msg: &P::Message,
        witness: &P::LocalWitness,
        prior_msgs: &[P::Message],
        prior_proofs: &[Self::Proof],
        rng: &mut R,
    ) -> Result<Self::Proof, Error> {
        if prior_msgs.len() != 0 && prior_msgs.len() != P::PRIOR_MSG_LEN {
            return Err(Box::new(PCDError::InvalidPriorMessagesLength(
                P::PRIOR_MSG_LEN,
                prior_msgs.len(),
            )));
        }

        if prior_msgs.len() != prior_proofs.len() {
            return Err(Box::new(PCDError::InvalidPriorProofsLength(
                prior_msgs.len(),
                prior_proofs.len(),
            )));
        }

        let base_case = prior_msgs.is_empty();

        // In the base case, these vectors will be empty.
        let mut help_accumulation_input_instances = Vec::new();
        let mut help_old_accumulator_instances = Vec::new();

        let mut main_accumulation_input_instances = Vec::new();
        let mut main_old_accumulator_instances = Vec::new();

        // Extract the input and accumulator instances to be passed into the main and help circuits.
        for (msg, proof) in prior_msgs.into_iter().zip(prior_proofs) {
            let Proof {
                help_nark_proof,
                help_accumulator,
                main_nark_proof,
                main_accumulator,
            } = proof;

            help_accumulation_input_instances.push(InputInstance {
                r1cs_input: HelpCircuit::<E, PC, P>::compute_public_input(
                    &pk.main_avk,
                    &main_accumulator.0,
                )?,
                first_round_message: help_nark_proof.first_msg.clone(),
            });

            help_old_accumulator_instances.push(help_accumulator.0.clone());

            main_accumulation_input_instances.push(InputInstance {
                r1cs_input: MainCircuit::<E, PC, P>::compute_public_input(
                    &pk.help_avk,
                    &help_accumulator.0,
                    msg,
                )?,
                first_round_message: main_nark_proof.first_msg.clone(),
            });

            main_old_accumulator_instances.push(main_accumulator.0.clone());
        }

        let (help_new_accumulator, main_nark_proof) = {
            let (help_new_accumulator, help_accumulation_proof) = {
                let help_accumulation_input_refs = help_accumulation_input_instances
                    .iter()
                    .zip(prior_proofs)
                    .map(|(instance, proof)| InputRef::<
                        MainField<E>,
                        PC::MainSponge,
                        ASForR1CSNark<HelpAffine<E>, PC::MainSponge>,
                    > {
                        instance,
                        witness: &proof.help_nark_proof.second_msg,
                    });

                let help_old_accumulator_refs = prior_proofs.iter().map(|proof| AccumulatorRef::<
                    MainField<E>,
                    PC::MainSponge,
                    ASForR1CSNark<HelpAffine<E>, PC::MainSponge>,
                > {
                    instance: &proof.help_accumulator.0,
                    witness: &proof.help_accumulator.1,
                });

                ASForR1CSNark::<HelpAffine<E>, PC::MainSponge>::prove(
                    &pk.help_apk,
                    help_accumulation_input_refs,
                    help_old_accumulator_refs,
                    if MAKE_ZK {
                        MakeZK::Enabled(rng)
                    } else {
                        MakeZK::Disabled
                    },
                    None,
                )?
            };

            let main_nark_proof = {
                let (prior_msgs, help_accumulation_input_instances, help_old_accumulator_instances) =
                    if !base_case {
                        (
                            Some(prior_msgs.to_vec()),
                            Some(help_accumulation_input_instances),
                            Some(help_old_accumulator_instances),
                        )
                    } else {
                        (None, None, None)
                    };

                // Circuit to verify the predicate holds and the help accumulation was properly computed.
                let main_circuit = MainCircuit::<E, PC, P> {
                    predicate: predicate.clone(),
                    msg: msg.clone(),
                    witness: witness.clone(),
                    prior_msgs,
                    help_avk: pk.help_avk.clone(),
                    help_accumulation_input_instances,
                    help_old_accumulator_instances,
                    help_new_accumulator_instance: help_new_accumulator.instance.clone(),
                    help_accumulation_proof,
                    _config_phantom: PhantomData,
                };

                let params = PC::HelpSponge::default_params();
                let help_sponge = PC::HelpSponge::new(&params);
                let main_nark_sponge =
                    ASForR1CSNark::<MainAffine<E>, PC::HelpSponge>::nark_sponge(&help_sponge);

                R1CSNark::prove(
                    &pk.main_apk.nark_pk,
                    main_circuit,
                    MAKE_ZK,
                    Some(main_nark_sponge),
                    if MAKE_ZK { Some(rng) } else { None },
                )?
            };

            // Convert the accumulator to tuple to store in the proof.
            let help_new_accumulator = {
                let Accumulator::<
                    MainField<E>,
                    PC::MainSponge,
                    ASForR1CSNark<HelpAffine<E>, PC::MainSponge>,
                > {
                    instance,
                    witness,
                } = help_new_accumulator;

                (instance, witness)
            };

            (help_new_accumulator, main_nark_proof)
        };

        let (main_new_accumulator, help_nark_proof) = {
            let (main_new_accumulator, main_accumulation_proof) = {
                let main_accumulation_input_refs = main_accumulation_input_instances
                    .iter()
                    .zip(prior_proofs)
                    .map(|(instance, proof)| InputRef::<
                        HelpField<E>,
                        PC::HelpSponge,
                        ASForR1CSNark<MainAffine<E>, PC::HelpSponge>,
                    > {
                        instance,
                        witness: &proof.main_nark_proof.second_msg,
                    });

                let main_old_accumulator_refs = prior_proofs.iter().map(|proof| AccumulatorRef::<
                    HelpField<E>,
                    PC::HelpSponge,
                    ASForR1CSNark<MainAffine<E>, PC::HelpSponge>,
                > {
                    instance: &proof.main_accumulator.0,
                    witness: &proof.main_accumulator.1,
                });

                ASForR1CSNark::<MainAffine<E>, PC::HelpSponge>::prove(
                    &pk.main_apk,
                    main_accumulation_input_refs,
                    main_old_accumulator_refs,
                    if MAKE_ZK {
                        MakeZK::Enabled(rng)
                    } else {
                        MakeZK::Disabled
                    },
                    None,
                )?
            };

            let help_nark_proof = {
                let (main_accumulation_input_instances, main_old_accumulator_instances) =
                    if !base_case {
                        (
                            Some(main_accumulation_input_instances),
                            Some(main_old_accumulator_instances),
                        )
                    } else {
                        (None, None)
                    };

                // Circuit to verify main accumulation was properly computed.
                let help_circuit = HelpCircuit::<E, PC, P> {
                    main_avk: pk.main_avk.clone(),
                    main_accumulation_input_instances,
                    main_old_accumulator_instances,
                    main_new_accumulator_instance: main_new_accumulator.instance.clone(),
                    main_accumulation_proof,
                    _config_phantom: PhantomData,
                    _predicate_phantom: PhantomData,
                };

                let params = PC::MainSponge::default_params();
                let main_sponge = PC::MainSponge::new(&params);
                let help_nark_sponge =
                    ASForR1CSNark::<HelpAffine<E>, PC::MainSponge>::nark_sponge(&main_sponge);

                R1CSNark::prove(
                    &pk.help_apk.nark_pk,
                    help_circuit,
                    MAKE_ZK,
                    Some(help_nark_sponge),
                    if MAKE_ZK { Some(rng) } else { None },
                )?
            };

            // Convert the accumulator to tuple to store in the proof.
            let main_new_accumulator = {
                let Accumulator::<
                    HelpField<E>,
                    PC::HelpSponge,
                    ASForR1CSNark<MainAffine<E>, PC::HelpSponge>,
                > {
                    instance,
                    witness,
                } = main_new_accumulator;

                (instance, witness)
            };

            (main_new_accumulator, help_nark_proof)
        };

        Ok(Proof::<E> {
            main_nark_proof,
            help_nark_proof,
            main_accumulator: main_new_accumulator,
            help_accumulator: help_new_accumulator,
        })
    }

    fn verify<P: PCDPredicate<MainField<E>>>(
        vk: &Self::VerifyingKey,
        msg: &P::Message,
        proof: &Self::Proof,
    ) -> Result<bool, Error> {
        let main_nark_verify = {
            let params = PC::HelpSponge::default_params();
            let help_sponge = PC::HelpSponge::new(&params);
            let main_nark_sponge =
                ASForR1CSNark::<MainAffine<E>, PC::HelpSponge>::nark_sponge(&help_sponge);

            R1CSNark::verify(
                &vk.main_ivk,
                &MainCircuit::<E, PC, P>::compute_public_input(
                    &vk.help_avk,
                    &proof.help_accumulator.0,
                    msg,
                )?,
                &proof.main_nark_proof,
                Some(main_nark_sponge),
            )
        };

        let help_nark_verify = {
            let params = PC::MainSponge::default_params();
            let main_sponge = PC::MainSponge::new(&params);
            let help_nark_sponge =
                ASForR1CSNark::<HelpAffine<E>, PC::MainSponge>::nark_sponge(&main_sponge);

            R1CSNark::verify(
                &vk.help_ivk,
                &HelpCircuit::<E, PC, P>::compute_public_input(
                    &vk.main_avk,
                    &proof.main_accumulator.0,
                )?,
                &proof.help_nark_proof,
                Some(help_nark_sponge),
            )
        };

        let main_accumulation_decide = {
            let main_accumulator_ref = AccumulatorRef::<
                HelpField<E>,
                PC::HelpSponge,
                ASForR1CSNark<MainAffine<E>, PC::HelpSponge>,
            > {
                instance: &proof.main_accumulator.0,
                witness: &proof.main_accumulator.1,
            };

            ASForR1CSNark::<MainAffine<E>, PC::HelpSponge>::decide(
                &vk.main_ivk,
                main_accumulator_ref,
                None,
            )?
        };

        let help_accumulation_decide = {
            let help_accumulator_ref = AccumulatorRef::<
                MainField<E>,
                PC::MainSponge,
                ASForR1CSNark<HelpAffine<E>, PC::MainSponge>,
            > {
                instance: &proof.help_accumulator.0,
                witness: &proof.help_accumulator.1,
            };

            ASForR1CSNark::<HelpAffine<E>, PC::MainSponge>::decide(
                &vk.help_ivk,
                help_accumulator_ref,
                None,
            )?
        };

        Ok(main_nark_verify
            && help_nark_verify
            && main_accumulation_decide
            && help_accumulation_decide)
    }
}

impl<E, PC> CircuitSpecificSetupPCD<MainField<E>> for R1CSNarkPCD<E, PC>
where
    E: CurveCycle,
    MainField<E>: PrimeField + Absorb,
    HelpField<E>: PrimeField + Absorb,
    MainAffine<E>: Absorb,
    HelpAffine<E>: Absorb,
    PC: R1CSNarkPCDConfig<E>,
{
}

#[cfg(test)]
pub mod tests {
    use crate::r1cs_nark_pcd::{R1CSNarkPCD, R1CSNarkPCDConfig};
    use ark_ec::{CurveCycle, PairingEngine};
    use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
    use ark_sponge::poseidon::PoseidonSponge;

    type MainAffine = <ark_mnt4_298::MNT4_298 as PairingEngine>::G1Affine;
    type MainField = <ark_mnt4_298::MNT4_298 as PairingEngine>::Fr;
    type MainCurveVar = ark_mnt4_298::constraints::G1Var;
    type MainSponge = PoseidonSponge<MainField>;
    type MainSpongeVar = PoseidonSpongeVar<MainField>;

    type HelpAffine = <ark_mnt6_298::MNT6_298 as PairingEngine>::G1Affine;
    type HelpField = <ark_mnt6_298::MNT6_298 as PairingEngine>::Fr;
    type HelpCurveVar = ark_mnt6_298::constraints::G1Var;
    type HelpSponge = PoseidonSponge<HelpField>;
    type HelpSpongeVar = PoseidonSpongeVar<HelpField>;

    pub struct TestCycle;
    impl CurveCycle for TestCycle {
        type E1 = MainAffine;
        type E2 = HelpAffine;
    }

    pub struct TestConfig {}
    impl R1CSNarkPCDConfig<TestCycle> for TestConfig {
        type MainCurveVar = MainCurveVar;
        type HelpCurveVar = HelpCurveVar;
        type MainSponge = MainSponge;
        type MainSpongeVar = MainSpongeVar;
        type HelpSponge = HelpSponge;
        type HelpSpongeVar = HelpSpongeVar;
    }

    type TestPCD = R1CSNarkPCD<TestCycle, TestConfig>;

    #[test]
    pub fn test_ivc() {
        #[cfg(ci)]
        crate::tests::test_ivc_base_case::<MainField, TestPCD>();

        #[cfg(not(ci))]
        crate::tests::test_ivc::<MainField, TestPCD>();
    }
}
