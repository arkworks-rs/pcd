#![allow(clippy::op_ref, clippy::type_complexity)]

use ark_ec::{CurveCycle, PairingEngine, PairingFriendlyCycle};
use ark_ed_on_mnt4_298::EdwardsParameters;
use ark_ff::{One, PrimeField};
use ark_marlin::constraints::snark::{MarlinSNARK, MarlinSNARKGadget};
use ark_marlin::fiat_shamir::constraints::FiatShamirAlgebraicSpongeRngVar;
use ark_marlin::fiat_shamir::poseidon::constraints::PoseidonSpongeVar;
use ark_marlin::fiat_shamir::poseidon::PoseidonSponge;
use ark_marlin::fiat_shamir::FiatShamirAlgebraicSpongeRng;
use ark_marlin::MarlinConfig;
use ark_mnt4_298::constraints::PairingVar as MNT4PairingVar;
use ark_mnt4_298::{Fq, Fr, MNT4_298};
use ark_mnt6_298::constraints::PairingVar as MNT6PairingVar;
use ark_mnt6_298::MNT6_298;
use ark_pcd::ec_cycle_pcd::{ECCyclePCD, ECCyclePCDConfig};
use ark_pcd::variable_length_crh::bowe_hopwood::constraints::VariableLengthBoweHopwoodCompressedCRHGadget;
use ark_pcd::variable_length_crh::bowe_hopwood::VariableLengthBoweHopwoodCompressedCRH;
use ark_pcd::{PCDPredicate, PCD};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::{MarlinKZG10, MarlinKZG10Gadget};
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;
use core::marker::PhantomData;
use rand_chacha::ChaChaRng;

#[derive(Copy, Clone, Debug)]
pub struct Mnt46298Cycle;
impl CurveCycle for Mnt46298Cycle {
    type E1 = <MNT4_298 as PairingEngine>::G1Affine;
    type E2 = <MNT6_298 as PairingEngine>::G1Affine;
}
impl PairingFriendlyCycle for Mnt46298Cycle {
    type Engine1 = MNT4_298;
    type Engine2 = MNT6_298;
}

#[derive(Copy, Clone, Debug)]
pub struct Mnt64298Cycle;
impl CurveCycle for Mnt64298Cycle {
    type E1 = <MNT6_298 as PairingEngine>::G1Affine;
    type E2 = <MNT4_298 as PairingEngine>::G1Affine;
}
impl PairingFriendlyCycle for Mnt64298Cycle {
    type Engine1 = MNT6_298;
    type Engine2 = MNT4_298;
}

type FS4 = FiatShamirAlgebraicSpongeRng<Fr, Fq, PoseidonSponge<Fq>>;
type FS6 = FiatShamirAlgebraicSpongeRng<Fq, Fr, PoseidonSponge<Fr>>;

type PCGadget4 = MarlinKZG10Gadget<Mnt64298Cycle, DensePolynomial<Fr>, MNT4PairingVar>;
type PCGadget6 = MarlinKZG10Gadget<Mnt46298Cycle, DensePolynomial<Fq>, MNT6PairingVar>;

type FSG4 = FiatShamirAlgebraicSpongeRngVar<Fr, Fq, PoseidonSponge<Fq>, PoseidonSpongeVar<Fq>>;
type FSG6 = FiatShamirAlgebraicSpongeRngVar<Fq, Fr, PoseidonSponge<Fr>, PoseidonSpongeVar<Fr>>;

#[derive(Clone)]
pub struct TestMarlinConfig;
impl MarlinConfig for TestMarlinConfig {
    const FOR_RECURSION: bool = true;
}

pub struct PCDMarlin;
impl ECCyclePCDConfig<Fr, Fq> for PCDMarlin {
    type CRH = VariableLengthBoweHopwoodCompressedCRH<ChaChaRng, EdwardsParameters>;
    type CRHGadget = VariableLengthBoweHopwoodCompressedCRHGadget<ChaChaRng, EdwardsParameters>;
    type MainSNARK =
        MarlinSNARK<Fr, Fq, MarlinKZG10<MNT4_298, DensePolynomial<Fr>>, FS4, TestMarlinConfig>;
    type HelpSNARK =
        MarlinSNARK<Fq, Fr, MarlinKZG10<MNT6_298, DensePolynomial<Fq>>, FS6, TestMarlinConfig>;
    type MainSNARKGadget = MarlinSNARKGadget<
        Fr,
        Fq,
        MarlinKZG10<MNT4_298, DensePolynomial<Fr>>,
        FS4,
        TestMarlinConfig,
        PCGadget4,
        FSG4,
    >;
    type HelpSNARKGadget = MarlinSNARKGadget<
        Fq,
        Fr,
        MarlinKZG10<MNT6_298, DensePolynomial<Fq>>,
        FS6,
        TestMarlinConfig,
        PCGadget6,
        FSG6,
    >;
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

type TestPCD = ECCyclePCD<Fr, Fq, PCDMarlin>;

#[test]
fn test_marlin_pcd() {
    let val_1 = Fr::one();

    let circ = TestPredicate::<Fr>::new();
    let mut rng = ark_std::test_rng();

    let (pk, vk) = TestPCD::circuit_specific_setup(&circ, &mut rng).unwrap();

    let proof_1 = TestPCD::prove(&pk, &circ, &val_1, &val_1, &[], &[], &mut rng).unwrap();
    assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_1, &proof_1).unwrap());

    #[cfg(not(ci))]
    {
        let val_2 = val_1 + &val_1;
        let val_3 = val_1 + &val_2;

        let proof_2 =
            TestPCD::prove(&pk, &circ, &val_2, &val_1, &[val_1], &[proof_1], &mut rng).unwrap();
        assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_2, &proof_2).unwrap());

        let proof_3 =
            TestPCD::prove(&pk, &circ, &val_3, &val_1, &[val_2], &[proof_2], &mut rng).unwrap();
        assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_3, &proof_3).unwrap());

        assert!(!TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_1, &proof_3).unwrap());
    }
}

#[test]
#[cfg(not(ci))]
fn test_marlin_universal_pcd() {
    use ark_marlin::constraints::snark::MarlinBound;
    use ark_pcd::UniversalSetupPCD;
    use ark_snark::UniversalSetupSNARK;

    let val_1 = Fr::one();
    let val_2 = val_1 + &val_1;
    let val_3 = val_1 + &val_2;

    let circ = TestPredicate::<Fr>::new();
    let mut rng = ark_std::test_rng();

    let bound: <MarlinSNARK<
        Fr,
        Fq,
        MarlinKZG10<MNT4_298, DensePolynomial<Fr>>,
        FS4,
        TestMarlinConfig,
    > as UniversalSetupSNARK<Fr>>::ComputationBound = MarlinBound { max_degree: 10 };

    let pp = TestPCD::universal_setup(&bound, &mut rng).unwrap();

    let (pk, vk) = TestPCD::index(&pp, &circ, &mut rng).unwrap();

    let proof_1 = TestPCD::prove(&pk, &circ, &val_1, &val_1, &[], &[], &mut rng).unwrap();
    assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_1, &proof_1).unwrap());

    let proof_2 =
        TestPCD::prove(&pk, &circ, &val_2, &val_1, &[val_1], &[proof_1], &mut rng).unwrap();
    assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_2, &proof_2).unwrap());

    let proof_3 =
        TestPCD::prove(&pk, &circ, &val_3, &val_1, &[val_2], &[proof_2], &mut rng).unwrap();
    assert!(TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_3, &proof_3).unwrap());

    assert!(!TestPCD::verify::<TestPredicate<Fr>>(&vk, &val_1, &proof_3).unwrap());
}
