use ark_accumulation::r1cs_nark_as;
use ark_accumulation::r1cs_nark_as::{r1cs_nark, AccumulatorInstance, AccumulatorWitness};
use ark_ec::{AffineCurve, CurveCycle};

pub(crate) type MainAffine<E> = <E as CurveCycle>::E1;
pub(crate) type HelpAffine<E> = <E as CurveCycle>::E2;

pub(crate) type MainField<E> = <<E as CurveCycle>::E2 as AffineCurve>::BaseField;
pub(crate) type HelpField<E> = <<E as CurveCycle>::E2 as AffineCurve>::ScalarField;

pub(crate) type MainProjective<E> = <MainAffine<E> as AffineCurve>::Projective;
pub(crate) type HelpProjective<E> = <HelpAffine<E> as AffineCurve>::Projective;

// TODO: fix
pub(crate) const SPONGE_RATE: usize = 4;

/// The proving key of [`R1CSNarkPCD`][nark_pcd].
///
/// [nark_pcd]: crate::r1cs_nark_pcd::R1CSNarkPCD
#[derive(Derivative)]
#[derivative(Clone(bound = "E: CurveCycle"))]
pub struct ProvingKey<E: CurveCycle> {
    /// The key for accumulating arguments about the main circuit.
    pub(crate) main_apk: r1cs_nark_as::ProverKey<MainAffine<E>>,

    /// The key for verifying the accumulation of arguments about the main circuit.
    pub(crate) main_avk: r1cs_nark_as::VerifierKey,

    /// The key for accumulating arguments about the help circuit.
    pub(crate) help_apk: r1cs_nark_as::ProverKey<HelpAffine<E>>,

    /// The key for verifying the accumulation of arguments about the help circuit.
    pub(crate) help_avk: r1cs_nark_as::VerifierKey,
}

/// The verifying key of [`R1CSNarkPCD`][nark_pcd].
///
/// [nark_pcd]: crate::r1cs_nark_pcd::R1CSNarkPCD
#[derive(Derivative)]
#[derivative(Clone(bound = "E: CurveCycle"))]
pub struct VerifyingKey<E: CurveCycle> {
    /// The key for verifying the accumulation of arguments about the main circuit.
    pub(crate) main_avk: r1cs_nark_as::VerifierKey,

    /// The key for verifying the accumulation of arguments about the help circuit.
    pub(crate) help_avk: r1cs_nark_as::VerifierKey,

    /// The key for verifying the arguments about the main circuit.
    pub(crate) main_ivk: r1cs_nark::IndexVerifierKey<MainAffine<E>>,

    /// The key for verifying the arguments about the help circuit.
    pub(crate) help_ivk: r1cs_nark::IndexVerifierKey<HelpAffine<E>>,
}

/// The proof of [`R1CSNarkPCD`][nark_pcd].
///
/// [nark_pcd]: crate::r1cs_nark_pcd::R1CSNarkPCD
#[derive(Derivative)]
#[derivative(Clone(bound = "E: CurveCycle"))]
pub struct Proof<E>
where
    E: CurveCycle,
{
    /// A proof attesting that the R1CS relation of the main circuit holds in the most recent step.
    pub(crate) main_nark_proof: r1cs_nark::Proof<MainAffine<E>>,

    /// A proof attesting that the R1CS relation of the help circuit holds in the most recent step.
    pub(crate) help_nark_proof: r1cs_nark::Proof<HelpAffine<E>>,

    /// An accumulator used to determine whether all of the arguments for the main circuit is
    /// verified to be true.
    pub(crate) main_accumulator: (
        AccumulatorInstance<MainAffine<E>>,
        AccumulatorWitness<MainField<E>>,
    ),

    /// An accumulator used to determine whether all of the arguments for the help circuit is
    /// verified to be true.
    pub(crate) help_accumulator: (
        AccumulatorInstance<HelpAffine<E>>,
        AccumulatorWitness<HelpField<E>>,
    ),
}
