use crate::variable_length_crh::VariableLengthCRH;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::{
    alloc::AllocVar, bits::uint8::UInt8, eq::EqGadget, select::CondSelectGadget, ToBytesGadget,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::{fmt::Debug, vec::Vec};

pub trait VariableLengthCRHGadget<H: VariableLengthCRH<ConstraintF>, ConstraintF: PrimeField>:
    Sized
{
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + Debug
        + Clone
        + Sized;
    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

    fn check_evaluation_gadget(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;

    fn convert_output_to_field_gadgets(
        output: &Self::OutputVar,
    ) -> Result<Vec<FpVar<ConstraintF>>, SynthesisError>;
}
