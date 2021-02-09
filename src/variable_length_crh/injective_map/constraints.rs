use crate::variable_length_crh::{
    constraints::VariableLengthCRHGadget,
    injective_map::VariableLengthPedersenCRHCompressor,
    pedersen::constraints::{
        VariableLengthPedersenCRHGadget, VariableLengthPedersenCRHGadgetParameters,
    },
};
use ark_ec::{models::TEModelParameters, ModelParameters};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::{CryptoRng, Rng, SeedableRng};
use ark_std::{vec, vec::Vec};

pub struct VariableLengthPedersenCRHCompressorGadget<RO, P>
where
    RO: Rng + CryptoRng + SeedableRng,
    P: TEModelParameters,
    P::BaseField: PrimeField,
{
    pub crh: VariableLengthPedersenCRHGadget<RO, P>,
}

impl<RO, P> VariableLengthCRHGadget<VariableLengthPedersenCRHCompressor<RO, P>, P::BaseField>
    for VariableLengthPedersenCRHCompressorGadget<RO, P>
where
    RO: Rng + CryptoRng + SeedableRng,
    P: TEModelParameters,
    P::BaseField: PrimeField,
{
    type OutputVar = FpVar<P::BaseField>;
    type ParametersVar = VariableLengthPedersenCRHGadgetParameters;

    fn check_evaluation_gadget(
        parameters: &Self::ParametersVar,
        input: &[UInt8<P::BaseField>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let result =
            VariableLengthPedersenCRHGadget::<RO, P>::check_evaluation_gadget(parameters, input)?;
        Ok(result.x)
    }

    fn convert_output_to_field_gadgets(
        output: &Self::OutputVar,
    ) -> Result<Vec<FpVar<<P as ModelParameters>::BaseField>>, SynthesisError> {
        Ok(vec![output.clone()])
    }
}

#[cfg(test)]
mod test {
    use crate::variable_length_crh::constraints::VariableLengthCRHGadget;
    use crate::variable_length_crh::injective_map::constraints::VariableLengthPedersenCRHCompressorGadget;
    use crate::variable_length_crh::injective_map::VariableLengthPedersenCRHCompressor;
    use crate::variable_length_crh::VariableLengthCRH;
    use ark_ed_on_bls12_381::{EdwardsParameters as JubJubParameters, Fq as Fr};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::rand::Rng;
    use ark_std::test_rng;
    use rand_chacha::ChaChaRng;

    type TestCRH = VariableLengthPedersenCRHCompressor<ChaChaRng, JubJubParameters>;
    type TestCRHGadget = VariableLengthPedersenCRHCompressorGadget<ChaChaRng, JubJubParameters>;

    fn generate_input<R: Rng>(
        cs: ConstraintSystemRef<Fr>,
        rng: &mut R,
    ) -> ([u8; 128], Vec<UInt8<Fr>>) {
        let mut input = [1u8; 128];
        rng.fill_bytes(&mut input);

        let mut input_bytes = vec![];
        for input_byte in input.iter() {
            input_bytes.push(UInt8::new_witness(cs.clone(), || Ok(*input_byte)).unwrap());
        }
        (input, input_bytes)
    }

    #[test]
    fn crh_primitive_gadget_test() {
        let rng = &mut test_rng();
        let cs_sys = ConstraintSystem::<Fr>::new();
        let cs = ConstraintSystemRef::new(cs_sys);

        let (input, input_bytes) = generate_input(cs.clone(), rng);
        println!("number of constraints for input: {}", cs.num_constraints());

        let parameters = TestCRH::setup(rng).unwrap();
        let primitive_result = TestCRH::evaluate(&parameters, &input).unwrap();

        let gadget_parameters =
            <TestCRHGadget as VariableLengthCRHGadget<TestCRH, Fr>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "gadget_parameters"),
                parameters,
            )
            .unwrap();
        println!(
            "number of constraints for input + params: {}",
            cs.num_constraints()
        );

        let gadget_result =
            <TestCRHGadget as VariableLengthCRHGadget<TestCRH, Fr>>::check_evaluation_gadget(
                &gadget_parameters,
                &input_bytes,
            )
            .unwrap();

        println!("number of constraints total: {}", cs.num_constraints());

        assert_eq!(primitive_result, gadget_result.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
