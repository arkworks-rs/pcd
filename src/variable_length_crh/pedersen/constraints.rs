use ark_ec::{
    models::TEModelParameters, twisted_edwards_extended::GroupProjective as TEProjective,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar as TEAffineVar;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{vec, vec::Vec};

use crate::variable_length_crh::constraints::VariableLengthCRHGadget;
use crate::variable_length_crh::pedersen::{
    VariableLengthPedersenCRH, VariableLengthPedersenParameters,
};
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::{
    alloc::AllocVar, bits::uint8::UInt8, fields::fp::FpVar, groups::CurveVar, ToBitsGadget,
};
use ark_std::rand::{CryptoRng, Rng, SeedableRng};
use core::{borrow::Borrow, marker::PhantomData};

pub struct VariableLengthPedersenCRHGadgetParameters {
    pub params: VariableLengthPedersenParameters,
}

impl Clone for VariableLengthPedersenCRHGadgetParameters {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
        }
    }
}

pub struct VariableLengthPedersenCRHGadget<RO: Rng + CryptoRng + SeedableRng, P: TEModelParameters>
{
    #[doc(hidden)]
    pub ro_phantom: PhantomData<RO>,
    #[doc(hideen)]
    pub te_parameters_phantom: PhantomData<P>,
}

impl<RO, P> VariableLengthCRHGadget<VariableLengthPedersenCRH<RO, P>, P::BaseField>
    for VariableLengthPedersenCRHGadget<RO, P>
where
    RO: Rng + CryptoRng + SeedableRng,
    P: TEModelParameters,
    P::BaseField: PrimeField,
{
    type OutputVar = TEAffineVar<P, FpVar<P::BaseField>>;
    type ParametersVar = VariableLengthPedersenCRHGadgetParameters;

    fn check_evaluation_gadget(
        parameters: &Self::ParametersVar,
        input: &[UInt8<P::BaseField>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut padded_input = Vec::with_capacity(input.len() + 4);

        let input_len = (input.len() as u32).to_le_bytes();
        padded_input.extend_from_slice(&*UInt8::constant_vec(&input_len));
        padded_input.extend_from_slice(input);

        assert!(input.len() < (1u64 << 32) as usize);

        // Compute sum of h_i^{m_i} for all i.
        let input_in_bits: Vec<_> = padded_input
            .iter()
            .flat_map(|byte| byte.to_bits_le().unwrap())
            .collect();

        let generators = parameters
            .params
            .get_generators::<RO, TEProjective<P>>(input_in_bits.len());

        let mut result = TEAffineVar::<P, FpVar<P::BaseField>>::zero();

        result.precomputed_base_scalar_mul_le(input_in_bits.iter().zip(generators.iter()))?;

        Ok(result)
    }

    fn convert_output_to_field_gadgets(
        output: &Self::OutputVar,
    ) -> Result<Vec<FpVar<P::BaseField>>, SynthesisError> {
        Ok(vec![output.x.clone(), output.y.clone()])
    }
}

#[cfg(test)]
mod test {
    use crate::variable_length_crh::constraints::VariableLengthCRHGadget;
    use crate::variable_length_crh::VariableLengthCRH;
    use crate::variable_length_crh::{
        pedersen::constraints::VariableLengthPedersenCRHGadget, pedersen::VariableLengthPedersenCRH,
    };
    use ark_ed_on_bls12_381::{EdwardsParameters as JubJubParameters, Fq as Fr};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::rand::Rng;
    use ark_std::test_rng;
    use rand_chacha::ChaChaRng;

    type TestCRH = VariableLengthPedersenCRH<ChaChaRng, JubJubParameters>;
    type TestCRHGadget = VariableLengthPedersenCRHGadget<ChaChaRng, JubJubParameters>;

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

        assert_eq!(primitive_result.x, gadget_result.x.value().unwrap());
        assert_eq!(primitive_result.y, gadget_result.y.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}

impl<ConstraintF: Field> AllocVar<VariableLengthPedersenParameters, ConstraintF>
    for VariableLengthPedersenCRHGadgetParameters
{
    fn new_variable<T: Borrow<VariableLengthPedersenParameters>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let t = f()?;
        let params = t.borrow().clone();
        Ok(VariableLengthPedersenCRHGadgetParameters { params })
    }
}
