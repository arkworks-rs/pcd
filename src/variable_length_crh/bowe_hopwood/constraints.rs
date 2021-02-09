use ark_ec::{twisted_edwards_extended::GroupProjective as TEProjective, TEModelParameters};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, groups::curves::twisted_edwards::AffineVar, prelude::*, uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, marker::PhantomData, vec, vec::Vec};

use crate::variable_length_crh::bowe_hopwood::{
    VariableLengthBoweHopwoodCompressedCRH, VariableLengthBoweHopwoodParameters,
};
use crate::variable_length_crh::constraints::VariableLengthCRHGadget;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::rand::{CryptoRng, Rng, SeedableRng};

#[derive(Default)]
pub struct VariableLengthBoweHopwoodParametersVar<P: TEModelParameters> {
    params: VariableLengthBoweHopwoodParameters<P>,
}

impl<P: TEModelParameters> Clone for VariableLengthBoweHopwoodParametersVar<P> {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
        }
    }
}

impl<P: TEModelParameters> VariableLengthBoweHopwoodParametersVar<P> {
    pub fn get_generators<RO: Rng + CryptoRng + SeedableRng>(
        &self,
        pos: usize,
    ) -> Vec<Vec<TEProjective<P>>> {
        self.params.get_generators::<RO>(pos)
    }
}

pub const WINDOW_SIZE: usize = 64;
pub const CHUNK_SIZE: usize = 3;

pub struct VariableLengthBoweHopwoodCompressedCRHGadget<
    RO: Rng + CryptoRng + SeedableRng,
    P: TEModelParameters,
> where
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
{
    #[doc(hidden)]
    _rand: PhantomData<RO>,
    #[doc(hidden)]
    _params: PhantomData<P>,
}

impl<RO, P> VariableLengthCRHGadget<VariableLengthBoweHopwoodCompressedCRH<RO, P>, P::BaseField>
    for VariableLengthBoweHopwoodCompressedCRHGadget<RO, P>
where
    RO: Rng + CryptoRng + SeedableRng,
    P: TEModelParameters,
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
{
    type OutputVar = FpVar<P::BaseField>;
    type ParametersVar = VariableLengthBoweHopwoodParametersVar<P>;

    fn check_evaluation_gadget(
        parameters: &Self::ParametersVar,
        input: &[UInt8<P::BaseField>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        // Pad the input if it is not the current length.
        let mut input_in_bits: Vec<Boolean<_>> = input
            .iter()
            .flat_map(|byte| byte.to_bits_le().unwrap())
            .collect();

        if (input_in_bits.len()) % CHUNK_SIZE != 0 {
            let current_length = input_in_bits.len();
            for _ in 0..(CHUNK_SIZE - current_length % CHUNK_SIZE) {
                input_in_bits.push(Boolean::constant(false));
            }
        }

        assert!(input_in_bits.len() % CHUNK_SIZE == 0);

        let generators = parameters.get_generators::<RO>(input_in_bits.len() / CHUNK_SIZE);

        // Allocate new variable for the result.
        let input_in_bits = input_in_bits
            .chunks(WINDOW_SIZE * CHUNK_SIZE)
            .map(|x| x.chunks(CHUNK_SIZE).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        let result =
            AffineVar::<P, FpVar<P::BaseField>>::precomputed_base_3_bit_signed_digit_scalar_mul(
                &generators,
                &input_in_bits,
            )?;

        Ok(result.x)
    }

    fn convert_output_to_field_gadgets(
        output: &Self::OutputVar,
    ) -> Result<Vec<FpVar<P::BaseField>>, SynthesisError> {
        Ok(vec![(*output).clone()])
    }
}

impl<P> AllocVar<VariableLengthBoweHopwoodParameters<P>, P::BaseField>
    for VariableLengthBoweHopwoodParametersVar<P>
where
    P: TEModelParameters,
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
{
    fn new_variable<T: Borrow<VariableLengthBoweHopwoodParameters<P>>>(
        _cs: impl Into<Namespace<P::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(VariableLengthBoweHopwoodParametersVar { params })
    }
}

#[cfg(test)]
mod test {
    use ark_std::rand::Rng;

    use crate::variable_length_crh::bowe_hopwood::constraints::VariableLengthBoweHopwoodCompressedCRHGadget;
    use crate::variable_length_crh::bowe_hopwood::VariableLengthBoweHopwoodCompressedCRH;
    use crate::variable_length_crh::constraints::VariableLengthCRHGadget;
    use crate::variable_length_crh::VariableLengthCRH;
    use ark_ed_on_bls12_381::{EdwardsParameters, Fq as Fr};
    use ark_std::test_rng;

    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use rand_chacha::ChaChaRng;

    type TestCRH = VariableLengthBoweHopwoodCompressedCRH<ChaChaRng, EdwardsParameters>;
    type TestCRHGadget = VariableLengthBoweHopwoodCompressedCRHGadget<ChaChaRng, EdwardsParameters>;

    fn generate_input<R: Rng>(
        cs: ConstraintSystemRef<Fr>,
        rng: &mut R,
    ) -> ([u8; 189], Vec<UInt8<Fr>>) {
        let mut input = [1u8; 189];
        rng.fill_bytes(&mut input);

        let mut input_bytes = vec![];
        for byte in input.iter() {
            input_bytes.push(UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap());
        }
        (input, input_bytes)
    }

    #[test]
    fn test_native_equality() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let (input, input_var) = generate_input(cs.clone(), rng);
        println!("number of constraints for input: {}", cs.num_constraints());

        let parameters = TestCRH::setup(rng).unwrap();
        let primitive_result = TestCRH::evaluate(&parameters, &input).unwrap();

        let parameters_var =
            <TestCRHGadget as VariableLengthCRHGadget<TestCRH, Fr>>::ParametersVar::new_witness(
                ark_relations::ns!(cs, "parameters_var"),
                || Ok(&parameters),
            )
            .unwrap();
        println!(
            "number of constraints for input + params: {}",
            cs.num_constraints()
        );

        let result_var =
            TestCRHGadget::check_evaluation_gadget(&parameters_var, &input_var).unwrap();

        println!("number of constraints total: {}", cs.num_constraints());

        assert_eq!(primitive_result, result_var.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
