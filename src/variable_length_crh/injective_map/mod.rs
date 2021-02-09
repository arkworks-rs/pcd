use crate::{
    variable_length_crh::{
        pedersen::{VariableLengthPedersenCRH, VariableLengthPedersenParameters},
        VariableLengthCRH,
    },
    Error,
};
use ark_ec::models::{ModelParameters, TEModelParameters};
use ark_ff::PrimeField;
use ark_std::rand::{CryptoRng, Rng, SeedableRng};
use ark_std::{marker::PhantomData, vec, vec::Vec};

pub mod constraints;

pub struct VariableLengthPedersenCRHCompressor<
    RO: Rng + CryptoRng + SeedableRng,
    P: TEModelParameters,
> {
    pub ro_phantom: PhantomData<RO>,
    pub te_parameters_phantom: PhantomData<P>,
}

impl<RO: Rng + CryptoRng + SeedableRng, P: TEModelParameters> VariableLengthCRH<P::BaseField>
    for VariableLengthPedersenCRHCompressor<RO, P>
where
    P::BaseField: PrimeField,
{
    type Output = P::BaseField;
    type Parameters = VariableLengthPedersenParameters;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        VariableLengthPedersenCRH::<RO, P>::setup(rng)
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<P::BaseField, Error> {
        let result = VariableLengthPedersenCRH::<RO, P>::evaluate(parameters, input)?;
        Ok(result.x)
    }

    fn convert_output_to_field_elements(
        output: Self::Output,
    ) -> Result<Vec<<P as ModelParameters>::BaseField>, Error> {
        Ok(vec![output])
    }
}
