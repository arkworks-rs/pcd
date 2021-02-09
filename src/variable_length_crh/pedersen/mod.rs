use crate::{variable_length_crh::VariableLengthCRH, Error};
use ark_ec::{
    group::Group, models::TEModelParameters, twisted_edwards_extended::GroupAffine as TEAffine,
};
use ark_ff::{PrimeField, ToConstraintField, Zero};
use ark_std::rand::{CryptoRng, Rng, SeedableRng};
use ark_std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
};
use ark_std::{vec, vec::Vec};

pub mod constraints;

pub struct VariableLengthPedersenParameters {
    pub seed: Vec<u8>,
}

impl VariableLengthPedersenParameters {
    pub fn get_generators<RO: Rng + CryptoRng + SeedableRng, G: Group>(
        &self,
        pos: usize,
    ) -> Vec<G> {
        let mut seed = RO::Seed::default();
        let seed_as_mut = seed.as_mut();
        seed_as_mut[..self.seed.len()].clone_from_slice(&self.seed[..]);

        let mut rng = RO::from_seed(seed);

        let mut res = Vec::<G>::new();
        for _ in 0..pos {
            res.push(G::rand(&mut rng));
        }
        res
    }
}

pub struct VariableLengthPedersenCRH<RO: Rng + CryptoRng + SeedableRng, P: TEModelParameters> {
    #[doc(hidden)]
    pub ro_phantom: PhantomData<RO>,
    #[doc(hidden)]
    pub te_parameters_phantom: PhantomData<P>,
}

impl<RO: Rng + CryptoRng + SeedableRng, P: TEModelParameters> VariableLengthCRH<P::BaseField>
    for VariableLengthPedersenCRH<RO, P>
where
    P::BaseField: PrimeField,
{
    type Output = TEAffine<P>;
    type Parameters = VariableLengthPedersenParameters;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let mut seed = RO::Seed::default();
        let seed_as_mut = seed.as_mut();
        rng.fill_bytes(seed_as_mut);

        Ok(Self::Parameters {
            seed: seed_as_mut.to_vec(),
        })
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let mut padded_input = Vec::with_capacity(input.len() + 4);
        let len = (input.len() as u32).to_le_bytes();
        padded_input.extend_from_slice(&len);
        padded_input.extend_from_slice(input);

        assert!(input.len() < (1u64 << 32) as usize);

        // Compute sum of h_i^{m_i} for all i.
        let bits = bytes_to_bits(&padded_input);
        let generators = parameters.get_generators::<RO, TEAffine<P>>(bits.len());

        let result = bits
            .iter()
            .zip(generators.iter())
            .map(|(bit, generator)| {
                if *bit {
                    *generator
                } else {
                    TEAffine::<P>::zero()
                }
            })
            .sum::<TEAffine<P>>();

        Ok(result)
    }

    fn convert_output_to_field_elements(output: Self::Output) -> Result<Vec<P::BaseField>, Error> {
        Ok(vec![output.x, output.y])
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> i) & 1;
            bits.push(bit == 1)
        }
    }
    bits
}

impl Debug for VariableLengthPedersenParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        writeln!(f, "Pedersen Hash Parameters {{")?;
        writeln!(f, "\t  Generator {:?}", self.seed)?;
        writeln!(f, "}}")
    }
}

impl<ConstraintF: PrimeField> ToConstraintField<ConstraintF> for VariableLengthPedersenParameters {
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        self.seed.to_field_elements()
    }
}

impl Clone for VariableLengthPedersenParameters {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed.clone(),
        }
    }
}

impl Default for VariableLengthPedersenParameters {
    fn default() -> Self {
        Self { seed: Vec::new() }
    }
}
