use crate::Error;
use ark_std::rand::{CryptoRng, Rng, SeedableRng};
use ark_std::{
    cfg_chunks,
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
    vec,
    vec::Vec,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::pedersen;
use crate::variable_length_crh::VariableLengthCRH;
use ark_ec::{
    twisted_edwards_extended::GroupProjective as TEProjective, ModelParameters, ProjectiveCurve,
    TEModelParameters,
};
use ark_ff::{Field, PrimeField, UniformRand};

pub mod constraints;

type ConstraintF<P> = <<P as ModelParameters>::BaseField as Field>::BasePrimeField;

pub const WINDOW_SIZE: usize = 64;
pub const CHUNK_SIZE: usize = 3;

pub struct VariableLengthBoweHopwoodParameters<P: TEModelParameters> {
    pub seed: Vec<u8>,
    #[doc(hidden)]
    pub _params: PhantomData<P>,
}

impl<P: TEModelParameters> Clone for VariableLengthBoweHopwoodParameters<P> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed.clone(),
            _params: PhantomData,
        }
    }
}

impl<P: TEModelParameters> Default for VariableLengthBoweHopwoodParameters<P> {
    fn default() -> Self {
        Self {
            seed: vec![0u8; 32],
            _params: PhantomData,
        }
    }
}

impl<P: TEModelParameters> VariableLengthBoweHopwoodParameters<P> {
    pub fn get_generators<RO: Rng + CryptoRng + SeedableRng>(
        &self,
        pos: usize,
    ) -> Vec<Vec<TEProjective<P>>> {
        let mut seed = RO::Seed::default();
        let seed_as_mut = seed.as_mut();
        seed_as_mut[..self.seed.len()].clone_from_slice(&self.seed[..]);

        let mut rng = RO::from_seed(seed);

        let num_windows = (pos + WINDOW_SIZE - 1) / WINDOW_SIZE;

        let mut generators = Vec::new();
        for _ in 0..num_windows {
            let mut generators_for_segment = Vec::new();
            let mut base = TEProjective::rand(&mut rng);
            for _ in 0..WINDOW_SIZE {
                generators_for_segment.push(base);
                for _ in 0..4 {
                    base.double_in_place();
                }
            }
            generators.push(generators_for_segment);
        }
        generators
    }
}

pub struct VariableLengthBoweHopwoodCompressedCRH<
    RO: Rng + CryptoRng + SeedableRng,
    P: TEModelParameters,
> where
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
{
    _rand: PhantomData<RO>,
    _group: PhantomData<P>,
}

impl<RO: Rng + CryptoRng + SeedableRng, P: TEModelParameters> VariableLengthCRH<ConstraintF<P>>
    for VariableLengthBoweHopwoodCompressedCRH<RO, P>
where
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
{
    type Output = ConstraintF<P>;
    type Parameters = VariableLengthBoweHopwoodParameters<P>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let mut seed = RO::Seed::default();
        let seed_as_mut = seed.as_mut();
        rng.fill_bytes(seed_as_mut);

        Ok(Self::Parameters {
            seed: seed_as_mut.to_vec(),
            _params: PhantomData,
        })
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let mut padded_input = Vec::with_capacity(input.len());
        let input = pedersen::bytes_to_bits(input);
        padded_input.extend_from_slice(&input);
        if input.len() % CHUNK_SIZE != 0 {
            let current_length = input.len();
            padded_input.extend_from_slice(&vec![false; CHUNK_SIZE - current_length % CHUNK_SIZE]);
        }

        assert_eq!(padded_input.len() % CHUNK_SIZE, 0);
        assert_eq!(CHUNK_SIZE, 3);

        // Compute sum of h_i^{sum of
        // (1-2*c_{i,j,2})*(1+c_{i,j,0}+2*c_{i,j,1})*2^{4*(j-1)} for all j in segment}
        // for all i. Described in section 5.4.1.7 in the Zcash protocol
        // specification.

        let generator = parameters.get_generators::<RO>(padded_input.len() / CHUNK_SIZE);

        let result = cfg_chunks!(padded_input, WINDOW_SIZE * CHUNK_SIZE)
            .zip(generator)
            .map(|(segment_bits, segment_generators)| {
                cfg_chunks!(segment_bits, CHUNK_SIZE)
                    .zip(segment_generators)
                    .map(|(chunk_bits, generator)| {
                        let mut encoded = generator;
                        if chunk_bits[0] {
                            encoded += generator;
                        }
                        if chunk_bits[1] {
                            encoded = encoded + &generator + &generator;
                        }
                        if chunk_bits[2] {
                            encoded = -encoded;
                        }
                        encoded
                    })
                    .sum::<TEProjective<P>>()
            })
            .sum::<TEProjective<P>>();

        Ok(result.into_affine().x)
    }

    fn convert_output_to_field_elements(
        output: Self::Output,
    ) -> Result<Vec<ConstraintF<P>>, Error> {
        Ok(vec![output])
    }
}

impl<P: TEModelParameters> Debug for VariableLengthBoweHopwoodParameters<P>
where
    P::BaseField: PrimeField<BasePrimeField = P::BaseField>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        writeln!(f, "Bowe-Hopwood-Pedersen Hash Parameters {{")?;
        writeln!(f, "\t  Generator {:?}", self.seed)?;
        writeln!(f, "}}")
    }
}

#[cfg(test)]
mod test {
    use crate::variable_length_crh::bowe_hopwood::VariableLengthBoweHopwoodCompressedCRH;
    use crate::variable_length_crh::VariableLengthCRH;
    use ark_ed_on_bls12_381::EdwardsParameters;
    use ark_std::test_rng;
    use rand_chacha::ChaChaRng;

    type H = VariableLengthBoweHopwoodCompressedCRH<ChaChaRng, EdwardsParameters>;

    #[test]
    fn test_simple_bh() {
        let rng = &mut test_rng();
        let params = H::setup(rng).unwrap();
        let _ = H::evaluate(&params, &[1, 2, 3]).unwrap();
    }
}
