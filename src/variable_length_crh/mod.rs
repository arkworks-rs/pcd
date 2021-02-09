use crate::Error;
use ark_ff::{PrimeField, ToBytes};
use ark_std::rand::{CryptoRng, Rng};
use ark_std::{hash::Hash, vec::Vec};

pub mod constraints;

pub trait VariableLengthCRH<F: PrimeField> {
    type Output: ToBytes + Clone + Eq + Hash + Default;
    type Parameters: Clone + Default;

    fn setup<R: Rng + CryptoRng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error>;
    fn convert_output_to_field_elements(output: Self::Output) -> Result<Vec<F>, Error>;
}

pub mod bowe_hopwood;
pub mod injective_map;
pub mod pedersen;
