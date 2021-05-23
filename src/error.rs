use ark_std::error::Error;

/// Common errors that PCD schemes may throw.
#[derive(Debug)]
pub enum PCDError {
    /// The number of prior messages does not match the predicate.
    InvalidPriorMessagesLength(usize, usize),

    /// The number of prior proofs does not match the predicate.
    InvalidPriorProofsLength(usize, usize),
}

impl core::fmt::Display for PCDError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let error_text = match self {
            PCDError::InvalidPriorMessagesLength(expected, actual) => format!(
                "Expected the number of prior messages to be `{}` but got `{}` instead",
                expected, actual
            ),

            PCDError::InvalidPriorProofsLength(expected, actual) => format!(
                "Expected the number of prior proofs to be `{}` but got `{}` instead",
                expected, actual
            ),
        };

        write!(f, "{}", error_text)
    }
}

impl Error for PCDError {}
