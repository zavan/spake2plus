use core::fmt;

/// Why a message, a record or a PBKDF output was refused, or a run aborted.
///
/// Every refusal of the peer's data aborts the run: the session that met
/// it is consumed and nothing derived from it is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A message or record of the wrong length.
    Length {
        /// The length the suite fixes.
        expected: usize,
        /// The length received.
        actual: usize,
    },
    /// A PBKDF output whose length is odd or outside the suite's
    /// [`MIN_PBKDF_OUTPUT_LEN`](crate::Suite::MIN_PBKDF_OUTPUT_LEN) and
    /// [`MAX_PBKDF_OUTPUT_LEN`](crate::Suite::MAX_PBKDF_OUTPUT_LEN).
    PbkdfOutputLength {
        /// The length received.
        actual: usize,
    },
    /// Not the uncompressed encoding of an element of the prime-order
    /// group other than the identity: off the curve, the identity, or
    /// malformed.
    InvalidPoint,
    /// A scalar that is zero or not below the group order: `w0` in a record,
    /// or `w0` or `w1` from a PBKDF output.
    InvalidScalar,
    /// A share that cancels the password's mask: `w0*N` from a verifier,
    /// or `w0*M` from a prover, which would leave `Z` and `V` the identity
    /// and nothing secret in the key.
    DegenerateShare,
    /// The peer's key confirmation does not match: it holds a different
    /// password, context or identity, or the messages were altered.
    ConfirmationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::PbkdfOutputLength { actual } => {
                write!(
                    f,
                    "a PBKDF output of {actual} bytes is not two equal halves of a usable length"
                )
            }
            Self::InvalidPoint => f.write_str("not an encoded point of the group"),
            Self::InvalidScalar => {
                f.write_str("a scalar that is zero or not below the group order")
            }
            Self::DegenerateShare => f.write_str("a share that cancels the password's mask"),
            Self::ConfirmationFailed => f.write_str("the key confirmation does not match"),
        }
    }
}

impl core::error::Error for Error {}
