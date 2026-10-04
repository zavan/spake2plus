//! What the two sides hold before a run: the context, the prover's secret
//! and the verifier's record (RFC 9383, section 3.2).

use core::fmt;

use p256::elliptic_curve::Group as _;
use p256::elliptic_curve::ff::Field as _;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;
use crate::suite::sealed::{Bytes as _, Group as _};
use crate::suite::{Group, Point, Scalar, ScalarBytes, Suite};

/// What both sides bind into the transcript besides the password: an
/// application-specific context and the two identities, each empty when
/// absent.
///
/// The context should name the protocol and its version, and may carry the
/// suite and the PBKDF's parameters, so that both sides agree on all of
/// them. Where the identities are not implicit, RFC 9383 recommends
/// non-empty ones, against unknown key-share attacks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Context<'a> {
    /// The application's context string.
    pub context: &'a [u8],
    /// `idProver`.
    pub prover_id: &'a [u8],
    /// `idVerifier`.
    pub verifier_id: &'a [u8],
}

/// `scalar`, unless it is zero.
fn nonzero<S: Suite>(scalar: Scalar<S>) -> Result<Scalar<S>, Error> {
    if bool::from(scalar.is_zero()) {
        return Err(Error::InvalidScalar);
    }
    Ok(scalar)
}

/// The prover's secret, `w0` and `w1`, derived from the password.
///
/// It is zeroized on drop, and its `Debug` shows nothing.
///
/// # Deriving it from a password
///
/// RFC 9383 leaves the password hash to the application: run a slow,
/// salted PBKDF (Argon2id or scrypt are the RFC's examples) over
///
/// ```text
/// len(pw) || pw || len(idProver) || idProver || len(idVerifier) || idVerifier
/// ```
///
/// with each `len` eight bytes, little-endian, and pass its output,
/// `w0s || w1s`, to [`from_pbkdf_output`](Self::from_pbkdf_output). With
/// PBKDF2 from the `pbkdf2` crate, for example:
///
/// ```
/// use spake2plus::{P256Sha256, ProverSecret, Suite};
///
/// fn len(bytes: &[u8]) -> [u8; 8] {
///     (bytes.len() as u64).to_le_bytes()
/// }
///
/// let (password, prover_id, verifier_id) = (b"hunter2", b"alice", b"server");
/// let mut input = Vec::new();
/// for part in [&password[..], &prover_id[..], &verifier_id[..]] {
///     input.extend_from_slice(&len(part));
///     input.extend_from_slice(part);
/// }
/// let mut output = [0; P256Sha256::MIN_PBKDF_OUTPUT_LEN];
/// pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&input, b"per-user salt", 600_000, &mut output);
///
/// let secret = ProverSecret::<P256Sha256>::from_pbkdf_output(&output)?;
/// let record = secret.verifier_record(); // what the verifier stores
/// # Ok::<(), spake2plus::Error>(())
/// ```
pub struct ProverSecret<S: Suite> {
    w0: Scalar<S>,
    w1: Scalar<S>,
}

impl<S: Suite> ProverSecret<S> {
    /// `w0` and `w1` from a PBKDF's output, `w0s || w1s`: each half read as
    /// a big-endian integer and reduced modulo the group order.
    ///
    /// # Errors
    ///
    /// [`Error::PbkdfOutputLength`] unless the output splits into two
    /// equal halves and its length is between the suite's
    /// [`MIN_PBKDF_OUTPUT_LEN`](Suite::MIN_PBKDF_OUTPUT_LEN) and
    /// [`MAX_PBKDF_OUTPUT_LEN`](Suite::MAX_PBKDF_OUTPUT_LEN), and
    /// [`Error::InvalidScalar`] when a half reduces to zero, which no real
    /// password hash gives: a zero `w0` would leave the shares unmasked,
    /// and a zero `w1` the record `L` the identity.
    pub fn from_pbkdf_output(output: &[u8]) -> Result<Self, Error> {
        let refused = Error::PbkdfOutputLength {
            actual: output.len(),
        };
        if output.len() % 2 != 0
            || output.len() < S::MIN_PBKDF_OUTPUT_LEN
            || output.len() > S::MAX_PBKDF_OUTPUT_LEN
        {
            return Err(refused);
        }
        let (w0s, w1s) = output.split_at(output.len() / 2);
        let (Some(w0), Some(w1)) = (Group::<S>::reduce(w0s), Group::<S>::reduce(w1s)) else {
            return Err(refused);
        };
        Ok(Self {
            w0: nonzero::<S>(w0)?,
            w1: nonzero::<S>(w1)?,
        })
    }

    /// The verifier's registration record: `w0` and `L = w1*P`.
    #[must_use]
    pub fn verifier_record(&self) -> VerifierRecord<S> {
        VerifierRecord {
            w0: self.w0,
            l: Point::<S>::generator() * self.w1,
        }
    }

    pub(crate) fn w0(&self) -> &Scalar<S> {
        &self.w0
    }

    pub(crate) fn w1(&self) -> &Scalar<S> {
        &self.w1
    }
}

impl<S: Suite> Clone for ProverSecret<S> {
    fn clone(&self) -> Self {
        Self {
            w0: self.w0,
            w1: self.w1,
        }
    }
}

impl<S: Suite> Drop for ProverSecret<S> {
    fn drop(&mut self) {
        self.w0.zeroize();
        self.w1.zeroize();
    }
}

impl<S: Suite> fmt::Debug for ProverSecret<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProverSecret(..)")
    }
}

/// The verifier's registration record: `w0` and `L = w1*P`.
///
/// Keep it secret: with it, anyone can pose as the verifier, and test
/// password guesses offline against `L`. It is zeroized on drop, and its
/// `Debug` shows nothing.
pub struct VerifierRecord<S: Suite> {
    w0: Scalar<S>,
    l: Point<S>,
}

impl<S: Suite> VerifierRecord<S> {
    /// Parses a record stored with [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for the wrong length, [`Error::InvalidScalar`] when
    /// `w0` is zero or not below the group order, and [`Error::InvalidPoint`] when
    /// `L` is not an element of the group other than the identity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let expected = size_of::<S::Record>();
        let length = Error::Length {
            expected,
            actual: bytes.len(),
        };
        if bytes.len() != expected {
            return Err(length);
        }
        let (w0, l) = bytes
            .split_at_checked(size_of::<ScalarBytes<S>>())
            .ok_or(length)?;
        Ok(Self {
            w0: nonzero::<S>(Group::<S>::scalar_from_bytes(w0).ok_or(Error::InvalidScalar)?)?,
            l: Group::<S>::decode(l).ok_or(Error::InvalidPoint)?,
        })
    }

    /// The record for storage: `w0`, big-endian, then `L`, SEC1
    /// uncompressed. The copy is zeroized on drop.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<S::Record> {
        let mut record = Zeroizing::new(S::Record::zeroed());
        let w0 = Zeroizing::new(Group::<S>::scalar_to_bytes(&self.w0));
        let (head, tail) = record.as_mut().split_at_mut(w0.as_ref().len());
        head.copy_from_slice(w0.as_ref());
        // `L` is never the identity, the one point without an encoding: it
        // was decoded, or computed from a `w1` a PBKDF would have to hit
        // exactly zero.
        let _encoded: Option<()> = Group::<S>::encode(&self.l, tail);
        record
    }

    pub(crate) fn w0(&self) -> &Scalar<S> {
        &self.w0
    }

    pub(crate) fn l(&self) -> &Point<S> {
        &self.l
    }
}

impl<S: Suite> Clone for VerifierRecord<S> {
    fn clone(&self) -> Self {
        Self {
            w0: self.w0,
            l: self.l,
        }
    }
}

impl<S: Suite> Drop for VerifierRecord<S> {
    fn drop(&mut self) {
        self.w0.zeroize();
        self.l.zeroize();
    }
}

impl<S: Suite> fmt::Debug for VerifierRecord<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifierRecord(..)")
    }
}
