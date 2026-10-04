//! SPAKE2+ ([RFC 9383]), the augmented password-authenticated key exchange.
//!
//! Two parties, a prover (the client, which knows the password) and a
//! verifier (the server, which holds only a record derived from it), agree
//! on a shared key over an untrusted channel, each proving to the other
//! that it holds the password or its record. An eavesdropper learns
//! nothing it could test password guesses against, an active attacker can
//! test one guess per run, and a thief of the verifier's record still has
//! to guess the password before it can pose as the prover.
//!
//! # A run
//!
//! The prover derives a [`ProverSecret`] from the password (the password
//! hash is the application's: see [`ProverSecret`]), and the verifier
//! stores its [`VerifierRecord`] at registration. Then:
//!
//! ```
//! use spake2plus::{Context, P256Sha256, Prover, ProverSecret, Verifier};
//!
//! # fn main() -> Result<(), spake2plus::Error> {
//! # let pbkdf_output = [7; 80];
//! let secret = ProverSecret::<P256Sha256>::from_pbkdf_output(&pbkdf_output)?;
//! let record = secret.verifier_record();
//! let context = Context {
//!     context: b"MyApp v1",
//!     prover_id: b"alice",
//!     verifier_id: b"server",
//! };
//! let mut rng = rand::rng();
//!
//! // The prover sends shareP.
//! let (prover, share_p) = Prover::start(&secret, &context, &mut rng);
//!
//! // The verifier answers shareV and confirmV.
//! let (verifier, share_v) = Verifier::start(&record, &context, &mut rng);
//! let (verifier, confirm_v) = verifier.receive(&share_p)?;
//!
//! // The prover checks confirmV and answers confirmP.
//! let prover = prover.receive(&share_v)?;
//! let (confirm_p, prover_key) = prover.finish(&confirm_v)?;
//!
//! // The verifier checks confirmP.
//! let verifier_key = verifier.finish(&confirm_p)?;
//! assert_eq!(prover_key.as_bytes(), verifier_key.as_bytes());
//! # Ok(())
//! # }
//! ```
//!
//! Messages travel as bytes: each has `as_bytes`, and `from_bytes` to parse
//! what the peer sent, which refuses a wrong length and any share that is
//! not a point of the group other than the identity.
//!
//! Every step consumes its session, so a run cannot be resumed, repeated
//! or confirmed twice, and the [`SharedKey`] exists only once the peer's
//! confirmation has been checked. A failed step ends the run: start a new
//! one.
//!
//! # Suites
//!
//! [`P256Sha256`] and [`P256Sha512`]. [`Suite`] is sealed, so suites can be
//! added without breaking callers.
//!
//! # Random numbers
//!
//! The ephemeral scalars come from a caller's [`rand_core::CryptoRng`],
//! re-exported here at the version this crate takes, such as `rand::rng()`
//! from the `rand` crate.
//!
//! [RFC 9383]: https://www.rfc-editor.org/rfc/rfc9383
#![no_std]

#[cfg(test)]
extern crate std;

mod error;
mod messages;
mod prover;
mod registration;
mod schedule;
mod suite;
#[cfg(test)]
mod tests;
mod verifier;

pub use p256::elliptic_curve::rand_core;
pub use zeroize;

pub use error::Error;
pub use messages::{ConfirmP, ConfirmV, ShareP, ShareV, SharedKey};
pub use prover::{Prover, ProverConfirmedFirst, ProverConfirming};
pub use registration::{Context, ProverSecret, VerifierRecord};
pub use suite::{Bytes, P256Sha256, P256Sha512, Suite};
pub use verifier::{Verifier, VerifierConfirming};
