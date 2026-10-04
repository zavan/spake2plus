#![doc = include_str!("../README.md")]
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
