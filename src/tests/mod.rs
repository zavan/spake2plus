//! Tests with access to the crate's internals: the RFC's vectors, checked
//! value by value, and the group's encodings and reductions.

mod group;
mod rfc9383;
mod vectors;

use std::vec::Vec;

use crate::rand_core::{Infallible, TryCryptoRng, TryRng};

/// The bytes `hex` spells.
fn unhex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "an odd number of hex digits");
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

/// A "random" number generator that gives back exactly the bytes it was
/// made with, so a run can be made to pick the RFC's `x` and `y`. Running
/// out of them fails the test.
struct Replay(Vec<u8>);

impl Replay {
    /// The 64 bytes that reduce to the scalar `hex` spells: zeros, then it.
    fn scalar(hex: &str) -> Self {
        let scalar = unhex(hex);
        let mut bytes = std::vec![0; 64 - scalar.len()];
        bytes.extend_from_slice(&scalar);
        Self(bytes)
    }
}

impl TryRng for Replay {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        assert!(dst.len() <= self.0.len(), "the replayed bytes ran out");
        dst.copy_from_slice(&self.0[..dst.len()]);
        self.0.drain(..dst.len());
        Ok(())
    }
}

impl TryCryptoRng for Replay {}
