//! Every parser of the peer's bytes, and the steps that take what they
//! accept: nothing may panic, and whatever parses is exactly what came in.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spake2plus::rand_core::{Infallible, TryCryptoRng, TryRng};
use spake2plus::{
    ConfirmP, ConfirmV, Context, P256Sha256, P256Sha512, Prover, ProverSecret, ShareP, ShareV,
    Suite, Verifier, VerifierRecord,
};

/// A fixed stream of bytes: the runs here need no secrecy, only
/// repeatability, so a crash reproduces from its input alone.
struct Counter(u8);

impl TryRng for Counter {
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
        for byte in dst {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

impl TryCryptoRng for Counter {}

fn parse<S: Suite>(data: &[u8]) {
    let Ok(secret) = ProverSecret::<S>::from_pbkdf_output(&[7; 80]) else {
        return;
    };
    let context = Context::default();
    if let Ok(share) = ShareP::<S>::from_bytes(data) {
        assert_eq!(share.as_ref(), data);
        let (verifier, _) = Verifier::start(&secret.verifier_record(), &context, &mut Counter(0));
        // The share's own first bytes as `confirmP`: never the right one.
        let forged = data.get(..size_of::<S::Confirmation>()).unwrap_or_default();
        if let Ok((verifier, _)) = verifier.receive(&share)
            && let Ok(confirm) = ConfirmP::<S>::from_bytes(forged)
        {
            assert!(verifier.finish(&confirm).is_err(), "a forged confirmation");
        }
    }
    if let Ok(share) = ShareV::<S>::from_bytes(data) {
        assert_eq!(share.as_ref(), data);
        let (prover, _) = Prover::start(&secret, &context, &mut Counter(1));
        let _confirming = prover.receive(&share);
    }
    if let Ok(confirm) = ConfirmP::<S>::from_bytes(data) {
        assert_eq!(confirm.as_ref(), data);
    }
    if let Ok(confirm) = ConfirmV::<S>::from_bytes(data) {
        assert_eq!(confirm.as_ref(), data);
    }
    if let Ok(record) = VerifierRecord::<S>::from_bytes(data) {
        assert_eq!(record.to_bytes().as_ref(), data);
    }
    let _secret = ProverSecret::<S>::from_pbkdf_output(data);
}

fuzz_target!(|data: &[u8]| {
    parse::<P256Sha256>(data);
    parse::<P256Sha512>(data);
});
