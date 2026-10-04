//! Properties over random passwords, runs and bytes.

// Compiled for tests only, which lets clippy treat its helpers as test code.
#![cfg(test)]

use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;
use spake2plus::{
    ConfirmP, Context, Error, P256Sha256, Prover, ProverSecret, ShareP, ShareV, Verifier,
    VerifierRecord,
};

/// A PBKDF output of a usable length: two equal halves, 80 to 128 bytes.
fn pbkdf_output() -> impl Strategy<Value = Vec<u8>> {
    (40..=64_usize).prop_flat_map(|half| prop::collection::vec(any::<u8>(), 2 * half))
}

/// A run between a prover with one password and a verifier registered with
/// another (or the same): the shared keys, or the first refusal.
fn run(
    prover_output: &[u8],
    verifier_output: &[u8],
    context: &Context<'_>,
    seed: u64,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut rng = StdRng::seed_from_u64(seed);
    let secret = ProverSecret::<P256Sha256>::from_pbkdf_output(prover_output)?;
    let record = ProverSecret::<P256Sha256>::from_pbkdf_output(verifier_output)?.verifier_record();
    let (prover, share_p) = Prover::start(&secret, context, &mut rng);
    let (verifier, share_v) = Verifier::start(&record, context, &mut rng);
    let (verifier, confirm_v) = verifier.receive(&share_p)?;
    let (confirm_p, prover_key) = prover.receive(&share_v)?.finish(&confirm_v)?;
    let verifier_key = verifier.finish(&confirm_p)?;
    Ok((
        prover_key.as_bytes().to_vec(),
        verifier_key.as_bytes().to_vec(),
    ))
}

proptest! {
    #[test]
    fn the_same_password_agrees_on_a_key(
        output in pbkdf_output(),
        context in prop::collection::vec(any::<u8>(), 0..64),
        prover_id in prop::collection::vec(any::<u8>(), 0..16),
        verifier_id in prop::collection::vec(any::<u8>(), 0..16),
        seed in any::<u64>(),
    ) {
        let context = Context {
            context: &context,
            prover_id: &prover_id,
            verifier_id: &verifier_id,
        };
        let (prover_key, verifier_key) = run(&output, &output, &context, seed).unwrap();
        prop_assert_eq!(prover_key, verifier_key);
    }

    #[test]
    fn another_password_fails_the_verifiers_confirmation(
        ours in pbkdf_output(),
        theirs in pbkdf_output(),
        seed in any::<u64>(),
    ) {
        prop_assume!(ours != theirs);
        prop_assert_eq!(
            run(&ours, &theirs, &Context::default(), seed).err(),
            Some(Error::ConfirmationFailed)
        );
    }

    #[test]
    fn a_parsed_share_is_exactly_the_bytes_of_a_point(bytes in prop::collection::vec(any::<u8>(), 0..80)) {
        if let Ok(share) = ShareP::<P256Sha256>::from_bytes(&bytes) {
            prop_assert_eq!(share.as_ref(), &bytes[..]);
            prop_assert_eq!(bytes.len(), 65);
            prop_assert_eq!(bytes[0], 0x04);
        }
        prop_assert_eq!(
            ShareV::<P256Sha256>::from_bytes(&bytes).is_ok(),
            ShareP::<P256Sha256>::from_bytes(&bytes).is_ok()
        );
    }

    #[test]
    fn a_share_on_the_curve_parses(seed in any::<u64>()) {
        let mut rng = StdRng::seed_from_u64(seed);
        let secret = ProverSecret::<P256Sha256>::from_pbkdf_output(&[3; 80]).unwrap();
        let (_, share) = Prover::start(&secret, &Context::default(), &mut rng);
        prop_assert_eq!(ShareP::<P256Sha256>::from_bytes(share.as_ref()), Ok(share));
    }

    #[test]
    fn a_confirmation_parses_at_its_length_only(bytes in prop::collection::vec(any::<u8>(), 0..70)) {
        let parsed = ConfirmP::<P256Sha256>::from_bytes(&bytes);
        prop_assert_eq!(parsed.is_ok(), bytes.len() == 32);
    }

    #[test]
    fn a_parsed_record_stores_the_same_bytes(output in pbkdf_output(), flip in 0..97 * 8_usize) {
        let record = ProverSecret::<P256Sha256>::from_pbkdf_output(&output)
            .unwrap()
            .verifier_record()
            .to_bytes();
        let parsed = VerifierRecord::<P256Sha256>::from_bytes(record.as_ref()).unwrap();
        prop_assert_eq!(parsed.to_bytes(), record.clone());
        let mut altered = record.to_vec();
        altered[flip / 8] ^= 1 << (flip % 8);
        if let Ok(parsed) = VerifierRecord::<P256Sha256>::from_bytes(&altered) {
            prop_assert_eq!(&parsed.to_bytes()[..], &altered[..]);
        }
    }
}
