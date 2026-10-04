//! The prover and the verifier against each other, through the public API
//! and with messages carried as bytes, as an application would.

// Compiled for tests only, which lets clippy treat its helpers as test code.
#![cfg(test)]

use rand::SeedableRng;
use rand::rngs::StdRng;
use spake2plus::{
    ConfirmP, ConfirmV, Context, Error, P256Sha256, P256Sha512, Prover, ProverSecret, ShareP,
    ShareV, SharedKey, Suite, Verifier, VerifierRecord,
};

const CONTEXT: Context<'static> = Context {
    context: b"spake2plus tests v1",
    prover_id: b"alice",
    verifier_id: b"server",
};

fn secret_of<S: Suite>(fill: u8) -> ProverSecret<S> {
    ProverSecret::from_pbkdf_output(&[fill; 80]).unwrap()
}

/// A run with every message serialized and parsed on the way, the
/// verifier's record stored and loaded, and the prover confirming in the
/// RFC's order or first. The keys each side ends with, or the first error.
fn run<S: Suite>(
    prover: (&ProverSecret<S>, &Context<'_>),
    verifier: (&VerifierRecord<S>, &Context<'_>),
    prover_confirms_first: bool,
    rng: &mut StdRng,
) -> Result<(SharedKey<S>, SharedKey<S>), Error> {
    let record = VerifierRecord::<S>::from_bytes(verifier.0.to_bytes().as_ref())?;
    let (verifier_session, share_v) = Verifier::start(&record, verifier.1, rng);
    let (prover_session, share_p) = Prover::start(prover.0, prover.1, rng);

    let share_p = ShareP::from_bytes(share_p.as_ref())?;
    let (verifier_session, confirm_v) = verifier_session.receive(&share_p)?;

    let share_v = ShareV::from_bytes(share_v.as_ref())?;
    let confirm_v = ConfirmV::from_bytes(confirm_v.as_ref())?;
    let prover_session = prover_session.receive(&share_v)?;
    let (confirm_p, prover_key) = if prover_confirms_first {
        let (confirm_p, prover_session) = prover_session.confirm_first();
        let confirm_p = ConfirmP::from_bytes(confirm_p.as_ref())?;
        // The verifier checks first here, so its refusal comes first.
        let verifier_key = verifier_session.finish(&confirm_p)?;
        return Ok((prover_session.finish(&confirm_v)?, verifier_key));
    } else {
        prover_session.finish(&confirm_v)?
    };
    let confirm_p = ConfirmP::from_bytes(confirm_p.as_ref())?;
    Ok((prover_key, verifier_session.finish(&confirm_p)?))
}

fn both_orders_agree<S: Suite>() {
    let mut rng = StdRng::seed_from_u64(1);
    let secret = secret_of::<S>(7);
    let record = secret.verifier_record();
    let mut keys = Vec::new();
    for first in [false, true] {
        let (prover_key, verifier_key) =
            run((&secret, &CONTEXT), (&record, &CONTEXT), first, &mut rng).unwrap();
        assert_eq!(prover_key.as_bytes(), verifier_key.as_bytes());
        keys.push(prover_key.as_bytes().as_ref().to_vec());
    }
    assert_ne!(keys[0], keys[1], "each run has its own key");
}

#[test]
fn both_roles_agree_in_either_confirmation_order() {
    both_orders_agree::<P256Sha256>();
    both_orders_agree::<P256Sha512>();
}

fn mismatches_fail<S: Suite>() {
    let mut rng = StdRng::seed_from_u64(2);
    let secret = secret_of::<S>(7);
    let record = secret.verifier_record();
    let other = secret_of::<S>(8).verifier_record();
    let contexts = [
        Context {
            context: b"spake2plus tests v2",
            ..CONTEXT
        },
        Context {
            prover_id: b"mallory",
            ..CONTEXT
        },
        Context {
            verifier_id: b"other server",
            ..CONTEXT
        },
        Context {
            prover_id: CONTEXT.verifier_id,
            verifier_id: CONTEXT.prover_id,
            ..CONTEXT
        },
    ];
    for first in [false, true] {
        let wrong_password = run((&secret, &CONTEXT), (&other, &CONTEXT), first, &mut rng);
        assert_eq!(wrong_password.err(), Some(Error::ConfirmationFailed));
        for context in &contexts {
            let wrong_context = run((&secret, &CONTEXT), (&record, context), first, &mut rng);
            assert_eq!(wrong_context.err(), Some(Error::ConfirmationFailed));
        }
    }
}

#[test]
fn another_password_context_or_identity_fails_confirmation() {
    mismatches_fail::<P256Sha256>();
    mismatches_fail::<P256Sha512>();
}

#[test]
fn a_confirmation_from_another_run_or_role_is_refused() {
    let mut rng = StdRng::seed_from_u64(3);
    let secret = secret_of::<P256Sha256>(7);
    let record = secret.verifier_record();
    let start = |rng: &mut StdRng| {
        let (prover, share_p) = Prover::start(&secret, &CONTEXT, rng);
        let (verifier, share_v) = Verifier::start(&record, &CONTEXT, rng);
        let (verifier, confirm_v) = verifier.receive(&share_p).unwrap();
        (prover.receive(&share_v).unwrap(), verifier, confirm_v)
    };
    let (prover, verifier, confirm_v) = start(&mut rng);
    let (other_prover, _, other_confirm_v) = start(&mut rng);

    // The other run's confirmV, and this run's confirmV posing as confirmP.
    assert_eq!(
        prover.finish(&other_confirm_v).err(),
        Some(Error::ConfirmationFailed)
    );
    let as_confirm_p = ConfirmP::from_bytes(confirm_v.as_ref()).unwrap();
    assert_eq!(
        verifier.finish(&as_confirm_p).err(),
        Some(Error::ConfirmationFailed)
    );
    // The prover's own confirmP posing as confirmV.
    let (confirm_p, other_prover) = other_prover.confirm_first();
    let as_confirm_v = ConfirmV::from_bytes(confirm_p.as_ref()).unwrap();
    assert_eq!(
        other_prover.finish(&as_confirm_v).err(),
        Some(Error::ConfirmationFailed)
    );
}

#[test]
fn secrets_never_show_in_debug_output() {
    let mut rng = StdRng::seed_from_u64(4);
    let secret = secret_of::<P256Sha256>(7);
    let record = secret.verifier_record();
    let (prover, share_p) = Prover::start(&secret, &CONTEXT, &mut rng);
    let (verifier, share_v) = Verifier::start(&record, &CONTEXT, &mut rng);
    let shown = format!("{secret:?} {record:?} {prover:?} {verifier:?}");
    assert_eq!(
        shown,
        "ProverSecret(..) VerifierRecord(..) Prover(..) Verifier(..)"
    );
    let (verifier, confirm_v) = verifier.receive(&share_p).unwrap();
    let prover = prover.receive(&share_v).unwrap();
    let shown = format!("{verifier:?} {prover:?}");
    assert_eq!(shown, "VerifierConfirming(..) ProverConfirming(..)");
    let (confirm_p, prover) = prover.confirm_first();
    assert_eq!(format!("{prover:?}"), "ProverConfirmedFirst(..)");
    let key = prover.finish(&confirm_v).unwrap();
    assert_eq!(format!("{key:?}"), "SharedKey(..)");
    assert!(verifier.finish(&confirm_p).is_ok());
}

#[test]
fn the_suites_name_themselves_as_rfc_9383_does() {
    assert_eq!(P256Sha256::NAME, "P256-SHA256-HKDF-SHA256-HMAC-SHA256");
    assert_eq!(P256Sha512::NAME, "P256-SHA512-HKDF-SHA512-HMAC-SHA512");
    assert_eq!(
        (
            P256Sha256::MIN_PBKDF_OUTPUT_LEN,
            P256Sha256::MAX_PBKDF_OUTPUT_LEN
        ),
        (80, 128)
    );
}
