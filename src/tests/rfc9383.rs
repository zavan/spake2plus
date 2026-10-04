//! Both roles against RFC 9383's test vectors, every value of each.

use std::vec::Vec;

use hmac::digest::Digest;

use super::vectors::{P256_SHA256, P256_SHA512, Vector};
use super::{Replay, unhex};
use crate::schedule::{Transcript, expand};
use crate::suite::sealed::{Bytes as _, Group as _};
use crate::suite::{Group, Hash, Point};
use crate::{
    ConfirmP, ConfirmV, Context, P256Sha256, P256Sha512, Prover, ProverSecret, ShareP, ShareV,
    Suite, Verifier, VerifierRecord,
};

/// The vector's context and identities.
fn context(vector: &Vector) -> Context<'static> {
    Context {
        context: vector.context,
        prover_id: vector.prover_id,
        verifier_id: vector.verifier_id,
    }
}

/// A PBKDF output that reduces to the vector's `w0` and `w1`: each padded
/// to the 40 bytes a half takes, with zeros in front.
fn secret<S: Suite>(vector: &Vector) -> ProverSecret<S> {
    let mut output = Vec::new();
    for scalar in [vector.w0, vector.w1] {
        output.extend_from_slice(&[0; 8]);
        output.extend_from_slice(&unhex(scalar));
    }
    ProverSecret::from_pbkdf_output(&output).unwrap()
}

/// `point`, encoded as it travels.
fn encoded<S: Suite>(point: &Point<S>) -> Vec<u8> {
    let mut bytes = S::Share::zeroed();
    Group::<S>::encode(point, bytes.as_mut()).unwrap();
    bytes.as_ref().to_vec()
}

fn registration_matches<S: Suite>(vector: &Vector) {
    let record = secret::<S>(vector).verifier_record();
    let mut expected = unhex(vector.w0);
    expected.extend_from_slice(&unhex(vector.l));
    assert_eq!(record.to_bytes().as_ref(), &expected[..]);
    let parsed = VerifierRecord::<S>::from_bytes(&expected).unwrap();
    assert_eq!(parsed.to_bytes().as_ref(), &expected[..]);
}

fn shares_and_shared_points_match<S: Suite>(vector: &Vector) {
    let secret = secret::<S>(vector);
    let (prover, share_p) = Prover::start(&secret, &context(vector), &mut Replay::scalar(vector.x));
    let (verifier, share_v) = Verifier::start(
        &secret.verifier_record(),
        &context(vector),
        &mut Replay::scalar(vector.y),
    );
    assert_eq!(share_p.as_ref(), &unhex(vector.share_p)[..]);
    assert_eq!(share_v.as_ref(), &unhex(vector.share_v)[..]);
    for (z, v) in [
        prover.shared(&share_v).unwrap(),
        verifier.shared(&share_p).unwrap(),
    ] {
        assert_eq!(encoded::<S>(&z), unhex(vector.z));
        assert_eq!(encoded::<S>(&v), unhex(vector.v));
    }
}

fn key_schedule_matches<S: Suite>(vector: &Vector) {
    assert_eq!(
        Hash::<S>::digest(unhex(vector.tt)).to_vec(),
        unhex(vector.k_main),
        "the vector's own TT and K_main"
    );
    let share_p = ShareP::<S>::from_bytes(&unhex(vector.share_p)).unwrap();
    let share_v = ShareV::<S>::from_bytes(&unhex(vector.share_v)).unwrap();
    let point = |hex| Group::<S>::decode(&unhex(hex)).unwrap();
    let w0 = Group::<S>::scalar_from_bytes(&unhex(vector.w0)).unwrap();
    let main = Transcript::<S>::new(&context(vector))
        .main(
            &share_p,
            &share_v,
            (&point(vector.z), &point(vector.v)),
            &w0,
        )
        .unwrap();
    assert_eq!(main.to_vec(), unhex(vector.k_main));

    let mut shared = S::SharedKey::zeroed();
    let confirmation = expand::<S>(&main, &mut shared).unwrap();
    let mut expected = unhex(vector.k_confirm_p);
    expected.extend_from_slice(&unhex(vector.k_confirm_v));
    assert_eq!(confirmation.as_ref(), &expected[..]);
    assert_eq!(shared.as_ref(), &unhex(vector.k_shared)[..]);
}

/// A whole run, in the RFC's order, and with the prover confirming first.
fn runs_match<S: Suite>(vector: &Vector) {
    for prover_confirms_first in [false, true] {
        let secret = secret::<S>(vector);
        let (prover, share_p) =
            Prover::start(&secret, &context(vector), &mut Replay::scalar(vector.x));
        let (verifier, share_v) = Verifier::start(
            &secret.verifier_record(),
            &context(vector),
            &mut Replay::scalar(vector.y),
        );
        let (verifier, confirm_v) = verifier.receive(&share_p).unwrap();
        assert_eq!(confirm_v.as_ref(), &unhex(vector.confirm_v)[..]);

        let prover = prover.receive(&share_v).unwrap();
        let (confirm_p, prover_key) = if prover_confirms_first {
            let (confirm_p, prover) = prover.confirm_first();
            (confirm_p, prover.finish(&confirm_v).unwrap())
        } else {
            prover.finish(&confirm_v).unwrap()
        };
        assert_eq!(confirm_p.as_ref(), &unhex(vector.confirm_p)[..]);
        assert_eq!(prover_key.as_bytes().as_ref(), &unhex(vector.k_shared)[..]);

        let verifier_key = verifier.finish(&confirm_p).unwrap();
        assert_eq!(
            verifier_key.as_bytes().as_ref(),
            &unhex(vector.k_shared)[..]
        );
    }
}

/// The parsed messages are the vector's, byte for byte.
fn messages_round_trip<S: Suite>(vector: &Vector) {
    for hex in [vector.share_p, vector.share_v] {
        let bytes = unhex(hex);
        assert_eq!(
            ShareP::<S>::from_bytes(&bytes).unwrap().as_ref(),
            &bytes[..]
        );
        assert_eq!(
            ShareV::<S>::from_bytes(&bytes).unwrap().as_ref(),
            &bytes[..]
        );
    }
    for hex in [vector.confirm_p, vector.confirm_v] {
        let bytes = unhex(hex);
        assert_eq!(
            ConfirmP::<S>::from_bytes(&bytes).unwrap().as_ref(),
            &bytes[..]
        );
        assert_eq!(
            ConfirmV::<S>::from_bytes(&bytes).unwrap().as_ref(),
            &bytes[..]
        );
    }
}

fn the_vector_matches<S: Suite>(vector: &Vector) {
    assert_eq!(
        vector.context,
        std::format!("SPAKE2+-{} Test Vectors", S::NAME).as_bytes(),
        "the vector is this suite's"
    );
    registration_matches::<S>(vector);
    shares_and_shared_points_match::<S>(vector);
    key_schedule_matches::<S>(vector);
    runs_match::<S>(vector);
    messages_round_trip::<S>(vector);
}

#[test]
fn p256_sha256_matches_the_rfc_vector() {
    the_vector_matches::<P256Sha256>(&P256_SHA256);
}

#[test]
fn p256_sha512_matches_the_rfc_vector() {
    the_vector_matches::<P256Sha512>(&P256_SHA512);
}
