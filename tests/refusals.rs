//! Every refusal, through the public API: malformed and invalid shares,
//! shares that cancel the password's mask, confirmations, records and
//! PBKDF outputs.

// Compiled for tests only, which lets clippy treat its helpers as test code.
#![cfg(test)]

use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{ProjectivePoint, PublicKey, Scalar};
use rand::SeedableRng;
use rand::rngs::StdRng;
use spake2plus::{
    ConfirmP, ConfirmV, Context, Error, P256Sha256, P256Sha512, Prover, ProverSecret, ShareP,
    ShareV, Verifier, VerifierRecord,
};

/// RFC 9383's `M` and `N` for P-256, compressed.
const M: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
/// The field prime of P-256.
const PRIME: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
/// The group order of P-256.
const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn uncompressed(point: &ProjectivePoint) -> Vec<u8> {
    point.to_sec1_point(false).as_bytes().to_vec()
}

fn point(compressed: &str) -> ProjectivePoint {
    PublicKey::from_sec1_bytes(&unhex(compressed))
        .unwrap()
        .to_projective()
}

/// A secret whose `w0` is 5: the low byte of each 40-byte half.
fn secret_with_w0_of_5() -> ProverSecret<P256Sha256> {
    let mut output = [0; 80];
    output[39] = 5;
    output[79] = 9;
    ProverSecret::from_pbkdf_output(&output).unwrap()
}

/// Encodings that are not a share, each with the refusal it meets.
fn malformed_shares() -> Vec<(Vec<u8>, Error)> {
    let generator = uncompressed(&ProjectivePoint::GENERATOR);
    let length = |actual| Error::Length {
        expected: 65,
        actual,
    };
    let with_tag = |tag: u8| {
        let mut bytes = generator.clone();
        bytes[0] = tag;
        bytes
    };
    let mut off_curve = generator.clone();
    off_curve[64] ^= 1;
    let mut x_is_the_prime = vec![0x04];
    x_is_the_prime.extend_from_slice(&unhex(PRIME));
    x_is_the_prime.extend_from_slice(&generator[33..]);
    let mut zeros = vec![0; 65];
    zeros[0] = 0x04;
    vec![
        (vec![], length(0)),
        (vec![0x00], length(1)),
        (
            ProjectivePoint::GENERATOR
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
            length(33),
        ),
        (generator[..64].to_vec(), length(64)),
        ([&generator[..], &[0]].concat(), length(66)),
        (with_tag(0x00), Error::InvalidPoint),
        (with_tag(0x02), Error::InvalidPoint),
        (with_tag(0x03), Error::InvalidPoint),
        (with_tag(0x05), Error::InvalidPoint),
        (with_tag(0x06), Error::InvalidPoint),
        (with_tag(0x07), Error::InvalidPoint),
        (off_curve, Error::InvalidPoint),
        (x_is_the_prime, Error::InvalidPoint),
        (zeros, Error::InvalidPoint),
    ]
}

#[test]
fn a_share_that_is_not_a_point_of_the_group_is_refused() {
    for (bytes, error) in malformed_shares() {
        assert_eq!(
            ShareP::<P256Sha256>::from_bytes(&bytes),
            Err(error),
            "{bytes:02x?}"
        );
        assert_eq!(
            ShareV::<P256Sha256>::from_bytes(&bytes),
            Err(error),
            "{bytes:02x?}"
        );
        assert_eq!(
            ShareP::<P256Sha512>::from_bytes(&bytes),
            Err(error),
            "{bytes:02x?}"
        );
    }
    let generator = uncompressed(&ProjectivePoint::GENERATOR);
    assert!(ShareP::<P256Sha256>::from_bytes(&generator).is_ok());
}

#[test]
fn a_share_that_cancels_the_password_mask_is_refused() {
    let mut rng = StdRng::seed_from_u64(5);
    let secret = secret_with_w0_of_5();
    let five = Scalar::from(5u64);

    // The verifier's `w0*N` leaves the prover's `Y - w0*N` the identity.
    let w0_n = ShareV::from_bytes(&uncompressed(&(point(N) * five))).unwrap();
    let (prover, _) = Prover::start(&secret, &Context::default(), &mut rng);
    assert_eq!(prover.receive(&w0_n).err(), Some(Error::DegenerateShare));

    // The prover's `w0*M` leaves the verifier's `X - w0*M` the identity.
    let w0_m = ShareP::from_bytes(&uncompressed(&(point(M) * five))).unwrap();
    let (verifier, _) = Verifier::start(&secret.verifier_record(), &Context::default(), &mut rng);
    assert_eq!(verifier.receive(&w0_m).err(), Some(Error::DegenerateShare));

    // The masks of another `w0` are only shares from the wrong password.
    let six = Scalar::from(6u64);
    let w0_n = ShareV::from_bytes(&uncompressed(&(point(N) * six))).unwrap();
    let (prover, _) = Prover::start(&secret, &Context::default(), &mut rng);
    assert!(prover.receive(&w0_n).is_ok());
}

#[test]
fn a_confirmation_of_the_wrong_length_is_refused() {
    for length in [0, 31, 33, 64] {
        let expected = Some(Error::Length {
            expected: 32,
            actual: length,
        });
        let bytes = vec![0; length];
        assert_eq!(ConfirmP::<P256Sha256>::from_bytes(&bytes).err(), expected);
        assert_eq!(ConfirmV::<P256Sha256>::from_bytes(&bytes).err(), expected);
    }
    assert_eq!(
        ConfirmV::<P256Sha512>::from_bytes(&[0; 32]),
        Err(Error::Length {
            expected: 64,
            actual: 32
        })
    );
}

#[test]
fn a_confirmation_off_by_one_bit_is_refused_by_every_state() {
    let mut rng = StdRng::seed_from_u64(6);
    let secret = secret_with_w0_of_5();
    let flipped = |bytes: &[u8], at: usize| {
        let mut bytes = bytes.to_vec();
        bytes[at / 8] ^= 1 << (at % 8);
        bytes
    };
    for at in [0, 7, 100, 255] {
        let (prover, share_p) = Prover::start(&secret, &Context::default(), &mut rng);
        let (verifier, share_v) =
            Verifier::start(&secret.verifier_record(), &Context::default(), &mut rng);
        let (verifier, confirm_v) = verifier.receive(&share_p).unwrap();
        let bad_v = ConfirmV::from_bytes(&flipped(confirm_v.as_ref(), at)).unwrap();
        let prover = prover.receive(&share_v).unwrap();
        let (confirm_p, prover) = prover.confirm_first();
        assert_eq!(prover.finish(&bad_v).err(), Some(Error::ConfirmationFailed));
        let bad_p = ConfirmP::from_bytes(&flipped(confirm_p.as_ref(), at)).unwrap();
        assert_eq!(
            verifier.finish(&bad_p).err(),
            Some(Error::ConfirmationFailed)
        );

        let (prover, share_p) = Prover::start(&secret, &Context::default(), &mut rng);
        let (verifier, share_v) =
            Verifier::start(&secret.verifier_record(), &Context::default(), &mut rng);
        let (_, confirm_v) = verifier.receive(&share_p).unwrap();
        let bad_v = ConfirmV::from_bytes(&flipped(confirm_v.as_ref(), at)).unwrap();
        let prover = prover.receive(&share_v).unwrap();
        assert_eq!(prover.finish(&bad_v).err(), Some(Error::ConfirmationFailed));
    }
}

#[test]
fn a_malformed_record_is_refused() {
    let record = secret_with_w0_of_5().verifier_record().to_bytes();
    let length = |actual| Error::Length {
        expected: 97,
        actual,
    };
    for actual in [0, 32, 96, 98] {
        let mut bytes = record.to_vec();
        bytes.resize(actual, 0);
        assert_eq!(
            VerifierRecord::<P256Sha256>::from_bytes(&bytes).err(),
            Some(length(actual))
        );
    }
    let mut w0_is_the_order = record.to_vec();
    w0_is_the_order[..32].copy_from_slice(&unhex(ORDER));
    assert_eq!(
        VerifierRecord::<P256Sha256>::from_bytes(&w0_is_the_order).err(),
        Some(Error::InvalidScalar)
    );
    let mut l_off_curve = record.to_vec();
    l_off_curve[96] ^= 1;
    assert_eq!(
        VerifierRecord::<P256Sha256>::from_bytes(&l_off_curve).err(),
        Some(Error::InvalidPoint)
    );
    let mut l_compressed_tag = record.to_vec();
    l_compressed_tag[32] = 0x02;
    assert_eq!(
        VerifierRecord::<P256Sha256>::from_bytes(&l_compressed_tag).err(),
        Some(Error::InvalidPoint)
    );
    assert_eq!(&record[..32], &[[0; 31].as_slice(), &[5]].concat()[..]);
}

#[test]
fn a_pbkdf_output_of_an_unusable_length_is_refused() {
    for length in [0, 2, 78, 79, 81, 129, 130, 256] {
        assert_eq!(
            ProverSecret::<P256Sha256>::from_pbkdf_output(&vec![1; length]).err(),
            Some(Error::PbkdfOutputLength { actual: length }),
            "{length} bytes"
        );
    }
    for length in [80, 82, 100, 128] {
        assert!(
            ProverSecret::<P256Sha512>::from_pbkdf_output(&vec![1; length]).is_ok(),
            "{length} bytes"
        );
    }
}

#[test]
fn every_error_says_what_went_wrong() {
    let shown = [
        Error::Length {
            expected: 65,
            actual: 64,
        },
        Error::PbkdfOutputLength { actual: 79 },
        Error::InvalidPoint,
        Error::InvalidScalar,
        Error::DegenerateShare,
        Error::ConfirmationFailed,
    ]
    .map(|error| error.to_string());
    assert_eq!(
        shown,
        [
            "expected 65 bytes, got 64",
            "a PBKDF output of 79 bytes is not two equal halves of a usable length",
            "not an encoded point of the group",
            "a scalar not below the group order",
            "a share that cancels the password's mask",
            "the key confirmation does not match",
        ]
    );
}
