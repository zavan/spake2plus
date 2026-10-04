//! The P-256 group: its constants, encodings and reductions.

use core::fmt::Write as _;
use std::string::String;

use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{NistP256, ProjectivePoint, PublicKey, Scalar};

use super::{Replay, unhex};
use crate::suite::sealed::Group;

/// The group order.
const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// `scalar`, big-endian, as hex.
fn hex(scalar: &Scalar) -> String {
    let mut hex = String::new();
    for byte in NistP256::scalar_to_bytes(scalar) {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

#[test]
fn m_and_n_are_the_rfcs_compressed_points() {
    for (constant, compressed) in [
        (
            NistP256::M,
            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f",
        ),
        (
            NistP256::N,
            "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49",
        ),
    ] {
        let point = PublicKey::from_sec1_bytes(&unhex(compressed))
            .unwrap()
            .to_projective();
        assert_eq!(NistP256::fixed(constant), point);
        assert_eq!(point.to_sec1_point(false).as_bytes(), constant);
    }
}

#[test]
fn only_uncompressed_points_of_the_curve_decode() {
    let generator = ProjectivePoint::GENERATOR.to_sec1_point(false);
    let generator = generator.as_bytes();
    assert_eq!(
        NistP256::decode(generator),
        Some(ProjectivePoint::GENERATOR)
    );

    let compressed = ProjectivePoint::GENERATOR.to_sec1_point(true);
    let mut hybrid = generator.to_vec();
    hybrid[0] = 0x06 | (generator[64] & 1);
    let mut off_curve = generator.to_vec();
    off_curve[64] ^= 1;
    let mut zeros = [0; 65];
    zeros[0] = 0x04;
    for refused in [
        compressed.as_bytes(),
        &hybrid,
        &off_curve,
        &zeros,
        &[0x00],
        &generator[..64],
        &[],
    ] {
        assert_eq!(NistP256::decode(refused), None, "{refused:02x?}");
    }
}

#[test]
fn the_identity_has_no_encoding_and_lengths_must_match() {
    let mut out = [0; 65];
    assert_eq!(NistP256::encode(&ProjectivePoint::IDENTITY, &mut out), None);
    assert_eq!(
        NistP256::encode(&ProjectivePoint::GENERATOR, &mut [0; 64]),
        None
    );
    assert_eq!(
        NistP256::encode(&ProjectivePoint::GENERATOR, &mut out),
        Some(())
    );
    assert_eq!(
        &out[..],
        ProjectivePoint::GENERATOR.to_sec1_point(false).as_bytes()
    );
}

#[test]
fn scalars_reduce_modulo_the_order_from_any_length_up_to_64_bytes() {
    let reduce = |hex: &str| NistP256::reduce(&unhex(hex)).unwrap();
    assert_eq!(reduce("05"), Scalar::from(5u64));
    assert_eq!(reduce(ORDER), Scalar::ZERO);
    assert_eq!(
        reduce("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556"),
        Scalar::from(5u64),
        "the order plus 5"
    );
    // 2^256 and 2^320 - 1 and 2^512 - 1, reduced with Python's integers.
    assert_eq!(
        hex(&reduce(&std::format!("01{}", "00".repeat(32)))),
        "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf"
    );
    assert_eq!(
        hex(&reduce(&"ff".repeat(40))),
        "fffffffe00000001431905529c0166cd22159165b6faae70f756a571fc632550"
    );
    assert_eq!(
        hex(&reduce(&"ff".repeat(64))),
        "66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea1"
    );
    assert_eq!(NistP256::reduce(&[0xff; 65]), None);
}

#[test]
fn a_random_scalar_reduces_64_bytes_of_the_generator() {
    let mut replay = Replay::scalar(ORDER);
    replay.0.push(0xaa);
    assert_eq!(NistP256::random(&mut replay), Scalar::ZERO);
    assert_eq!(replay.0, [0xaa], "exactly 64 bytes were taken");
}

#[test]
fn a_record_scalar_must_be_below_the_order() {
    assert_eq!(
        NistP256::scalar_from_bytes(&unhex(ORDER)).map(|scalar| hex(&scalar)),
        None
    );
    let below = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";
    assert_eq!(
        NistP256::scalar_from_bytes(&unhex(below)).map(|scalar| hex(&scalar)),
        Some(below.into())
    );
    assert!(NistP256::scalar_from_bytes(&[1; 31]).is_none());
    assert!(NistP256::scalar_from_bytes(&[1; 33]).is_none());
}
