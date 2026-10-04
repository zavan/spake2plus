//! The ciphersuites: a group, a hash, a KDF and a MAC (RFC 9383, section 4).
//!
//! [`Suite`] is sealed: the crate implements it for the suites it supports,
//! so adding a suite, or an item to the trait, never breaks a caller.

use core::fmt::Debug;

use p256::elliptic_curve::ff::{FromUniformBytes, PrimeField};
use p256::elliptic_curve::rand_core::CryptoRng;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::{Group as _, PublicKey};
use p256::{NistP256, ProjectivePoint};
use zeroize::Zeroize;

/// A SPAKE2+ ciphersuite from RFC 9383, section 4.
///
/// Its associated types are the fixed-size byte arrays of its messages, so
/// for [`P256Sha256`] a share is a `[u8; 65]` and a confirmation a
/// `[u8; 32]`.
pub trait Suite: sealed::Suite + Copy + Debug + Eq + core::hash::Hash + Send + Sync {
    /// The ciphersuite's name in RFC 9383, for example
    /// `P256-SHA256-HKDF-SHA256-HMAC-SHA256`.
    const NAME: &'static str;

    /// The fewest bytes of PBKDF output that registration takes:
    /// `w0s || w1s`, each half `ceil(log2(p)) + 64` bits long, so that
    /// reducing it modulo the group order `p` carries a bias of at most
    /// 2^-64 (RFC 9383, section 3.2).
    const MIN_PBKDF_OUTPUT_LEN: usize;

    /// The most bytes of PBKDF output that registration takes.
    const MAX_PBKDF_OUTPUT_LEN: usize;

    /// A share (`shareP` or `shareV`): a point of the group, SEC1
    /// uncompressed.
    type Share: Bytes;

    /// A key confirmation message (`confirmP` or `confirmV`): one MAC tag.
    type Confirmation: Bytes;

    /// The shared key, `K_shared`.
    type SharedKey: Bytes;

    /// A verifier's registration record: `w0`, big-endian, then `L`, SEC1
    /// uncompressed.
    type Record: Bytes;
}

/// A fixed-size byte array, such as a message of a [`Suite`].
///
/// Sealed: implemented for `[u8; N]` only.
pub trait Bytes:
    sealed::Bytes
    + Copy
    + Debug
    + Eq
    + core::hash::Hash
    + Send
    + Sync
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Zeroize
    + for<'a> TryFrom<&'a [u8]>
    + 'static
{
}

impl<const N: usize> Bytes for [u8; N] {}

/// P-256 with SHA-256, HKDF-SHA256 and HMAC-SHA256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum P256Sha256 {}

/// P-256 with SHA-512, HKDF-SHA512 and HMAC-SHA512.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum P256Sha512 {}

/// A P-256 point, SEC1 uncompressed.
const P256_POINT_LEN: usize = 65;
/// A P-256 scalar, big-endian.
const P256_SCALAR_LEN: usize = 32;
/// Half of the PBKDF output, at least: 256 bits for the order and 64 more.
const P256_MIN_HALF: usize = 40;
/// Half of the PBKDF output, at most: what one wide reduction takes.
const P256_MAX_HALF: usize = 64;

impl Suite for P256Sha256 {
    const NAME: &'static str = "P256-SHA256-HKDF-SHA256-HMAC-SHA256";
    const MIN_PBKDF_OUTPUT_LEN: usize = 2 * P256_MIN_HALF;
    const MAX_PBKDF_OUTPUT_LEN: usize = 2 * P256_MAX_HALF;
    type Share = [u8; P256_POINT_LEN];
    type Confirmation = [u8; 32];
    type SharedKey = [u8; 32];
    type Record = [u8; P256_SCALAR_LEN + P256_POINT_LEN];
}

impl sealed::Suite for P256Sha256 {
    type Group = NistP256;
    type Hash = sha2::Sha256;
    type ConfirmationKeys = [u8; 64];
}

impl Suite for P256Sha512 {
    const NAME: &'static str = "P256-SHA512-HKDF-SHA512-HMAC-SHA512";
    const MIN_PBKDF_OUTPUT_LEN: usize = 2 * P256_MIN_HALF;
    const MAX_PBKDF_OUTPUT_LEN: usize = 2 * P256_MAX_HALF;
    type Share = [u8; P256_POINT_LEN];
    type Confirmation = [u8; 64];
    type SharedKey = [u8; 64];
    type Record = [u8; P256_SCALAR_LEN + P256_POINT_LEN];
}

impl sealed::Suite for P256Sha512 {
    type Group = NistP256;
    type Hash = sha2::Sha512;
    type ConfirmationKeys = [u8; 128];
}

/// RFC 9383's `M` for P-256 (section 4), uncompressed.
const P256_M: [u8; P256_POINT_LEN] = [
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac,
    0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d,
    0x20,
];

/// RFC 9383's `N` for P-256 (section 4), uncompressed.
const P256_N: [u8; P256_POINT_LEN] = [
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68,
    0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb,
    0xe7,
];

impl sealed::Group for NistP256 {
    type Scalar = p256::Scalar;
    type Point = ProjectivePoint;
    type ScalarBytes = [u8; P256_SCALAR_LEN];
    const M: &'static [u8] = &P256_M;
    const N: &'static [u8] = &P256_N;

    fn decode(bytes: &[u8]) -> Option<Self::Point> {
        // Uncompressed only: `from_sec1_bytes` alone would also take the
        // compressed form and the identity's single byte. It checks the
        // length the tag implies.
        if bytes.first() != Some(&0x04) {
            return None;
        }
        // Refuses points off the curve. P-256 has cofactor 1, so every
        // point of the curve is in the prime-order group.
        PublicKey::<NistP256>::from_sec1_bytes(bytes)
            .ok()
            .map(|key| key.to_projective())
    }

    fn encode(point: &Self::Point, out: &mut [u8]) -> Option<()> {
        if bool::from(point.is_identity()) {
            return None;
        }
        let encoded = point.to_sec1_point(false);
        let encoded = encoded.as_bytes();
        if out.len() != encoded.len() {
            return None;
        }
        out.copy_from_slice(encoded);
        Some(())
    }

    fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self::Scalar {
        let mut wide = [0; P256_MAX_HALF];
        rng.fill_bytes(&mut wide);
        let scalar = p256::Scalar::from_uniform_bytes(&wide);
        wide.zeroize();
        scalar
    }

    fn reduce(bytes: &[u8]) -> Option<Self::Scalar> {
        let mut wide = [0; 2 * P256_SCALAR_LEN];
        let start = wide.len().checked_sub(bytes.len())?;
        wide.get_mut(start..)?.copy_from_slice(bytes);
        let scalar = p256::Scalar::from_uniform_bytes(&wide);
        wide.zeroize();
        Some(scalar)
    }

    fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar> {
        let bytes: [u8; P256_SCALAR_LEN] = bytes.try_into().ok()?;
        p256::Scalar::from_repr(bytes.into()).into()
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        scalar.to_repr().into()
    }
}

pub(crate) mod sealed {
    use core::ops::{Add, Mul, Sub};

    use hmac::digest::Digest;
    use hmac::digest::block_api::EagerHash;
    use p256::elliptic_curve::Group as _;
    use p256::elliptic_curve::rand_core::CryptoRng;
    use zeroize::Zeroize;

    /// The operations behind a [`Suite`](super::Suite).
    pub trait Suite: 'static {
        /// The group.
        type Group: Group;
        /// The hash, which also instantiates HKDF and HMAC.
        type Hash: EagerHash + Digest + Clone;
        /// `K_confirmP || K_confirmV`: two keys of the MAC's tag length.
        type ConfirmationKeys: super::Bytes;
    }

    /// A prime-order group with its SPAKE2+ constants.
    pub trait Group: 'static {
        /// An integer modulo the group order `p`.
        type Scalar: p256::elliptic_curve::ff::Field + Zeroize;
        /// An element of the group.
        type Point: p256::elliptic_curve::Group<Scalar = Self::Scalar>
            + Add<Output = Self::Point>
            + Sub<Output = Self::Point>
            + Mul<Self::Scalar, Output = Self::Point>
            + Zeroize;
        /// An encoded scalar, big-endian, as the transcript takes `w0`.
        type ScalarBytes: super::Bytes;
        /// RFC 9383's `M`, encoded.
        const M: &'static [u8];
        /// RFC 9383's `N`, encoded.
        const N: &'static [u8];

        /// The element `bytes` encode as they travel, unless it is the
        /// identity or not an element of the prime-order group at all.
        fn decode(bytes: &[u8]) -> Option<Self::Point>;

        /// Writes `point`, encoded as it travels, to `out`; none for the
        /// identity, which has no such encoding, or the wrong length.
        fn encode(point: &Self::Point, out: &mut [u8]) -> Option<()>;

        /// A scalar uniform in `[0, p-1]`: the reduction of more random
        /// bytes than the order takes, so its bias is negligible.
        fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self::Scalar;

        /// The big-endian `bytes` reduced modulo `p`; none when there are
        /// more than one reduction takes.
        fn reduce(bytes: &[u8]) -> Option<Self::Scalar>;

        /// The scalar `bytes` encode, unless it is not below `p` or
        /// `bytes` has the wrong length.
        fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar>;

        /// `scalar`, big-endian.
        fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes;

        /// One of the fixed points `M` and `N`.
        fn fixed(bytes: &[u8]) -> Self::Point {
            // Both constants are elements of the group, as a test asserts;
            // the fallback is never taken.
            Self::decode(bytes).unwrap_or_else(Self::Point::identity)
        }
    }

    /// A fixed-size byte array.
    pub trait Bytes {
        /// All zeros.
        fn zeroed() -> Self;
    }

    impl<const N: usize> Bytes for [u8; N] {
        fn zeroed() -> Self {
            [0; N]
        }
    }
}

/// The group of the suite `S`.
pub(crate) type Group<S> = <S as sealed::Suite>::Group;
/// An element of the group of the suite `S`.
pub(crate) type Point<S> = <Group<S> as sealed::Group>::Point;
/// The hash of the suite `S`.
pub(crate) type Hash<S> = <S as sealed::Suite>::Hash;
/// `K_confirmP || K_confirmV` for the suite `S`.
pub(crate) type ConfirmationKeys<S> = <S as sealed::Suite>::ConfirmationKeys;
/// An encoded scalar of the group of the suite `S`.
pub(crate) type ScalarBytes<S> = <Group<S> as sealed::Group>::ScalarBytes;
/// A scalar of the group of the suite `S`.
pub(crate) type Scalar<S> = <Group<S> as sealed::Group>::Scalar;
