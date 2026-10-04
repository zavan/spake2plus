//! Shares that would leave nothing secret: the peer's share is refused as
//! soon as it cancels the password's mask, before `Z` and `V` reach the
//! transcript, and a zero ephemeral scalar (a broken random number
//! generator) ends the run rather than hashing the identity.

use super::vectors::P256_SHA256;
use super::{Replay, unhex};
use crate::suite::sealed::{Bytes as _, Group as _};
use crate::suite::{Group, Point};
use crate::{Context, Error, P256Sha256, Prover, ProverSecret, ShareP, ShareV, Suite, Verifier};

type S = P256Sha256;

/// `w0` times one of the fixed points, as a share's bytes.
fn mask(fixed: &[u8], secret: &ProverSecret<S>) -> <S as Suite>::Share {
    let point: Point<S> = Group::<S>::fixed(fixed) * *secret.w0();
    let mut bytes = <S as Suite>::Share::zeroed();
    Group::<S>::encode(&point, bytes.as_mut()).unwrap();
    bytes
}

/// The RFC vector's `w0` and `w1`.
fn secret() -> ProverSecret<S> {
    let mut output = std::vec![0; 8];
    output.extend_from_slice(&unhex(P256_SHA256.w0));
    output.extend_from_slice(&[0; 8]);
    output.extend_from_slice(&unhex(P256_SHA256.w1));
    ProverSecret::<S>::from_pbkdf_output(&output).unwrap()
}

#[test]
fn shared_points_refuse_the_mask_itself() {
    let secret = secret();
    let context = Context::default();

    let (prover, _) = Prover::start(&secret, &context, &mut Replay::scalar(P256_SHA256.x));
    let w0_n = ShareV::from_bytes(&mask(Group::<S>::N, &secret)).unwrap();
    assert_eq!(prover.shared(&w0_n).err(), Some(Error::DegenerateShare));

    let (verifier, _) = Verifier::start(
        &secret.verifier_record(),
        &context,
        &mut Replay::scalar(P256_SHA256.y),
    );
    let w0_m = ShareP::from_bytes(&mask(Group::<S>::M, &secret)).unwrap();
    assert_eq!(verifier.shared(&w0_m).err(), Some(Error::DegenerateShare));
}

#[test]
fn a_zero_ephemeral_scalar_ends_the_run() {
    let secret = secret();
    let context = Context::default();
    let record = secret.verifier_record();
    let zero = || Replay(std::vec![0; 64]);

    // `x = 0`: the prover's `Z` is the identity.
    let (prover, _) = Prover::start(&secret, &context, &mut zero());
    let (_, share_v) = Verifier::start(&record, &context, &mut Replay::scalar(P256_SHA256.y));
    assert_eq!(prover.receive(&share_v).err(), Some(Error::DegenerateShare));

    // `y = 0`: the verifier's `Z` and `V` are the identity.
    let (_, share_p) = Prover::start(&secret, &context, &mut Replay::scalar(P256_SHA256.x));
    let (verifier, _) = Verifier::start(&record, &context, &mut zero());
    assert_eq!(
        verifier.receive(&share_p).err(),
        Some(Error::DegenerateShare)
    );
}
