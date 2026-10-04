//! The transcript and the key schedule (RFC 9383, sections 3.3 and 3.4).

use hkdf::Hkdf;
use hmac::Hmac;
use hmac::digest::{Digest, KeyInit, Mac, Output};
use p256::elliptic_curve::Group as _;
use zeroize::{Zeroize, Zeroizing};

use crate::messages::SharePoint;
use crate::suite::sealed::{Bytes as _, Group as _};
use crate::suite::{ConfirmationKeys, Group, Hash, Point, Scalar, Suite};
use crate::{Context, Error, ShareP, ShareV};

/// `Z` and `V`, zeroized on drop.
pub(crate) type SharedPoints<S> = (Zeroizing<Point<S>>, Zeroizing<Point<S>>);

/// The peer's share with the password's mask taken out: `X - w0*M` or
/// `Y - w0*N`.
///
/// # Errors
///
/// [`Error::DegenerateShare`] when that leaves the identity: the share was
/// the mask itself, and `Z` and `V` would hold nothing secret.
pub(crate) fn unmask<S: Suite>(
    share: &impl SharePoint<S>,
    mask: &[u8],
    w0: &Scalar<S>,
) -> Result<Zeroizing<Point<S>>, Error> {
    let unmasked = Zeroizing::new(share.point()? - Group::<S>::fixed(mask) * *w0);
    if bool::from(unmasked.is_identity()) {
        return Err(Error::DegenerateShare);
    }
    Ok(unmasked)
}

/// The transcript `TT`, hashed as it is written: its parts known before the
/// shares are, so a session holds a hash state rather than its inputs.
#[derive(Clone)]
pub(crate) struct Transcript<S: Suite>(Hash<S>);

impl<S: Suite> Transcript<S> {
    /// The context, the identities and `M` and `N`.
    pub(crate) fn new(context: &Context<'_>) -> Self {
        let mut transcript = Self(Hash::<S>::new());
        for part in [
            context.context,
            context.prover_id,
            context.verifier_id,
            Group::<S>::M,
            Group::<S>::N,
        ] {
            transcript.write(part);
        }
        transcript
    }

    /// `len(part) || part`, the length as eight bytes, little-endian.
    fn write(&mut self, part: &[u8]) {
        self.0.update((part.len() as u64).to_le_bytes());
        self.0.update(part);
    }

    /// The rest of the transcript, hashed into `K_main`, then the key
    /// schedule and both confirmations.
    pub(crate) fn finish(
        self,
        share_p: &ShareP<S>,
        share_v: &ShareV<S>,
        shared: (&Point<S>, &Point<S>),
        w0: &Scalar<S>,
    ) -> Result<Keys<S>, Error> {
        let mut main = self.main(share_p, share_v, shared, w0)?;
        let keys = Keys::derive(&main, share_p, share_v);
        AsMut::<[u8]>::as_mut(&mut main).zeroize();
        keys
    }

    /// `K_main = Hash(TT)`, with the rest of the transcript: the shares,
    /// `Z`, `V` and `w0`.
    pub(crate) fn main(
        mut self,
        share_p: &ShareP<S>,
        share_v: &ShareV<S>,
        (z, v): (&Point<S>, &Point<S>),
        w0: &Scalar<S>,
    ) -> Result<Output<Hash<S>>, Error> {
        let mut encoded = Zeroizing::new([S::Share::zeroed(); 2]);
        let [z_bytes, v_bytes] = &mut *encoded;
        Group::<S>::encode(z, z_bytes.as_mut()).ok_or(Error::DegenerateShare)?;
        Group::<S>::encode(v, v_bytes.as_mut()).ok_or(Error::DegenerateShare)?;
        let w0 = Zeroizing::new(Group::<S>::scalar_to_bytes(w0));
        for part in [
            share_p.as_ref(),
            share_v.as_ref(),
            z_bytes.as_ref(),
            v_bytes.as_ref(),
            w0.as_ref(),
        ] {
            self.write(part);
        }
        Ok(self.0.finalize())
    }
}

/// What the key schedule gives a session: both confirmations and the
/// shared key. Zeroized on drop.
pub(crate) struct Keys<S: Suite> {
    /// `confirmP = MAC(K_confirmP, shareV)`.
    pub(crate) confirm_p: S::Confirmation,
    /// `confirmV = MAC(K_confirmV, shareP)`.
    pub(crate) confirm_v: S::Confirmation,
    /// `K_shared`.
    pub(crate) shared: S::SharedKey,
}

impl<S: Suite> Keys<S> {
    /// The confirmations, `MAC(K_confirmP, shareV)` and
    /// `MAC(K_confirmV, shareP)`, and `K_shared`, from `K_main`.
    fn derive(main: &[u8], share_p: &ShareP<S>, share_v: &ShareV<S>) -> Result<Self, Error> {
        let mut keys = Self {
            confirm_p: S::Confirmation::zeroed(),
            confirm_v: S::Confirmation::zeroed(),
            shared: S::SharedKey::zeroed(),
        };
        let confirmation = expand::<S>(main, &mut keys.shared)?;
        let (prover_key, verifier_key) =
            confirmation.as_ref().split_at(size_of::<S::Confirmation>());
        mac::<S>(prover_key, share_v.as_ref(), &mut keys.confirm_p);
        mac::<S>(verifier_key, share_p.as_ref(), &mut keys.confirm_v);
        Ok(keys)
    }
}

impl<S: Suite> Drop for Keys<S> {
    fn drop(&mut self) {
        self.confirm_p.zeroize();
        self.confirm_v.zeroize();
        self.shared.zeroize();
    }
}

/// `K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")`,
/// returned, and `K_shared = KDF(nil, K_main, "SharedKey")`, into `shared`.
pub(crate) fn expand<S: Suite>(
    main: &[u8],
    shared: &mut S::SharedKey,
) -> Result<Zeroizing<ConfirmationKeys<S>>, Error> {
    let kdf = Hkdf::<Hash<S>>::new(None, main);
    let mut confirmation = Zeroizing::new(ConfirmationKeys::<S>::zeroed());
    // Both lengths are fixed by the suite and far under HKDF's limit of 255
    // digests, so neither expansion fails.
    for (info, out) in [
        (&b"ConfirmationKeys"[..], confirmation.as_mut()),
        (b"SharedKey", shared.as_mut()),
    ] {
        kdf.expand(info, out).map_err(|_| Error::Length {
            expected: 255 * <Hash<S> as Digest>::output_size(),
            actual: out.len(),
        })?;
    }
    Ok(confirmation)
}

/// `MAC(key, data)` into `tag`: HMAC with the suite's hash.
fn mac<S: Suite>(key: &[u8], data: &[u8], tag: &mut S::Confirmation) {
    // HMAC takes a key of any length.
    if let Ok(mac) = <Hmac<Hash<S>> as KeyInit>::new_from_slice(key) {
        tag.as_mut()
            .copy_from_slice(&mac.chain_update(data).finalize().into_bytes());
    }
}
