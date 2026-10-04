//! The verifier's side of a run: the server, which holds the record.

use core::fmt;

use p256::elliptic_curve::Group as _;
use p256::elliptic_curve::rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::schedule::{Keys, SharedPoints, Transcript, unmask};
use crate::suite::sealed::Group as _;
use crate::suite::{Group, Point, Scalar, Suite};
use crate::{ConfirmP, ConfirmV, Context, Error, ShareP, ShareV, SharedKey, VerifierRecord};

/// The verifier with its share, `shareV`, waiting for `shareP`.
///
/// `shareV` does not depend on `shareP`, so it may be sent before or after
/// `shareP` arrives. Each step consumes the session, so it runs once, in
/// order, and the shared key appears only once the prover's confirmation
/// has been checked. It is zeroized on drop, and its `Debug` shows nothing.
pub struct Verifier<S: Suite> {
    record: VerifierRecord<S>,
    y: Scalar<S>,
    share: ShareV<S>,
    transcript: Transcript<S>,
}

impl<S: Suite> Verifier<S> {
    /// Starts a run: picks `y` and computes `shareV = y*P + w0*N`, to send
    /// to the prover.
    pub fn start<R: CryptoRng + ?Sized>(
        record: &VerifierRecord<S>,
        context: &Context<'_>,
        rng: &mut R,
    ) -> (Self, ShareV<S>) {
        let mask = Zeroizing::new(Group::<S>::fixed(Group::<S>::N) * *record.w0());
        loop {
            let mut y = Group::<S>::random(rng);
            // The identity only when `y*P = -w0*N`, which a random `y`
            // hits with probability 2^-256; then pick another.
            if let Ok(share) = ShareV::from_point(&(Point::<S>::generator() * y + *mask)) {
                let verifier = Self {
                    record: record.clone(),
                    y,
                    share,
                    transcript: Transcript::new(context),
                };
                return (verifier, share);
            }
            y.zeroize();
        }
    }

    /// Takes the prover's share and derives the keys, through `Z` and `V`,
    /// the transcript and the key schedule. Gives `confirmV`, to send to
    /// the prover.
    ///
    /// # Errors
    ///
    /// [`Error::DegenerateShare`] when `shareP` is `w0*M`, which would
    /// leave nothing secret in the key.
    pub fn receive(
        self,
        share_p: &ShareP<S>,
    ) -> Result<(VerifierConfirming<S>, ConfirmV<S>), Error> {
        let (z, v) = self.shared(share_p)?;
        let keys =
            self.transcript
                .clone()
                .finish(share_p, &self.share, (&z, &v), self.record.w0())?;
        let confirm_v = ConfirmV::new(keys.confirm_v);
        Ok((VerifierConfirming { keys }, confirm_v))
    }

    /// `Z = y*(X - w0*M)` and `V = y*L` (the cofactor is 1).
    pub(crate) fn shared(&self, share_p: &ShareP<S>) -> Result<SharedPoints<S>, Error> {
        let unmasked = unmask::<S>(share_p, Group::<S>::M, self.record.w0())?;
        Ok((
            Zeroizing::new(*unmasked * self.y),
            Zeroizing::new(*self.record.l() * self.y),
        ))
    }
}

impl<S: Suite> Drop for Verifier<S> {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl<S: Suite> fmt::Debug for Verifier<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Verifier(..)")
    }
}

/// The verifier that has sent `confirmV`, or holds it ready, waiting for
/// `confirmP`.
///
/// It is zeroized on drop, and its `Debug` shows nothing.
pub struct VerifierConfirming<S: Suite> {
    keys: Keys<S>,
}

impl<S: Suite> VerifierConfirming<S> {
    /// Checks the prover's confirmation, in constant time, and gives the
    /// shared key. Send no application data before this succeeds.
    ///
    /// # Errors
    ///
    /// [`Error::ConfirmationFailed`] when `confirmP` does not match: the
    /// prover holds another password, context or identity, or the messages
    /// were altered.
    pub fn finish(self, confirm_p: &ConfirmP<S>) -> Result<SharedKey<S>, Error> {
        confirm_p.check(&self.keys.confirm_p)?;
        Ok(SharedKey::new(self.keys.shared))
    }
}

impl<S: Suite> fmt::Debug for VerifierConfirming<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifierConfirming(..)")
    }
}
