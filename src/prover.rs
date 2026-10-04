//! The prover's side of a run: the client, which knows the password.

use core::fmt;

use p256::elliptic_curve::Group as _;
use p256::elliptic_curve::rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::schedule::{Keys, SharedPoints, Transcript, unmask};
use crate::suite::sealed::Group as _;
use crate::suite::{Group, Point, Scalar, Suite};
use crate::{ConfirmP, ConfirmV, Context, Error, ProverSecret, ShareP, ShareV, SharedKey};

/// The prover after sending `shareP`, waiting for `shareV`.
///
/// Each step consumes the session, so it runs once, in order, and the
/// shared key appears only once the verifier's confirmation has been
/// checked. It is zeroized on drop, and its `Debug` shows nothing.
pub struct Prover<S: Suite> {
    secret: ProverSecret<S>,
    x: Scalar<S>,
    share: ShareP<S>,
    transcript: Transcript<S>,
}

impl<S: Suite> Prover<S> {
    /// Starts a run: picks `x` and computes `shareP = x*P + w0*M`, to send
    /// to the verifier.
    pub fn start<R: CryptoRng + ?Sized>(
        secret: &ProverSecret<S>,
        context: &Context<'_>,
        rng: &mut R,
    ) -> (Self, ShareP<S>) {
        let mask = Zeroizing::new(Group::<S>::fixed(Group::<S>::M) * *secret.w0());
        loop {
            let mut x = Group::<S>::random(rng);
            // The identity only when `x*P = -w0*M`, which a random `x`
            // hits with probability 2^-256; then pick another.
            if let Ok(share) = ShareP::from_point(&(Point::<S>::generator() * x + *mask)) {
                let prover = Self {
                    secret: secret.clone(),
                    x,
                    share,
                    transcript: Transcript::new(context),
                };
                return (prover, share);
            }
            x.zeroize();
        }
    }

    /// Takes the verifier's share and derives the keys, through `Z` and
    /// `V`, the transcript and the key schedule.
    ///
    /// # Errors
    ///
    /// [`Error::DegenerateShare`] when `shareV` is `w0*N`, which would
    /// leave nothing secret in the key.
    pub fn receive(self, share_v: &ShareV<S>) -> Result<ProverConfirming<S>, Error> {
        let (z, v) = self.shared(share_v)?;
        let keys =
            self.transcript
                .clone()
                .finish(&self.share, share_v, (&z, &v), self.secret.w0())?;
        Ok(ProverConfirming { keys })
    }

    /// `Z = x*(Y - w0*N)` and `V = w1*(Y - w0*N)` (the cofactor is 1).
    pub(crate) fn shared(&self, share_v: &ShareV<S>) -> Result<SharedPoints<S>, Error> {
        let unmasked = unmask::<S>(share_v, Group::<S>::N, self.secret.w0())?;
        Ok((
            Zeroizing::new(*unmasked * self.x),
            Zeroizing::new(*unmasked * *self.secret.w1()),
        ))
    }
}

impl<S: Suite> Drop for Prover<S> {
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

impl<S: Suite> fmt::Debug for Prover<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Prover(..)")
    }
}

/// The prover holding both confirmations, waiting for `confirmV`.
///
/// It is zeroized on drop, and its `Debug` shows nothing.
pub struct ProverConfirming<S: Suite> {
    keys: Keys<S>,
}

impl<S: Suite> ProverConfirming<S> {
    /// Checks the verifier's confirmation, in constant time, and only then
    /// gives the prover's confirmation, to send, and the shared key: the
    /// order RFC 9383 requires.
    ///
    /// # Errors
    ///
    /// [`Error::ConfirmationFailed`] when `confirmV` does not match: the
    /// verifier holds another password, context or identity, or the
    /// messages were altered. Send nothing more.
    pub fn finish(self, confirm_v: &ConfirmV<S>) -> Result<(ConfirmP<S>, SharedKey<S>), Error> {
        confirm_v.check(&self.keys.confirm_v)?;
        Ok((
            ConfirmP::new(self.keys.confirm_p),
            SharedKey::new(self.keys.shared),
        ))
    }

    /// Gives the prover's confirmation before the verifier's has arrived,
    /// for protocols that send it first (TP-Link's TPAP sends `shareP` and
    /// `confirmP` together after receiving `shareV`). The shared key still
    /// waits for the verifier's confirmation.
    ///
    /// # Security
    ///
    /// This departs from RFC 9383, which has the prover check `confirmV`
    /// before sending `confirmP`. `confirmP` is a MAC keyed by the
    /// password, so an impostor posing as the verifier, who sent its own
    /// `shareV`, can test password guesses against it offline, without
    /// ever proving it knows the record. Use it only when the protocol
    /// forces this order, and with a password hash slow enough to make
    /// those guesses expensive.
    #[must_use]
    pub fn confirm_first(self) -> (ConfirmP<S>, ProverConfirmedFirst<S>) {
        (
            ConfirmP::new(self.keys.confirm_p),
            ProverConfirmedFirst { keys: self.keys },
        )
    }
}

impl<S: Suite> fmt::Debug for ProverConfirming<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProverConfirming(..)")
    }
}

/// The prover that sent `confirmP` first, waiting for `confirmV`; see
/// [`ProverConfirming::confirm_first`].
///
/// It is zeroized on drop, and its `Debug` shows nothing.
pub struct ProverConfirmedFirst<S: Suite> {
    keys: Keys<S>,
}

impl<S: Suite> ProverConfirmedFirst<S> {
    /// Checks the verifier's confirmation, in constant time, and gives the
    /// shared key.
    ///
    /// # Errors
    ///
    /// [`Error::ConfirmationFailed`] when `confirmV` does not match.
    pub fn finish(self, confirm_v: &ConfirmV<S>) -> Result<SharedKey<S>, Error> {
        confirm_v.check(&self.keys.confirm_v)?;
        Ok(SharedKey::new(self.keys.shared))
    }
}

impl<S: Suite> fmt::Debug for ProverConfirmedFirst<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProverConfirmedFirst(..)")
    }
}
