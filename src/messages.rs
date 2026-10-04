//! The messages of a run and the key it ends with.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::Error;
use crate::suite::sealed::{Bytes as _, Group as _};
use crate::suite::{Bytes, Group, Point, Suite};

/// The bytes, unless their length is not the suite's.
fn sized<B: Bytes>(bytes: &[u8]) -> Result<B, Error> {
    B::try_from(bytes).map_err(|_| Error::Length {
        expected: size_of::<B>(),
        actual: bytes.len(),
    })
}

/// A share's point.
pub(crate) trait SharePoint<S: Suite> {
    /// The point, validated when the share was parsed or computed.
    fn point(&self) -> Result<Point<S>, Error>;
}

macro_rules! share {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// Parsing checks the length, the uncompressed SEC1 form, that the
        /// point is on the curve and that it is not the identity, so a value
        /// of this type is always an element of the prime-order group.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub struct $name<S: Suite>(S::Share);

        impl<S: Suite> $name<S> {
            /// Parses a share received from the peer.
            ///
            /// # Errors
            ///
            /// [`Error::Length`] for the wrong length, and
            /// [`Error::InvalidPoint`] for anything but a point of the group
            /// other than the identity.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                let share: S::Share = sized(bytes)?;
                Group::<S>::decode(share.as_ref()).ok_or(Error::InvalidPoint)?;
                Ok(Self(share))
            }

            /// The share as it travels.
            #[must_use]
            pub fn as_bytes(&self) -> &S::Share {
                &self.0
            }

            /// The share from a point computed here.
            pub(crate) fn from_point(point: &Point<S>) -> Result<Self, Error> {
                let mut share = S::Share::zeroed();
                Group::<S>::encode(point, share.as_mut()).ok_or(Error::DegenerateShare)?;
                Ok(Self(share))
            }
        }

        impl<S: Suite> SharePoint<S> for $name<S> {
            fn point(&self) -> Result<Point<S>, Error> {
                Group::<S>::decode(self.0.as_ref()).ok_or(Error::InvalidPoint)
            }
        }

        impl<S: Suite> AsRef<[u8]> for $name<S> {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
    };
}

share!(
    /// `shareP`, the prover's share: `X = x*P + w0*M`.
    ShareP
);
share!(
    /// `shareV`, the verifier's share: `Y = y*P + w0*N`.
    ShareV
);

macro_rules! confirmation {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub struct $name<S: Suite>(S::Confirmation);

        impl<S: Suite> $name<S> {
            /// Parses a confirmation received from the peer. Whether it
            /// matches is checked by the session that expects it, in
            /// constant time.
            ///
            /// # Errors
            ///
            /// [`Error::Length`] for the wrong length.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                sized(bytes).map(Self)
            }

            /// The confirmation as it travels.
            #[must_use]
            pub fn as_bytes(&self) -> &S::Confirmation {
                &self.0
            }

            pub(crate) fn new(tag: S::Confirmation) -> Self {
                Self(tag)
            }

            /// Whether this is `expected`, compared in constant time.
            pub(crate) fn check(&self, expected: &S::Confirmation) -> Result<(), Error> {
                if bool::from(self.0.as_ref().ct_eq(expected.as_ref())) {
                    Ok(())
                } else {
                    Err(Error::ConfirmationFailed)
                }
            }
        }

        impl<S: Suite> AsRef<[u8]> for $name<S> {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
    };
}

confirmation!(
    /// `confirmP`, the prover's key confirmation: `MAC(K_confirmP, shareV)`.
    ConfirmP
);
confirmation!(
    /// `confirmV`, the verifier's key confirmation: `MAC(K_confirmV, shareP)`.
    ConfirmV
);

/// `K_shared`, the key both sides hold once the run is confirmed.
///
/// Derive the application's keys from it (for example with HKDF) rather
/// than using it directly. It is zeroized on drop, and its `Debug` shows
/// nothing.
pub struct SharedKey<S: Suite>(S::SharedKey);

impl<S: Suite> SharedKey<S> {
    pub(crate) fn new(key: S::SharedKey) -> Self {
        Self(key)
    }

    /// The key's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &S::SharedKey {
        &self.0
    }
}

impl<S: Suite> Drop for SharedKey<S> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<S: Suite> fmt::Debug for SharedKey<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedKey(..)")
    }
}
