use super::{ExposeSecret, ExposeSecretMut};

/// Extension trait for ergonomic read-only secret exposure on concrete types.
///
/// Import this to add a `.expose_secret()` method to secret wrappers.
/// This delegates to the core [`ExposeSecret::expose_secret`] trait method.
///
/// # Examples
///
/// ```
/// use secure_gate::{Fixed, ExposeSecretExt};
///
/// let secret = Fixed::new([1u8, 2, 3]);
/// let exposed = secret.expose_secret();
/// assert_eq!(exposed.len(), 3);
/// ```
pub trait ExposeSecretExt: ExposeSecret {
    /// Exposes the secret for read-only access (delegates to [`ExposeSecret::expose_secret`]).
    #[inline(always)]
    fn expose_secret(&self) -> &Self::Inner {
        <Self as ExposeSecret>::expose_secret(self)
    }
}

// Blanket impl for all types satisfying ExposeSecret
impl<T: ExposeSecret + ?Sized> ExposeSecretExt for T {}

/// Extension trait for ergonomic mutable secret exposure on concrete types.
///
/// Import this to add a `.expose_secret_mut()` method to mutable secret wrappers.
/// This delegates to the core [`ExposeSecretMut::expose_secret_mut`] trait method.
///
/// # Examples
///
/// ```
/// use secure_gate::{Fixed, ExposeSecretMutExt};
///
/// let mut secret = Fixed::new([1u8, 2, 3]);
/// let exposed = secret.expose_secret_mut();
/// exposed[0] = 42;
/// ```
pub trait ExposeSecretMutExt: ExposeSecretMut {
    /// Exposes the secret for mutable access (delegates to [`ExposeSecretMut::expose_secret_mut`]).
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut Self::Inner {
        <Self as ExposeSecretMut>::expose_secret_mut(self)
    }
}

// Blanket impl for all types satisfying ExposeSecretMut
impl<T: ExposeSecretMut + ?Sized> ExposeSecretMutExt for T {}
