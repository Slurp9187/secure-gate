//! The plumbing behind `sealed_fixed_newtype!` and `sealed_dynamic_newtype!`. Not a public
//! API: everything here is reached only through `secure_gate::__private`.
//!
//! A sealed role has to turn its plain role into the `Fixed` or `Dynamic` inside it, and
//! back, without copying the bytes out by hand. The plain role's macro therefore emits a
//! conversion in each direction ([`FixedRole`], [`DynamicRole`]). Left callable, those
//! conversions would be a way into and out of a role that skips `derive: [FromWrapper]` /
//! `[IntoWrapper]`, which the newtype macros promise is the only way.
//!
//! So each conversion takes a [`RoleToken`] for its own role, and only this module can
//! make one. The sealed macros hold a [`SealedRole`] / [`SealedDynRole`], which is typed
//! by its role: it can be built only from that role and gives back only that role.
//!
//! How far this reaches: it stops safe code. A token is a zero-sized value with a private
//! field, so `unsafe` code can conjure one, as it can conjure anything.

use alloc::sync::Arc;
use core::marker::PhantomData;

use super::{Prekey, SealedDynamic, SealedFixed, SealedPayload};
use crate::{Dynamic, Fixed};

/// Proof that a role conversion was asked for by this crate's sealing code, for role `R`
/// and no other. Cannot be constructed outside this module.
pub struct RoleToken<R>(PhantomData<fn() -> R>);

impl<R> RoleToken<R> {
    #[inline(always)]
    fn new() -> Self {
        Self(PhantomData)
    }
}

/// A `fixed_newtype!` byte role, convertible to and from the `Fixed` it wraps without
/// copying the bytes out by hand. Lets `sealed_fixed_newtype!` seal a role directly.
pub trait FixedRole: Sized {
    /// The wrapped `Fixed<[u8; N]>`.
    type Fixed: SealableFixed;
    /// Unwraps the role.
    fn into_fixed(self, token: RoleToken<Self>) -> Self::Fixed;
    /// Wraps a `Fixed` as the role.
    fn from_fixed(fixed: Self::Fixed, token: RoleToken<Self>) -> Self;
}

/// Maps `Fixed<[u8; N]>` to `SealedFixed<N>` without naming `N`.
pub trait SealableFixed {
    /// `SealedFixed<N>`.
    type Sealed;
}

impl<const N: usize> SealableFixed for Fixed<[u8; N]> {
    type Sealed = SealedFixed<N>;
}

/// The `SealedFixed<N>` a role seals into.
pub type SealedOf<R> = <<R as FixedRole>::Fixed as SealableFixed>::Sealed;

/// A `dynamic_newtype!` `String` or `Vec<u8>` role, convertible to and from the `Dynamic`
/// it wraps by moving the box, never the bytes. Lets `sealed_dynamic_newtype!` seal a role
/// directly.
pub trait DynamicRole: Sized {
    /// `String` or `Vec<u8>`.
    type Payload: SealedPayload;
    /// Unwraps the role.
    fn into_dynamic(self, token: RoleToken<Self>) -> Dynamic<Self::Payload>;
    /// Wraps a `Dynamic` as the role.
    fn from_dynamic(dynamic: Dynamic<Self::Payload>, token: RoleToken<Self>) -> Self;
}

/// A `SealedFixed` that remembers which role it was sealed from. What
/// `sealed_fixed_newtype!` wraps.
pub struct SealedRole<R: FixedRole>(SealedOf<R>);

impl<R, const N: usize> SealedRole<R>
where
    R: FixedRole<Fixed = Fixed<[u8; N]>>,
{
    /// Seals `secret`.
    #[inline]
    pub fn seal(secret: R, prekey: &Arc<Prekey>) -> Self {
        Self(SealedFixed::seal(
            secret.into_fixed(RoleToken::new()),
            prekey,
        ))
    }

    /// Generates the key from the system RNG and seals it. A fresh random key is the role
    /// by construction, so no conversion is involved.
    #[inline]
    pub fn from_random(prekey: &Arc<Prekey>) -> Self {
        Self(SealedFixed::from_random(prekey))
    }

    /// Opens the key as its role for the length of `f`.
    #[inline]
    pub fn with_role<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&R) -> T,
    {
        self.0
            .with_wrapped(|fixed| R::from_fixed(fixed, RoleToken::new()), f)
    }

    /// Opens the key as its role, lets `f` change it, and re-seals under a fresh salt.
    #[inline]
    pub fn with_role_mut<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut R) -> T,
    {
        self.0.with_wrapped_mut(
            |fixed| R::from_fixed(fixed, RoleToken::new()),
            |role: R| role.into_fixed(RoleToken::new()),
            f,
        )
    }

    /// Opens the key as bytes for the length of `f`.
    #[inline]
    pub fn with_secret<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&[u8; N]) -> T,
    {
        self.0.with_secret(f)
    }

    /// Opens the key as bytes, lets `f` change it, and re-seals under a fresh salt.
    #[inline]
    pub fn with_secret_mut<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut [u8; N]) -> T,
    {
        self.0.with_secret_mut(f)
    }

    /// Opens the key back into its plain role.
    #[inline(always)]
    pub fn unseal(self) -> R {
        R::from_fixed(self.0.unseal(), RoleToken::new())
    }

    /// Constant-time comparison of the two plaintexts.
    #[cfg(feature = "ct-eq")]
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        crate::ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

/// A `SealedDynamic` that remembers which role it was sealed from. What
/// `sealed_dynamic_newtype!` wraps.
pub struct SealedDynRole<R: DynamicRole>(SealedDynamic<R::Payload>, PhantomData<fn() -> R>);

impl<R: DynamicRole> SealedDynRole<R> {
    /// Seals `secret`.
    #[inline]
    pub fn seal(secret: R, prekey: &Arc<Prekey>) -> Self {
        Self(
            SealedDynamic::seal(secret.into_dynamic(RoleToken::new()), prekey),
            PhantomData,
        )
    }

    /// Opens the secret as its role for the length of `f`.
    #[inline]
    pub fn with_role<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&R) -> T,
    {
        self.0
            .with_wrapped(|dynamic| R::from_dynamic(dynamic, RoleToken::new()), f)
    }

    /// Opens the secret for the length of `f`.
    #[inline]
    pub fn with_secret<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&R::Payload) -> T,
    {
        self.0.with_secret(f)
    }

    /// Opens the secret, lets `f` change it in place, and re-seals under a fresh salt.
    #[inline]
    pub fn with_secret_mut<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut <R::Payload as SealedPayload>::Mut) -> T,
    {
        self.0.with_secret_mut(f)
    }

    /// Opens the secret back into its plain role.
    #[inline]
    pub fn unseal(self) -> R {
        R::from_dynamic(self.0.unseal(), RoleToken::new())
    }

    /// Constant-time comparison of the two plaintexts.
    #[cfg(feature = "ct-eq")]
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        crate::ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

/// `N`, as for the `SealedFixed` inside.
impl<R, const N: usize> crate::SecretLen for SealedRole<R>
where
    R: FixedRole<Fixed = Fixed<[u8; N]>>,
{
    #[inline(always)]
    fn len(&self) -> usize {
        N
    }
}

/// The secret's length in bytes, as for the `SealedDynamic` inside.
impl<R: DynamicRole> crate::SecretLen for SealedDynRole<R> {
    #[inline]
    fn len(&self) -> usize {
        crate::SecretLen::len(&self.0)
    }
}
