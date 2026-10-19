/// Creates the sealed counterpart of a [`fixed_newtype!`](crate::fixed_newtype) byte role:
/// a distinct type around [`SealedFixed<N>`](crate::SealedFixed) that seals from, and
/// unseals to, that role and no other. Requires the `sealed` feature.
///
/// `sealed_fixed_newtype!(vis Name, Role, "doc")`: name and doc, like `fixed_newtype!`, plus
/// the role it seals. `Role` must come from the size-literal form of `fixed_newtype!`
/// (`fixed_newtype!(pub AppKey, 32)`). The length is taken from it, so it is never
/// restated. No derives.
///
/// The generated type has `seal(Role, &Arc<Prekey>)`, `with_role` / `with_role_mut` (the
/// closure gets `&Role` / `&mut Role`, for code that takes the role rather than bytes),
/// `with_secret` / `with_secret_mut` (bytes), `unseal() -> Role`, `len`, `is_empty`, a
/// redacted `Debug`, and `ConstantTimeEq` under `ct-eq`. Like `SealedFixed`, it has no
/// `expose_secret` and no `Hash`. The role a closure gets lives only for the call, in the
/// frame the stack scrub covers; moving it out of the closure takes it out of that cover.
///
/// ```rust
/// use secure_gate::{Prekey, RevealSecret, RevealSecretMut, fixed_newtype, sealed_fixed_newtype};
///
/// fixed_newtype!(pub AppKey, 32, "The app key.");
/// sealed_fixed_newtype!(pub SealedAppKey, AppKey, "The app key, sealed while idle.");
///
/// let prekey = Prekey::new();
/// let mut sealed = SealedAppKey::seal(AppKey::new([9u8; 32]), &prekey);
/// sealed.with_secret(|k| assert_eq!(k[0], 9));
///
/// // Code that takes the role, not bytes:
/// fn wrap_vault(key: &AppKey) -> u8 { key.with_secret(|k| k[0]) }
/// assert_eq!(sealed.with_role(wrap_vault), 9);
/// sealed.with_role_mut(|key: &mut AppKey| key.with_secret_mut(|k| k[0] = 10));
/// let key: AppKey = sealed.unseal();
/// key.with_secret(|k| assert_eq!(k[0], 10));
/// ```
///
/// Roles stay apart when sealed. A sealed role does not take another role's key:
///
/// ```compile_fail,E0308
/// use secure_gate::{Prekey, fixed_newtype, sealed_fixed_newtype};
///
/// fixed_newtype!(pub AppKey, 32);
/// fixed_newtype!(pub DbKey, 32);
/// sealed_fixed_newtype!(pub SealedAppKey, AppKey);
///
/// let prekey = Prekey::new();
/// let _ = SealedAppKey::seal(DbKey::new([0u8; 32]), &prekey);
/// ```
///
/// `with_role` hands only its own role:
///
/// ```compile_fail,E0631
/// use secure_gate::{Prekey, fixed_newtype, sealed_fixed_newtype};
///
/// fixed_newtype!(pub AppKey, 32);
/// fixed_newtype!(pub DbKey, 32);
/// sealed_fixed_newtype!(pub SealedAppKey, AppKey);
///
/// fn open_db(_: &DbKey) {}
/// let prekey = Prekey::new();
/// SealedAppKey::seal(AppKey::new([0u8; 32]), &prekey).with_role(open_db);
/// ```
///
/// Nor does one sealed role stand in for another:
///
/// ```compile_fail,E0308
/// use secure_gate::{Prekey, fixed_newtype, sealed_fixed_newtype};
///
/// fixed_newtype!(pub AppKey, 32);
/// fixed_newtype!(pub DbKey, 32);
/// sealed_fixed_newtype!(pub SealedAppKey, AppKey);
/// sealed_fixed_newtype!(pub SealedDbKey, DbKey);
///
/// fn open_db(_: &SealedDbKey) {}
/// let prekey = Prekey::new();
/// open_db(&SealedAppKey::seal(AppKey::new([0u8; 32]), &prekey));
/// ```
#[cfg(feature = "sealed")]
#[macro_export]
macro_rules! sealed_fixed_newtype {
    ($(#[$attr:meta])* $vis:vis $name:ident, $role:ty, $doc:literal) => {
        $crate::sealed_fixed_newtype!($(#[$attr])* #[doc = $doc] $vis $name, $role);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, $role:ty) => {
        $(#[$attr])*
        #[must_use = "holds secret material; bind it or chain a method call"]
        $vis struct $name($crate::__private::SealedOf<$role>);

        impl $name {
            /// Seals the role's key under `prekey`. The plain key is consumed and wiped.
            #[inline]
            pub fn seal(
                secret: $role,
                prekey: &$crate::__private::Arc<$crate::Prekey>,
            ) -> Self {
                Self($crate::SealedFixed::seal(
                    <$role as $crate::__private::FixedRole>::into_fixed(secret),
                    prekey,
                ))
            }

            /// Decrypts into a temporary of the role for the length of `f`, then wipes it and
            /// the stack below the call.
            #[inline]
            pub fn with_role<F, R>(&self, f: F) -> R
            where
                F: ::core::ops::FnOnce(&$role) -> R,
            {
                self.0
                    .__with_wrapped(<$role as $crate::__private::FixedRole>::from_fixed, f)
            }

            /// Decrypts into a temporary of the role, lets `f` change it, then re-seals under
            /// a fresh salt and wipes the temporary and the stack below the call.
            #[inline]
            pub fn with_role_mut<F, R>(&mut self, f: F) -> R
            where
                F: ::core::ops::FnOnce(&mut $role) -> R,
            {
                self.0.__with_wrapped_mut(
                    <$role as $crate::__private::FixedRole>::from_fixed,
                    <$role as $crate::__private::FixedRole>::into_fixed,
                    f,
                )
            }

            /// Decrypts into a temporary for the length of `f`, then wipes it.
            #[inline]
            pub fn with_secret<F, R>(&self, f: F) -> R
            where
                F: ::core::ops::FnOnce(&<$role as $crate::RevealSecret>::Inner) -> R,
            {
                self.0.with_secret(f)
            }

            /// Decrypts, lets `f` change the key, then re-seals under a fresh salt.
            #[inline]
            pub fn with_secret_mut<F, R>(&mut self, f: F) -> R
            where
                F: ::core::ops::FnOnce(&mut <$role as $crate::RevealSecret>::Inner) -> R,
            {
                self.0.with_secret_mut(f)
            }

            /// Opens the key back into its plain role. From then on it is an ordinary role
            /// value: returning it by value can leave a copy in the caller's frame
            /// (`SECURITY.md` §1). To read the key, prefer `with_role`, which leaves nothing.
            #[inline(always)]
            pub fn unseal(self) -> $role {
                <$role as $crate::__private::FixedRole>::from_fixed(self.0.unseal())
            }

            /// The key's length in bytes.
            #[inline(always)]
            pub const fn len(&self) -> usize {
                self.0.len()
            }

            /// `true` only for a zero-length key, which `fixed_newtype!` rejects.
            #[inline(always)]
            pub const fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl $crate::scoped::RevealScoped for $name {
            type Inner = <$role as $crate::RevealSecret>::Inner;

            #[inline]
            fn with_secret<F, R>(&self, f: F) -> R
            where
                F: ::core::ops::FnOnce(&Self::Inner) -> R,
            {
                self.0.with_secret(f)
            }
        }

        impl ::core::fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str("[REDACTED]")
            }
        }

        $crate::__sg_if_ct_eq! {
            impl $crate::ConstantTimeEq for $name {
                #[inline]
                fn ct_eq(&self, other: &Self) -> bool {
                    $crate::ConstantTimeEq::ct_eq(&self.0, &other.0)
                }
            }
        }
    };
}

/// Without the `sealed` feature the macro exists only to say which feature it needs.
#[cfg(not(feature = "sealed"))]
#[doc(hidden)]
#[macro_export]
macro_rules! sealed_fixed_newtype {
    ($($t:tt)*) => {
        ::core::compile_error!("sealed_fixed_newtype! requires secure-gate's `sealed` feature");
    };
}
