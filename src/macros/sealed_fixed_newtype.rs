/// Creates the sealed counterpart of a [`fixed_newtype!`](crate::fixed_newtype) byte role:
/// a distinct type around [`SealedFixed<N>`](crate::SealedFixed) that seals from, and
/// unseals to, that role and no other. Requires the `sealed` feature.
///
/// `sealed_fixed_newtype!(vis Name, Role, "doc")`: name and doc, like `fixed_newtype!`, plus
/// the role it seals. `Role` must come from the size-literal form of `fixed_newtype!`
/// (`fixed_newtype!(pub AppKey, 32)`). The length is taken from it, so it is never
/// restated. No derives.
///
/// The generated type has `seal(Role, &Arc<Prekey>)`, `with_secret`, `with_secret_mut`,
/// `unseal() -> Role`, `len`, `is_empty`, a redacted `Debug`, and `ConstantTimeEq` under
/// `ct-eq`. Like `SealedFixed`, it has no `expose_secret` and no `Hash`.
///
/// ```rust
/// use secure_gate::{Prekey, RevealSecret, fixed_newtype, sealed_fixed_newtype};
///
/// fixed_newtype!(pub AppKey, 32, "The app key.");
/// sealed_fixed_newtype!(pub SealedAppKey, AppKey, "The app key, sealed while idle.");
///
/// let prekey = Prekey::new();
/// let sealed = SealedAppKey::seal(AppKey::new([9u8; 32]), &prekey);
/// sealed.with_secret(|k| assert_eq!(k[0], 9));
/// let key: AppKey = sealed.unseal();
/// key.with_secret(|k| assert_eq!(k[0], 9));
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

            /// Opens the key back into its plain role.
            #[inline]
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
