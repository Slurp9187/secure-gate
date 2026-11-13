/// Creates the sealed counterpart of a [`dynamic_newtype!`](crate::dynamic_newtype) role: a
/// distinct type around [`SealedDynamic`](crate::SealedDynamic) that seals from, and unseals
/// to, that role and no other. Requires the `sealed` feature.
///
/// `sealed_dynamic_newtype!(vis Name, Role, "doc")`: name and doc, like `dynamic_newtype!`,
/// plus the role it seals. `Role` must come from the `String` or `Vec<u8>` form of
/// `dynamic_newtype!` (`dynamic_newtype!(pub Password, String)`); a `generic` role cannot be
/// sealed, because sealing needs a byte view of the secret. No derives.
///
/// The generated type has `seal(Role, &Arc<Prekey>)`, `with_role` (the closure gets `&Role`,
/// for code that takes the role rather than a `String` or bytes), `with_secret`,
/// `with_secret_mut`, `unseal() -> Role`, `len`, `is_empty`, a redacted `Debug`, and
/// `ConstantTimeEq` under `ct-eq`. Like `SealedDynamic`, it has no `expose_secret` and no
/// `Hash`. The role a closure gets lives only for the call and is wiped when it returns.
///
/// **There is no `with_role_mut`**, where
/// [`sealed_fixed_newtype!`](crate::sealed_fixed_newtype) has one. A `&mut Role` reaches
/// `&mut String` / `&mut Vec<u8>`, which can grow, and growth reallocates and frees the old
/// buffer unwiped. `with_secret_mut` hands out `&mut str` / `&mut [u8]` instead, as on
/// `SealedDynamic`: the length is fixed, so that cannot happen. To change the length,
/// `unseal`, edit, and seal again.
///
/// ```rust
/// use secure_gate::{Prekey, RevealSecret, dynamic_newtype, sealed_dynamic_newtype};
///
/// dynamic_newtype!(pub Password, String, "A login password.");
/// sealed_dynamic_newtype!(pub SealedPassword, Password, "A login password, sealed while idle.");
///
/// let prekey = Prekey::new();
/// let mut sealed = SealedPassword::seal(Password::from("hunter2"), &prekey);
/// sealed.with_secret(|p: &String| assert_eq!(p, "hunter2"));
///
/// // Code that takes the role, not a `String`:
/// fn check(pw: &Password) -> bool { pw.with_secret(|p| p.len() >= 7) }
/// assert!(sealed.with_role(check));
///
/// // In place, at a fixed length:
/// sealed.with_secret_mut(|p: &mut str| p.make_ascii_uppercase());
/// let password: Password = sealed.unseal();
/// password.with_secret(|p| assert_eq!(p, "HUNTER2"));
/// ```
///
/// Roles stay apart when sealed. A sealed role does not take another role's secret:
///
/// ```compile_fail,E0308
/// use secure_gate::{Prekey, dynamic_newtype, sealed_dynamic_newtype};
///
/// dynamic_newtype!(pub Password, String);
/// dynamic_newtype!(pub ApiToken, String);
/// sealed_dynamic_newtype!(pub SealedPassword, Password);
///
/// let prekey = Prekey::new();
/// let _ = SealedPassword::seal(ApiToken::from("t"), &prekey);
/// ```
///
/// `with_role` hands only its own role:
///
/// ```compile_fail,E0631
/// use secure_gate::{Prekey, dynamic_newtype, sealed_dynamic_newtype};
///
/// dynamic_newtype!(pub Password, String);
/// dynamic_newtype!(pub ApiToken, String);
/// sealed_dynamic_newtype!(pub SealedPassword, Password);
///
/// fn send(_: &ApiToken) {}
/// let prekey = Prekey::new();
/// SealedPassword::seal(Password::from("p"), &prekey).with_role(send);
/// ```
///
/// Nor does one sealed role stand in for another:
///
/// ```compile_fail,E0308
/// use secure_gate::{Prekey, dynamic_newtype, sealed_dynamic_newtype};
///
/// dynamic_newtype!(pub Password, String);
/// dynamic_newtype!(pub ApiToken, String);
/// sealed_dynamic_newtype!(pub SealedPassword, Password);
/// sealed_dynamic_newtype!(pub SealedApiToken, ApiToken);
///
/// fn send(_: &SealedApiToken) {}
/// let prekey = Prekey::new();
/// send(&SealedPassword::seal(Password::from("p"), &prekey));
/// ```
///
/// The mutable view cannot grow the secret:
///
/// ```compile_fail,E0599
/// use secure_gate::{Prekey, dynamic_newtype, sealed_dynamic_newtype};
///
/// dynamic_newtype!(pub Password, String);
/// sealed_dynamic_newtype!(pub SealedPassword, Password);
///
/// let prekey = Prekey::new();
/// let mut sealed = SealedPassword::seal(Password::from("p"), &prekey);
/// sealed.with_secret_mut(|p| p.push('x'));
/// ```
#[cfg(feature = "sealed")]
#[macro_export]
macro_rules! sealed_dynamic_newtype {
    ($(#[$attr:meta])* $vis:vis $name:ident, $role:ty, $doc:literal) => {
        $crate::sealed_dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, $role);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, $role:ty) => {
        $(#[$attr])*
        #[must_use = "holds secret material; bind it or chain a method call"]
        $vis struct $name(
            $crate::SealedDynamic<<$role as $crate::__private::DynamicRole>::Payload>,
        );

        impl $name {
            /// Seals the role's secret under `prekey`. The plain secret is consumed and wiped.
            #[inline]
            pub fn seal(
                secret: $role,
                prekey: &$crate::__private::Arc<$crate::Prekey>,
            ) -> Self {
                Self($crate::SealedDynamic::seal(
                    <$role as $crate::__private::DynamicRole>::into_dynamic(secret),
                    prekey,
                ))
            }

            /// Decrypts into a temporary of the role for the length of `f`, then wipes it.
            #[inline]
            pub fn with_role<F, R>(&self, f: F) -> R
            where
                F: ::core::ops::FnOnce(&$role) -> R,
            {
                self.0
                    .__with_wrapped(<$role as $crate::__private::DynamicRole>::from_dynamic, f)
            }

            /// Decrypts into a temporary for the length of `f`, then wipes it.
            #[inline]
            pub fn with_secret<F, R>(&self, f: F) -> R
            where
                F: ::core::ops::FnOnce(&<$role as $crate::__private::DynamicRole>::Payload) -> R,
            {
                self.0.with_secret(f)
            }

            /// Decrypts, lets `f` change the secret in place, then re-seals under a fresh
            /// salt. `f` gets `&mut str` or `&mut [u8]`: the length is fixed, so the buffer
            /// cannot reallocate and abandon an unwiped copy.
            #[inline]
            pub fn with_secret_mut<F, R>(&mut self, f: F) -> R
            where
                F: ::core::ops::FnOnce(
                    &mut <<$role as $crate::__private::DynamicRole>::Payload
                        as $crate::sealed::SealedPayload>::Mut,
                ) -> R,
            {
                self.0.with_secret_mut(f)
            }

            /// Opens the secret back into its plain role. Protection from sealing ends
            /// here; the role still wipes on drop.
            #[inline]
            pub fn unseal(self) -> $role {
                <$role as $crate::__private::DynamicRole>::from_dynamic(self.0.unseal())
            }

            /// The secret's length in bytes. Length can itself be sensitive for passwords;
            /// it is not printed by `Debug`.
            #[inline]
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// `true` if the secret is empty.
            #[inline]
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl $crate::scoped::RevealScoped for $name {
            type Inner = <$role as $crate::__private::DynamicRole>::Payload;

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
macro_rules! sealed_dynamic_newtype {
    ($($t:tt)*) => {
        ::core::compile_error!("sealed_dynamic_newtype! requires secure-gate's `sealed` feature");
    };
}
