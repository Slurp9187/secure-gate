//! Dual-test macros for side-by-side parity testing.
//!
//! Each macro creates a module with two `#[test]` functions:
//! - `real_secrecy`: runs the body with real `secrecy` crate imports
//! - `compat_shim`: runs the identical body with `secure-gate` compat imports
//!
//! ## Rules for test bodies
//!
//! - Use only names listed in the shared name tables (see plan §3)
//! - No qualified `::` paths inside the body — always unqualified names
//! - No `Deref` / `AsRef` — those are divergence tests, not parity tests
//! - v10 bodies: no `SecretString::from("&str literal")` — real secrecy v0.10.1
//!   has no `From<&str>`; use `SecretString::from(String::from(...))` instead
//! - v10 bodies: no `SecretString::default()` or `SecretSlice::default()` —
//!   real secrecy v0.10.1 lacks concrete `Default` impls for unsized shims

/// Run `$body` against both `secrecy 0.8.0` and the `secure-gate` v08 compat shim.
///
/// Shared imports injected into `real_secrecy`:
///   `Secret, SecretString, SecretVec, CloneableSecret, DebugSecret, ExposeSecret`
///   (all from `secrecy_v08::`)
///
/// Shared imports injected into `compat_shim`:
///   `Secret, SecretString, SecretVec, DebugSecret` from `secure_gate_compat::compat::v08`
///   `CloneableSecret, ExposeSecret` from `secure_gate_compat::compat`
macro_rules! dual_test_v08 {
    ($name:ident { $($tt:tt)* }) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[test]
            fn real_secrecy() {
                #[allow(unused_imports)]
                use secrecy_v08::{
                    CloneableSecret, DebugSecret, ExposeSecret, Secret, SecretString, SecretVec,
                };
                $($tt)*
            }

            #[test]
            fn compat_shim() {
                #[allow(unused_imports)]
                use secure_gate_compat::compat::v08::{DebugSecret, Secret, SecretString, SecretVec};
                #[allow(unused_imports)]
                use secure_gate_compat::compat::{CloneableSecret, ExposeSecret};
                $($tt)*
            }
        }
    };
}

/// Run `$body` against both `secrecy 0.10.1` and the `secure-gate` v10 compat shim.
///
/// Shared imports injected into `real_secrecy`:
///   `SecretBox, SecretString, SecretSlice, ExposeSecret, ExposeSecretMut`
///   (all from `secrecy_v10::`)
///
/// Shared imports injected into `compat_shim`:
///   `SecretBox, SecretString, SecretSlice` from `secure_gate_compat::compat::v10`
///   `ExposeSecret, ExposeSecretMut` from `secure_gate_compat::compat`
macro_rules! dual_test_v10 {
    ($name:ident { $($tt:tt)* }) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[test]
            fn real_secrecy() {
                #[allow(unused_imports)]
                use secrecy_v10::{
                    CloneableSecret, ExposeSecret, ExposeSecretMut, SecretBox, SecretSlice,
                    SecretString,
                };
                $($tt)*
            }

            #[test]
            fn compat_shim() {
                #[allow(unused_imports)]
                use secure_gate_compat::compat::v10::{SecretBox, SecretSlice, SecretString};
                #[allow(unused_imports)]
                use secure_gate_compat::compat::{CloneableSecret, ExposeSecret, ExposeSecretMut};
                $($tt)*
            }
        }
    };
}
