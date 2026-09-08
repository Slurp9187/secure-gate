//! Side-by-side parity tests: real `secrecy` vs `secure-gate` compat shim.
//!
//! Enabled by `--features dual-compat-test`. Each `dual_test_v08!` /
//! `dual_test_v10!` invocation expands into a module containing two `#[test]`
//! functions — `real_secrecy` and `compat_shim` — that run identical bodies
//! under different imports, producing output like:
//!
//! ```text
//! compat_dual::parity_v08::secret_new::real_secrecy  ... ok
//! compat_dual::parity_v08::secret_new::compat_shim   ... ok
//! ```
//!
//! ## Scope
//!
//! - `parity_v08` / `parity_v10`: shared-API dual tests + shim-extension tests
//! - `divergence`: zeroization parity assertions + shim-only stricter behaviors
#[macro_use]
mod macros;

mod divergence;
mod parity_v08;
mod parity_v10;
