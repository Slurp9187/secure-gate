//! Secrets held **encrypted in RAM while idle**, opened for one closure call at a time.
//! Requires the `sealed` feature.
//!
//! [`Fixed`](crate::Fixed) and [`Dynamic`](crate::Dynamic) hold their secret in plaintext
//! for their whole lifetime and wipe it on drop. [`SealedFixed`] and [`SealedDynamic`] hold
//! it as ChaCha20-Poly1305 ciphertext instead, and decrypt only into a temporary that
//! exists for the length of a `with_secret` / `with_secret_mut` call. The design follows
//! `sequoia-openpgp`'s `crypto::mem::Encrypted`, itself following OpenSSH.
//!
//! ```rust
//! use secure_gate::{Fixed, Prekey, SealedFixed};
//!
//! // One per session; drop it, and everything sealed under it, at lock or logout.
//! let prekey = Prekey::new();
//! if let Err(why) = prekey.lock_status() {
//!     eprintln!("note: {why}"); // not fatal
//! }
//!
//! let mut key = SealedFixed::seal(Fixed::new([7u8; 32]), &prekey);
//! key.with_secret(|k| assert_eq!(k[0], 7));
//! key.with_secret_mut(|k| k[0] = 8); // re-sealed under a fresh salt
//! let plain: Fixed<[u8; 32]> = key.unseal();
//! ```
//!
//! # How it works
//!
//! - A [`Prekey`] is 16 KiB of random bytes, page-aligned and locked in RAM where the
//!   operating system allows it. Each sealed object keeps an `Arc` to the one it was sealed
//!   under.
//! - Every seal draws a random 32-byte salt. The sealing key is `SHA-256(salt ‖ pre-key)`,
//!   recomputed on every access and wiped as soon as the cipher is keyed. It is never
//!   stored in the object. The cipher leaves a copy of it on the stack, so every seal and
//!   open ends by overwriting the 32 KiB of stack below the call (sequoia's `zero_stack`
//!   technique), on a panic as well as a normal return, which also removes plaintext a move
//!   left there. Measured on x86_64 Windows:
//!   `docs/design/receipts/sealed-stack-residue/` in the repository.
//! - Because every seal has its own key, the AEAD nonce is all-zero. Every re-seal after
//!   [`with_secret_mut`](SealedFixed::with_secret_mut) draws a new salt, so no key ever
//!   encrypts twice.
//!
//! # What it protects against
//!
//! **Lossy readout** of process memory: Spectre-class side channels, Rowhammer, cold boot.
//! These recover memory with bit errors. A 32-byte key read with a few flipped bits is
//! still recoverable by search; a sealing key that depends on all 131,072 bits of the
//! pre-key is not, because one wrong bit anywhere avalanches through SHA-256.
//!
//! With the pre-key locked, a sealed secret that reaches the **swap file** cannot be
//! opened from it, because the pre-key never gets there.
//!
//! # What it does not protect against
//!
//! - A **clean** read of the address space: a debugger, `/proc/<pid>/mem`, an attacker who
//!   can run code in the process. That read gets pre-key, salt and ciphertext together.
//! - **Hibernation** files and **crash or core dumps**, which capture locked pages too.
//! - A failed lock ([`Prekey::lock_status`] says so): the pre-key can then be swapped out
//!   like any other memory.
//! - The plaintext temporary while a closure runs. It lives on the stack
//!   ([`SealedFixed`]) or the heap ([`SealedDynamic`]) and is not locked; it is wiped, and
//!   the stack below the call overwritten, when the call returns. Copies the closure makes
//!   are the caller's to wipe.
//! - Registers, and stack residue beyond the overwritten 32 KiB. The overwrite was measured
//!   on one target; another target's cipher backend or frame layout may differ.
//! - Pages larger than the pre-key block's alignment (16 KiB on x86, x86_64 and Apple
//!   aarch64; 64 KiB elsewhere): the pre-key would share its page, so it is not locked at
//!   all, and [`Prekey::lock_status`] says so. No known target's default page is larger.
//! - What [`unseal`](SealedFixed::unseal) returns: an ordinary `Fixed`, whose by-value
//!   return can leave a copy in the caller's frame (`SECURITY.md` §1). Read through
//!   `with_secret` instead where you can.
//!
//! It narrows one threat. It is not a substitute for encrypted swap, disabled core dumps,
//! or anything else in `SECURITY.md`.
//!
//! # Cost
//!
//! Each access needs about 32 KiB of free stack for the scrub, on top of the cipher's own
//! frames: mind small custom thread stacks. Measured on x86_64 Windows: an access on a
//! 64 KiB thread stack completes in a release build and overflows in a debug build; 96 KiB
//! completes in both.
//!
//! Not zero-overhead. Each access hashes 16 KiB and runs one AEAD pass; each mutation adds
//! an RNG call and a second pass. The repository's `sealed_vs_fixed` benchmark measures it.
//!
//! # Not implemented, on purpose
//!
//! - `expose_secret` / [`RevealSecret`](crate::RevealSecret): plaintext must not outlive
//!   the call. Use [`RevealScoped`](crate::scoped::RevealScoped) for generic scoped access.
//! - `Hash`: it would feed the plaintext into a hasher whose state is never wiped.
//! - `Debug` beyond `[REDACTED]`: no salt, no tag, no length.

mod dynamic;
mod fixed;
mod prekey;

pub use dynamic::{SealedDynamic, SealedPayload};
pub use fixed::SealedFixed;
pub use prekey::{LockError, Prekey};

/// What the sealed types must not offer, checked by compiling each misuse.
///
/// No `expose_secret`, so no reference outlives the call:
///
/// ```compile_fail,E0599
/// use secure_gate::{Fixed, Prekey, SealedFixed};
/// let s = SealedFixed::seal(Fixed::new([0u8; 32]), &Prekey::new());
/// let _ = s.expose_secret();
/// ```
///
/// No `RevealSecret` impl to reach it through either:
///
/// ```compile_fail,E0277
/// use secure_gate::{Fixed, Prekey, RevealSecret, SealedFixed};
/// fn needs<S: RevealSecret>(_: &S) {}
/// needs(&SealedFixed::seal(Fixed::new([0u8; 32]), &Prekey::new()));
/// ```
///
/// No `Hash`, which would feed the plaintext to a hasher that is never wiped:
///
/// ```compile_fail,E0277
/// use secure_gate::{Fixed, Prekey, SealedFixed};
/// fn needs<H: core::hash::Hash>(_: &H) {}
/// needs(&SealedFixed::seal(Fixed::new([0u8; 32]), &Prekey::new()));
/// ```
///
/// `with_secret_mut` on a sealed `Vec` hands out a fixed-length slice, so it cannot grow:
///
/// ```compile_fail,E0599
/// use secure_gate::{Dynamic, Prekey, SealedDynamic};
/// let mut s = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(vec![1]), &Prekey::new());
/// s.with_secret_mut(|v| v.push(2));
/// ```
///
/// Nor can a sealed `String`:
///
/// ```compile_fail,E0599
/// use secure_gate::{Dynamic, Prekey, SealedDynamic};
/// let mut s = SealedDynamic::seal(Dynamic::<String>::new(String::from("a")), &Prekey::new());
/// s.with_secret_mut(|v| v.push_str("b"));
/// ```
///
/// A borrow from `with_secret` cannot escape the closure:
///
/// ```compile_fail
/// use secure_gate::{Fixed, Prekey, SealedFixed};
/// let s = SealedFixed::seal(Fixed::new([0u8; 32]), &Prekey::new());
/// let leaked: &[u8; 32] = s.with_secret(|b| b);
/// ```
///
/// Not `Clone`, even with the `cloneable` feature: like `Fixed<[u8; N]>`, a sealed byte
/// secret is not copied implicitly.
///
/// ```compile_fail,E0277
/// use secure_gate::{Fixed, Prekey, SealedFixed};
/// fn needs<C: Clone>(_: &C) {}
/// needs(&SealedFixed::seal(Fixed::new([0u8; 32]), &Prekey::new()));
/// ```
///
/// Only `Vec<u8>` and `String` can be sealed as variable-length secrets:
///
/// ```compile_fail,E0277
/// use secure_gate::{Dynamic, Prekey, SealedDynamic};
/// let _ = SealedDynamic::seal(Dynamic::<Vec<u16>>::new(vec![1]), &Prekey::new());
/// ```
#[cfg(doctest)]
pub struct MisuseDoesNotCompile;
