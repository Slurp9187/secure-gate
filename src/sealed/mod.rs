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
//! - A [`Prekey`] is 16 KiB of random bytes in a memory mapping of its own, between
//!   no-access guard pages, read-only, and locked in RAM where the operating system allows
//!   it. Each sealed object keeps an `Arc` to the one it was sealed under.
//! - Every seal draws a random 32-byte salt. The sealing key is `SHA-256(salt ‖ pre-key)`,
//!   recomputed on every access and wiped as soon as the cipher is keyed. It is never
//!   stored in the object. The cipher leaves a copy of it on the stack, so every seal and
//!   open ends by overwriting the 32 KiB of stack below the call (sequoia's `zero_stack`
//!   technique), on a panic as well as a normal return, which also removes plaintext a move
//!   left there. Measured on x86_64 Windows and Linux and on macOS ARM64, and on Linux
//!   ARM64 in a debug build (its release build leaves no key the probe can reach):
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
//! A **linear over-read** from a buffer elsewhere in the process (a C library's,
//! Heartbleed-style) does not reach the pre-key. It is not on the heap: measured, a 64 KiB
//! read from a C buffer captured the whole pre-key in every run when it was kept on the
//! heap, and none of it in its own mapping. And a read that runs into it faults on its
//! guard page: measured with readable memory placed directly against the mapping, where the
//! same read of an unguarded mapping takes all 16 KiB.
//!
//! # What it does not protect against
//!
//! - A **clean** read of the address space: a debugger, `/proc/<pid>/mem`, an attacker who
//!   can run code in the process. That read gets pre-key, salt and ciphertext together.
//! - **Hibernation** files, which capture locked pages too, and **crash dumps** on Windows
//!   and macOS. On Linux the pre-key is marked `MADV_DONTDUMP`, which the kernel documents
//!   as leaving it out of core dumps. On Windows a [`Prekey::new_idle_noaccess`] pre-key is
//!   absent from a user-mode full-memory dump (`MiniDumpWithFullMemory`) taken while it is
//!   idle, at the price of its lock; a kernel or complete memory dump captures physical
//!   memory whatever the protection.
//! - Over-reads of the sealed objects themselves: their ciphertext and salt are ordinary
//!   memory, but useless without the pre-key.
//! - A failed lock ([`Prekey::lock_status`] says so): the pre-key can then be swapped out
//!   like any other memory.
//! - The plaintext temporary while a closure runs. It lives on the stack
//!   ([`SealedFixed`]) or the heap ([`SealedDynamic`]) and is not locked; it is wiped, and
//!   the stack below the call overwritten, when the call returns. Copies the closure makes
//!   are the caller's to wipe.
//! - Registers, and stack residue beyond the overwritten 32 KiB. The overwrite was measured
//!   on x86_64 Windows and Linux only; another target's cipher backend or frame layout may
//!   differ.
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
//! # Where the protection stops
//!
//! Sealing protects a secret **while it is idle, and only as far as the pre-key is safe**.
//! Three edges, stated once:
//!
//! - **The pre-key.** Ciphertext, salt and tag are ordinary memory, and what keeps them
//!   closed is the pre-key, which is wiped when its last holder drops. A sealed value also
//!   wipes its own ciphertext, salt and tag when it is dropped, so a dropped secret leaves
//!   nothing to open even while other sealed values keep the pre-key alive. That wipe
//!   reaches the value where it is dropped: a [`SealedFixed`] that was moved leaves
//!   ciphertext in the stack slots it left (`SECURITY.md` §1), and a `SealedDynamic`'s one
//!   heap buffer is wiped whole.
//! - **The closure.** Inside `with_secret`, `with_secret_mut`, `with_role` and
//!   `with_role_mut` the secret is plaintext. The crate wipes the temporary it made; copies
//!   the closure makes are the caller's.
//! - **`unseal`.** It returns an ordinary [`Fixed`](crate::Fixed) or
//!   [`Dynamic`](crate::Dynamic) (or the plain role). From there the plain wrapper's rules
//!   apply and sealing protects nothing.
//!
//! # Not implemented, on purpose
//!
//! Every item here is a decision, not an omission. If you need one of them, open the secret
//! with `with_secret` and do it there, where the audit sweep sees it.
//!
//! - `expose_secret`, `into_inner` and [`RevealSecret`](crate::RevealSecret): plaintext
//!   must not outlive the call. Use [`RevealScoped`](crate::scoped::RevealScoped) for
//!   generic scoped access, and `unseal` to end sealing by name.
//! - [`RevealSecretMut`](crate::RevealSecretMut): it requires `RevealSecret`. The inherent
//!   `with_secret_mut` is the mutable access, and re-seals under a fresh salt. For
//!   [`SealedDynamic`] it hands out `&mut str` / `&mut [u8]`, not `&mut String` /
//!   `&mut Vec<u8>`, so the buffer cannot grow and abandon an unwiped copy.
//! - `Clone`, with or without `CloneableSecret`: a second copy
//!   would share the salt. Unseal, clone the plain value if its type allows it, and seal
//!   again.
//! - `Hash`, `PartialEq`, `Eq`: `Hash` would feed the plaintext into a hasher whose state
//!   is never wiped. Compare with `ConstantTimeEq` (the `ct-eq` feature).
//! - `Debug` beyond `[REDACTED]`: no salt, no tag, no length.
//! - `Zeroize`: zeroing a live sealed value would leave it unable to open. The sealed
//!   types do wipe on drop, and are `ZeroizeOnDrop`.
//! - Serde, the encoders (`ToHex` and the rest), the `try_from_*` decoders, `From`,
//!   `TryFrom` and `std::io::Write`: each would create or consume plaintext outside a
//!   scoped call. Decode or deserialize into a plain wrapper and seal that.
//! - `derive:` options on [`sealed_fixed_newtype!`](crate::sealed_fixed_newtype) and
//!   [`sealed_dynamic_newtype!`](crate::sealed_dynamic_newtype): a sealed role seals from
//!   and unseals to its one plain role, and nothing else.
//! - `with_role_mut` on `sealed_dynamic_newtype!`: it would hand out the growable role.
//!   `sealed_fixed_newtype!` has it, because a fixed role cannot grow.
//! - `from_random` on a sealed `String`, and on `sealed_dynamic_newtype!`: random bytes
//!   are not text, and that macro sees only the role's name, not whether it holds a
//!   `String` or a `Vec<u8>`. Seal a plain `Role::from_random(len)` instead.
//!   [`SealedFixed::from_random`], `SealedDynamic::<Vec<u8>>::from_random` and
//!   `sealed_fixed_newtype!`'s `from_random` exist.

mod dynamic;
mod fixed;
mod prekey;
#[doc(hidden)]
pub mod role;

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
///
/// The 0.9.0 hooks the sealed macros used, `__with_wrapped` and `__with_wrapped_mut`, are
/// gone (removed in 0.10.0):
///
/// ```compile_fail,E0599
/// use secure_gate::{Fixed, Prekey, RevealSecret, SealedFixed};
/// let s = SealedFixed::seal(Fixed::new([0u8; 4]), &Prekey::new());
/// let _ = s.__with_wrapped(|f| f, |f: &Fixed<[u8; 4]>| f.expose_secret()[0]);
/// ```
///
/// A sealed value has no plain `len()`: it is measured through
/// [`SecretLen`](crate::SecretLen), so the import is needed and searchable:
///
/// ```compile_fail,E0599
/// use secure_gate::{Fixed, Prekey, SealedFixed};
/// let s = SealedFixed::seal(Fixed::new([0u8; 4]), &Prekey::new());
/// let _ = s.len();
/// ```
///
/// Nor does the type a sealed macro generates:
///
/// ```compile_fail,E0599
/// use secure_gate::{Prekey, fixed_newtype, sealed_fixed_newtype};
/// fixed_newtype!(AppKey, 32);
/// sealed_fixed_newtype!(SealedAppKey, AppKey);
/// let k = SealedAppKey::seal(AppKey::new([0u8; 32]), &Prekey::new());
/// let _ = k.len();
/// ```
///
/// # The role wall
///
/// A sealed role is built on a conversion between the plain role and the `Fixed` or
/// `Dynamic` inside it. That conversion must not be a way into or out of a role that skips
/// `derive: [FromWrapper]` / `[IntoWrapper]`. Each case below compiled in 0.9.0.
///
/// A bare `Fixed` cannot be turned into a role through the hidden trait:
///
/// ```compile_fail,E0061
/// use secure_gate::{Fixed, fixed_newtype, __private::FixedRole};
/// fixed_newtype!(pub AppKey, 32);
/// let _ = <AppKey as FixedRole>::from_fixed(Fixed::new([0u8; 32]));
/// ```
///
/// Nor a role turned back into a bare `Fixed`:
///
/// ```compile_fail,E0061
/// use secure_gate::{Fixed, fixed_newtype, __private::FixedRole};
/// fixed_newtype!(pub AppKey, 32);
/// let _ = <AppKey as FixedRole>::into_fixed(AppKey::new([0u8; 32]));
/// ```
///
/// The token the conversion asks for cannot be made outside this crate:
///
/// ```compile_fail,E0423
/// use secure_gate::{Fixed, fixed_newtype, __private::{FixedRole, RoleToken}};
/// fixed_newtype!(pub AppKey, 32);
/// let token = RoleToken(core::marker::PhantomData);
/// let _ = <AppKey as FixedRole>::from_fixed(Fixed::new([0u8; 32]), token);
/// ```
///
/// A token is for one role. A hand-written role cannot spend the token it is given on
/// someone else's:
///
/// ```compile_fail,E0308
/// use secure_gate::{Fixed, fixed_newtype, __private::{FixedRole, RoleToken}};
/// fixed_newtype!(pub AppKey, 32);
/// pub struct Mine(Fixed<[u8; 32]>);
/// impl FixedRole for Mine {
///     type Fixed = Fixed<[u8; 32]>;
///     fn into_fixed(self, _: RoleToken<Self>) -> Self::Fixed { self.0 }
///     fn from_fixed(fixed: Self::Fixed, token: RoleToken<Self>) -> Self {
///         let _: AppKey = <AppKey as FixedRole>::from_fixed(Fixed::new([0u8; 32]), token);
///         Self(fixed)
///     }
/// }
/// ```
///
/// The same holds for a `dynamic_newtype!` role:
///
/// ```compile_fail,E0061
/// use secure_gate::{Dynamic, dynamic_newtype, __private::DynamicRole};
/// dynamic_newtype!(pub Password, String);
/// let _ = <Password as DynamicRole>::from_dynamic(Dynamic::<String>::new(String::new()));
/// ```
///
/// ```compile_fail,E0061
/// use secure_gate::{dynamic_newtype, __private::DynamicRole};
/// dynamic_newtype!(pub Password, String);
/// let _ = <Password as DynamicRole>::into_dynamic(Password::new("x"));
/// ```
#[cfg(doctest)]
pub struct MisuseDoesNotCompile;
