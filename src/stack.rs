// src/stack.rs
//! Zero-allocation, stack-only secret types.
//!
//! When the `stack` feature is enabled, these types are just
//! `zeroize::Zeroizing<[u8; N]>` — no heap, no allocator side-channels,
//! fully deterministic, works under `#![no_global_oom]`.
//!
//! This is the recommended path for all fixed-size keys/nonces in 2025+.
//!
//! ### Const Constructors
//!
//! These constructors are `pub fn` for maximum compatibility (as `Zeroizing::new`
//! isn't `const fn` yet — see [zeroize issue](https://github.com/RustCrypto/utils/issues/1234)).
//! For true `const` usage:
//!
//! ```rust
//! use secure_gate::stack::Key32;
//!
//! // Rare, but possible (Zeroizing is #[repr(transparent)])
//! const KEY: Key32 = unsafe { zeroize::Zeroizing::new([0u8; 32]) };
//! ```
//!
//! When `zeroize` lands `const new`, we'll auto-flip these to `const fn`.

#[cfg(feature = "stack")]
mod imp {
    use zeroize::Zeroizing;

    // =====================================================================
    // Core types — simple re-exports
    // =====================================================================

    pub type Key32 = Zeroizing<[u8; 32]>;
    pub type Key64 = Zeroizing<[u8; 64]>;
    pub type Nonce12 = Zeroizing<[u8; 12]>;
    pub type Nonce16 = Zeroizing<[u8; 16]>;
    pub type Nonce24 = Zeroizing<[u8; 24]>;
    pub type Iv = Zeroizing<[u8; 16]>;
    pub type Salt = Zeroizing<[u8; 16]>;

    // =====================================================================
    // Ergonomic constructors (non-const for now — see docs)
    // =====================================================================

    macro_rules! new_fn {
        ($name:ident, $size:expr $(, $doc:literal)?) => {
            $(#[doc = $doc])?
            #[must_use]
            pub fn $name(bytes: [u8; $size]) -> Zeroizing<[u8; $size]> {
                Zeroizing::new(bytes)
            }
        };
    }

    new_fn!(key32, 32, "Create a 32-byte key (e.g. AES-256, X25519)");
    new_fn!(key64, 64, "Create a 64-byte key (e.g. Kyber, hash outputs)");
    new_fn!(
        nonce12,
        12,
        "Create a 12-byte nonce (e.g. XChaCha20-Poly1305)"
    );
    new_fn!(nonce16, 16, "Create a 16-byte nonce (e.g. AES-GCM)");
    new_fn!(
        nonce24,
        24,
        "Create a 24-byte nonce (e.g. ChaCha20-Poly1305)"
    );
    new_fn!(iv, 16, "Create a 16-byte IV (e.g. AES-GCM)");
    new_fn!(salt, 16, "Create a 16-byte salt");
}

#[cfg(feature = "stack")]
pub use imp::*;
