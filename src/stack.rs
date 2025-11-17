// src/stack.rs
//! Zero-allocation, stack-only secret types.
//!
//! When the `stack` feature is enabled, these types are just
//! `zeroize::Zeroizing<[u8; N]>` — no heap, no allocator side-channels,
//! fully deterministic, works under `#![no_global_oom]`.

#[cfg(feature = "stack")]
mod imp {
    use zeroize::Zeroizing;

    pub type Key32 = Zeroizing<[u8; 32]>;
    pub type Key64 = Zeroizing<[u8; 64]>;
    pub type Nonce12 = Zeroizing<[u8; 12]>;
    pub type Nonce16 = Zeroizing<[u8; 16]>;
    pub type Nonce24 = Zeroizing<[u8; 24]>;
    pub type Iv = Zeroizing<[u8; 16]>;
    pub type Salt = Zeroizing<[u8; 16]>;

    macro_rules! new_fn {
        ($name:ident, $size:expr) => {
            #[must_use]
            pub fn $name(bytes: [u8; $size]) -> Zeroizing<[u8; $size]> {
                Zeroizing::new(bytes)
            }
        };
    }

    new_fn!(key32, 32);
    new_fn!(key64, 64);
    new_fn!(nonce12, 12);
    new_fn!(nonce16, 16);
    new_fn!(nonce24, 24);
    new_fn!(iv, 16);
    new_fn!(salt, 16);
}

#[cfg(feature = "stack")]
pub use imp::*;
