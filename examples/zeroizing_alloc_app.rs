//! The copy-paste application shape from `SECURITY.md`'s deployment-level remediation
//! guidance, made executable so it compiles rather than only being read.
//!
//! Only a **binary** can install a `#[global_allocator]` — the attribute may appear once per
//! program, so a library cannot make this choice for the applications that depend on it. That is
//! why `secure-gate` points application authors here instead of doing this itself.
//!
//! **Where this declaration goes matters.** In a crate that is a binary only, `src/main.rs` is
//! fine. In a crate with both a library and a binary target — the common `src/lib.rs` plus a
//! thin `src/main.rs` shape — the declaration belongs in `src/lib.rs` instead: one in `main.rs`
//! reaches the shipped binary but not the integration tests under `tests/`, each of which links
//! the library and would otherwise run with the default allocator.
//!
//! This file plays the role of that binary. It exercises a `Dynamic<Vec<u8>>` secret through a
//! capacity change (`with_secret_mut` growing past the current capacity), which is the exact
//! shape the allocator protects: the reallocation happens outside `secure-gate`, and the
//! abandoned block is what a zero-on-deallocate allocator wipes on the way to being freed.

use secure_gate::{Dynamic, RevealSecretMut};
use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);

fn main() {
    let mut secret = Dynamic::<Vec<u8>>::new(Vec::with_capacity(4));

    secret.with_secret_mut(|bytes| {
        bytes.extend_from_slice(b"key1");
    });

    // Force a reallocation: growing past the current capacity moves the buffer, abandoning the
    // old block. `ALLOC` wipes that block's contents as part of freeing it.
    secret.with_secret_mut(|bytes| {
        bytes.reserve(64);
        bytes.extend_from_slice(b"more-secret-bytes-after-the-move");
    });

    secret.with_secret_mut(|bytes| {
        println!("secret is {} bytes", bytes.len());
    });
}
