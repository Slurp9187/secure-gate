//! Class 3 — the growable buffer is one level below the wrapper's inner type.
//!
//! `Dynamic<Envelope>` satisfies every bound the crate asks for: `Envelope` is `Zeroize` by hand, so
//! the wrapper wipes it at drop. The secret lives in `Envelope::body`, a `Vec<u8>`, and it is grown
//! through `Envelope::absorb` — a method whose name is this consumer's vocabulary. No list can know
//! it, and the `Vec` it grows is not the wrapper's `Inner` type, so even a type-aware check that
//! knew `Dynamic<Vec<u8>>` was interesting would have to recurse through `Envelope` to find it.
//!
//! `ShardSet` is `Dynamic<Vec<Vec<u8>>>`: the outer `Vec` never changes capacity, so a sweep
//! watching the wrapper's own buffer sees a capacity-stable mutation, while the abandoned buffer is
//! an element's.

use secure_gate::{RevealSecret, RevealSecretMut};
use zeroize::Zeroize;

use super::roles::ShardSet;

/// A framed secret: the payload plus a plaintext routing label.
pub struct Envelope {
    /// The secret itself.
    pub body: Vec<u8>,
    /// Not secret; here so the struct is not a transparent `Vec` wrapper.
    pub label: u32,
}

impl Envelope {
    pub fn new(body: Vec<u8>) -> Self {
        Self { body, label: 0 }
    }

    /// Takes on more material. The consumer's word for it.
    pub fn absorb(&mut self, more: &[u8]) {
        self.body.extend_from_slice(more);
        self.label = self.label.wrapping_add(1);
    }
}

impl Zeroize for Envelope {
    fn zeroize(&mut self) {
        self.body.zeroize();
        self.label = 0;
    }
}

/// Grows the secret that lives two levels down from the access route.
pub fn absorb_into_envelope(env: &mut secure_gate::Dynamic<Envelope>, more: &[u8]) {
    env.with_secret_mut(|e| e.absorb(more));
}

/// Grows one shard. The wrapper's own `Vec<Vec<u8>>` keeps its capacity throughout.
pub fn grow_shard(shards: &mut ShardSet, index: usize, more: &[u8]) {
    shards.with_secret_mut(|outer| {
        if let Some(shard) = outer.get_mut(index) {
            shard.extend_from_slice(more);
        }
    });
}

/// The same shard growth reached through `as_wrapper_mut`, the `derive: [WrapperAccess]` route.
pub fn grow_shard_via_wrapper(shards: &mut ShardSet, index: usize, more: &[u8]) {
    let base = shards.as_wrapper_mut();
    base.with_secret_mut(|outer| {
        if let Some(shard) = outer.get_mut(index) {
            super::util_pad::pad(shard, more);
        }
    });
}

/// Reads the address of one shard's buffer, so the instrument can watch it.
pub fn shard_ptr(shards: &ShardSet, index: usize) -> *const u8 {
    shards.with_secret(|outer| outer[index].as_ptr())
}
