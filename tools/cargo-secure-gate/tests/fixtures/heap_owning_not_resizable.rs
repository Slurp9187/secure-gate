// The distinction `fe64ef8` was made of, and the one an earlier version of this
// pass got wrong in the most damaging direction: it reported every shape here as
// honest while `Fixed::new` refused all of them.
//
// A boxed slice cannot be resized, which is why `FixedStorage` originally
// accepted it. It still owns a heap allocation, and replacing the whole value
// through `with_secret_mut(|slot| *slot = other)` abandons that allocation
// unwiped -- measured at 1024 of 1024 bytes surviving. No capacity ever changed.
// So the predicate is heap ownership, and all four of these must be errors.
use secure_gate::FixedStorage;

struct Boxed(Box<[u8]>);
impl FixedStorage for Boxed {}

// `tests/compile-fail/fixed_reallocating_inner.rs` pins this one by name.
struct Maybe(Option<Box<[u8]>>);
impl FixedStorage for Maybe {}

struct Pair([Box<[u8]>; 2]);
impl FixedStorage for Pair {}

// Shared ownership is heap ownership on the same reasoning.
use std::sync::Arc;
struct Shared(Arc<[u8]>);
impl FixedStorage for Shared {}

// The inline contrast from the same measurement: assigned the same way, this
// frees nothing at all, because there is no allocation to abandon.
struct Inline([u8; 1024]);
impl FixedStorage for Inline {}
