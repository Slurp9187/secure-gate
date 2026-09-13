//! Consumer-side evasion corpus for a text-level "reallocation residue" sweep of `secure-gate`.
//!
//! Every module under [`corpus`] contains a REAL instance of the documented weakness — a
//! `Vec`/`String` buffer holding the whole secret is abandoned to the allocator unwiped — written
//! the way a consumer would plausibly write it, and shaped so that a regex/name-based scan of this
//! file reports nothing. The leak in each case is measured in `tests/measure.rs` with a
//! `GlobalAlloc` instrument; a case that cannot be measured is not a finding and is not here.
//!
//! Nothing in this crate is a vulnerability in `secure-gate` that the crate does not already
//! document. The claim under test is about the *detectability* of that weakness from text.

pub mod benign;
pub mod corpus;
