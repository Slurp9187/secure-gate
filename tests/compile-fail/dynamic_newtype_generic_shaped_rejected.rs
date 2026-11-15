//! `generic Vec<u8>` and `generic String` are strictly dominated spellings.
//!
//! Both take a payload the crate already knows how to handle and then withhold
//! the methods that handle it. The `generic` arm emits only the
//! shape-independent surface, so `SecretLen`, `From`, `new_with`, the encoders
//! and — for `Vec<u8>` under `std` — the `io::Write` impl that wipes the buffer
//! it abandons are all absent. Same growable payload, strictly less API.
//!
//! That is the distinction from `dynamic_newtype_alias_rejected.rs`: an alias
//! is a spelling the macro *cannot see through*, so it falls through to the
//! catch-all. These two it can see, so they are refused by name at the
//! declaration, which is where the greppable fix belongs.
//!
//! All four tails the `generic` arm accepts are pinned, because a bare-only
//! reject would leave the doc-string and `derive:` forms on the reduced arm and
//! a later arm-order slip would be invisible.
use secure_gate::dynamic_newtype;

dynamic_newtype!(pub Bytes, generic Vec<u8>);
dynamic_newtype!(pub Text, generic String);
dynamic_newtype!(pub BytesWithDoc, generic Vec<u8>, "a documented secret");
dynamic_newtype!(pub TextWithDerive, generic String, derive: [IntoWrapper]);

fn main() {}
