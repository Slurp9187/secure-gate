//! `generic [u8; N]` is strictly dominated by the size-literal arm.
//!
//! It takes a payload this crate already specialises (`Fixed<[u8; N]>`) and then
//! withholds `SecretLen`, `From`, `TryFrom`, the encoders and `from_random`. Same
//! bytes, strictly less API. `dynamic_newtype!` already refuses the analogous
//! spellings; this is the matching pin.
//!
//! All four tails the `generic` arm accepts are pinned, because a bare-only
//! reject would leave the doc-string and `derive:` forms on the reduced arm and
//! a later arm-order slip would be invisible. `generic [i16; 4]` is not in this
//! file: that is a legitimate reduced-API newtype, pinned by
//! `tests/compile-pass/fixed_nonzero_size.rs`.
use secure_gate::fixed_newtype;

fixed_newtype!(pub Bytes, generic [u8; 32]);
fixed_newtype!(pub BytesWithDoc, generic [u8; 16], "a documented secret");
fixed_newtype!(pub BytesWithDerive, generic [u8; 32], derive: [IntoWrapper]);
fixed_newtype!(
    pub BytesWithBoth,
    generic [u8; 8],
    "doc and derive",
    derive: [FromWrapper]
);

fn main() {}
