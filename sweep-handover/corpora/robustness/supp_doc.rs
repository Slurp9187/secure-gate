//! Module docs.
//!
//! Historical note: we used to write `// sg-sweep: ignore-file` here before the
//! lexer masked comments; it is only prose now.
struct K { v: Vec<u8> }
impl FixedStorage for K {}
fn leak(d: &mut Dynamic<Vec<u8>>) { d.with_secret_mut(|v| v.push(1)); }
