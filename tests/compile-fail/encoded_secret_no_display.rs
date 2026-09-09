//! `EncodedSecret` must not implement `Display`.
//!
//! `Debug` printing `[REDACTED]` teaches callers that the type is safe to put in a log
//! line. A transparent `Display` on the same type would then punish exactly the callers
//! who checked — `tracing::info!("token: {tok}")` would print the secret. Writing the
//! encoded value out is still available via `&*encoded`, which names the deref.
//!
//! Note the scope: this closes format strings, not extraction. `Deref<Target = str>`
//! still provides `str::to_string()`, by design.

use secure_gate::{Fixed, ToHex};

fn main() {
    let encoded = Fixed::new([0xABu8; 4]).to_hex();

    // Must not compile: `{}` on a secret-bearing type.
    println!("{encoded}");
}
