// Rust identifiers are XID, not `[A-Za-z_]`, so a one-character rename defeats
// an ASCII-only matcher. A real parser gets this for free; the fixture exists to
// keep it that way.
use secure_gate::FixedStorage;

struct Ключ {
    material: Vec<u8>,
}
impl FixedStorage for Ключ {}

struct 鍵 {
    material: String,
}
impl FixedStorage for 鍵 {}
