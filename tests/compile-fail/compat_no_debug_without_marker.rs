// Proves that Debug for v08::Secret<T> requires T: DebugSecret.
// A type that does not opt-in to DebugSecret cannot be formatted with {:?},
// preventing accidental secret exposure through logging / tracing / panics.
use secure_gate::compat::v08::Secret;
use zeroize::Zeroize;

struct SensitiveKey(Vec<u8>);

impl Zeroize for SensitiveKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
// Note: no `impl DebugSecret for SensitiveKey` — Debug must not compile.

fn requires_debug<T: core::fmt::Debug>(_: T) {}

fn main() {
    let s = Secret::new(SensitiveKey(vec![0xABu8; 32]));
    // E0277: Secret<SensitiveKey> does not implement Debug because
    // SensitiveKey does not implement DebugSecret.
    requires_debug(s);
}
