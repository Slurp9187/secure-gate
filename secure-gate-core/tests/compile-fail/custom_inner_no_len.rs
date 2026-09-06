// The import is the point: `len()` must be absent even with `SecretLen` in scope.
// rustc reports it unused once the call fails to resolve; allow that so the
// snapshot is identical whether or not CI turns warnings into errors.
#[allow(unused_imports)]
use secure_gate::{Fixed, SecretLen};
use zeroize::Zeroize;

struct SessionKey([u8; 32]);
impl Zeroize for SessionKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

fn main() {
    let key = Fixed::new(SessionKey([0u8; 32]));
    // SecretLen is deliberately narrow: a custom inner type has no meaningful
    // length, so `len()` must not compile even with the trait in scope.
    let _ = key.len();
}
