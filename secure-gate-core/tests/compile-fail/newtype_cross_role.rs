//! Two newtypes of the same shape must not be interchangeable.
//!
//! This is the entire point of `fixed_newtype!` over `fixed_alias!`: an
//! encryption key and a MAC key are both `Fixed<[u8; 32]>`, and passing one
//! where the other belongs compiles silently under a type alias.
use secure_gate::fixed_newtype;

fixed_newtype!(pub EncKey, 32);
fixed_newtype!(pub MacKey, 32);

fn seal(_enc: &EncKey, _mac: &MacKey) {}

fn main() {
    let enc = EncKey::new([1u8; 32]);
    let mac = MacKey::new([2u8; 32]);
    seal(&mac, &enc); // roles swapped
}
