// `Fixed::new_with` hands the closure a `&mut [u8; N]`. It has no capacity to
// change, and since #201's FixedStorage bound its inner type cannot be a Vec.
// Must not be flagged: the method name is shared with Dynamic, the hazard is not.
use secure_gate::{fixed_newtype, Fixed};

fixed_newtype!(pub Key, 32, "An AES-256 key.");

pub fn derive_key(material: &[u8]) -> Key {
    Key::new_with(|slot| {
        slot.copy_from_slice(&material[..32]);
    })
}

pub fn derive_bare(material: &[u8]) -> Fixed<[u8; 32]> {
    Fixed::new_with(|slot| {
        slot.copy_from_slice(&material[..32]);
    })
}
