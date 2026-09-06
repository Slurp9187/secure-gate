//! R5: opting one newtype into `Serialize` must not opt in its siblings.
//!
//! `PublicId` and `FileId` share a base (`Dynamic<String>`). A hand-written
//! `Serialize` for `PublicId` routes through `with_secret`; `FileId` gains
//! nothing — it is a different type, and the base never implements
//! `Serialize` (its inner `String` cannot be `SerializableSecret` downstream).
use secure_gate::{RevealSecret, dynamic_newtype};
use serde::{Serialize, Serializer};

dynamic_newtype!(pub PublicId, String);
dynamic_newtype!(pub FileId, String);

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.with_secret(|v| v.serialize(s))
    }
}

fn main() {
    let public = PublicId::new("safe-to-expose");
    let _ = serde_json::to_string(&public).unwrap();

    let file = FileId::new("never-crosses-ipc");
    let _ = serde_json::to_string(&file).unwrap(); // must not compile
}
