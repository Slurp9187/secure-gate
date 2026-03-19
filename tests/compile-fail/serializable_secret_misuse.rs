// This should fail to compile because BadSecret does not implement SerializableSecret.
// The SerializableSecret marker is the security gate: serialization of wrappers is
// opt-in and deliberate, never automatic — even for types that implement serde::Serialize.
use secure_gate::{Dynamic, Fixed};

#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
struct BadSecret(Vec<u8>);

fn main() {
    // Fails: Dynamic<BadSecret> does not implement Serialize — SerializableSecret not satisfied.
    let _ = serde_json::to_string(&Dynamic::<BadSecret>::new(BadSecret(vec![])));

    // Fails: Fixed<[u8; 32]> does not implement Serialize — SerializableSecret not satisfied.
    let _ = serde_json::to_string(&Fixed::<[u8; 32]>::new([0; 32]));
}
