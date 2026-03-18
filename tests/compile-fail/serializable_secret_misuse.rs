use secure_gate::{Dynamic, Fixed};

// This should fail to compile without the SerializableSecret marker
#[derive(serde::Serialize, serde::Deserialize)]
struct BadSecret(Vec<u8>);

fn main() {
    let _ = serde_json::to_string(&Dynamic::<BadSecret>::new(BadSecret(vec![])));
    let _ = serde_json::to_string(&Fixed::<[u8; 32]>::new([0; 32]));
}
