//! serde_suite/deserialize.rs — serde deserialize coverage

#[cfg(feature = "serde-deserialize")]
#[test]
fn fixed_deserialize_from_array() {
    use secure_gate::{ExposeSecret, Fixed};
    let result: Fixed<[u8; 4]> = serde_json::from_str("[1,2,3,4]").expect("deserialize");
    assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_deserialize_from_array() {
    use secure_gate::{Dynamic, ExposeSecret};
    let result: Dynamic<Vec<u8>> = serde_json::from_str("[1,2,3,4]").expect("deserialize");
    assert_eq!(result.expose_secret(), &[1, 2, 3, 4]);
}

#[cfg(feature = "serde-deserialize")]
#[test]
fn dynamic_deserialize_from_string() {
    use secure_gate::{Dynamic, ExposeSecret};
    let result: Dynamic<String> = serde_json::from_str("\"hello\"").expect("deserialize");
    assert_eq!(result.expose_secret(), "hello");
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]
#[test]
fn fixed_deserialize_wrong_length() {
    use secure_gate::Fixed;
    let result: Result<Fixed<[u8; 4]>, _> = serde_json::from_str("[1,2,3]");
    assert!(result.is_err());
}
