#[cfg(feature = "rand")]
use secure_gate::random::{DynamicRandom, FixedRandom};

#[cfg(feature = "encoding-hex")]
use secure_gate::encoding::hex::HexString;

use secure_gate::{ExposeSecret, ExposeSecretMut};

#[cfg(feature = "encoding-base64")]
use secure_gate::encoding::base64::Base64String;

#[cfg(feature = "encoding-bech32")]
use secure_gate::encoding::bech32::Bech32String;

#[test]
fn test_fixed_read_only() {
    let secret = secure_gate::Fixed::new([1u8, 2, 3, 4]);
    let exposed: &[u8; 4] = secret.expose_secret();
    assert_eq!(exposed, &[1, 2, 3, 4]);
}

#[test]
fn test_dynamic_read_only() {
    let secret: secure_gate::Dynamic<Vec<u8>> = secure_gate::Dynamic::new(vec![1u8, 2, 3, 4]);
    let exposed = secret.expose_secret().as_slice();
    assert_eq!(exposed, &[1, 2, 3, 4]);
}

#[test]
fn test_fixed_mutable() {
    let mut secret = secure_gate::Fixed::new([1u8, 2, 3, 4]);
    {
        let exposed: &mut [u8; 4] = secret.expose_secret_mut();
        exposed[0] = 42;
    }
    assert_eq!(secret.expose_secret(), &[42, 2, 3, 4]);
}

#[test]
fn test_dynamic_mutable() {
    let mut secret: secure_gate::Dynamic<Vec<u8>> = secure_gate::Dynamic::new(vec![1u8, 2, 3, 4]);
    {
        let exposed: &mut Vec<u8> = secret.expose_secret_mut();
        exposed[0] = 42;
    }
    assert_eq!(secret.expose_secret().as_slice(), &[42, 2, 3, 4]);
}

#[cfg(feature = "rand")]
#[test]
fn test_fixed_random_read_only() {
    let secret = FixedRandom::<32>::generate();
    let exposed: &[u8] = secret.expose_secret();
    assert_eq!(exposed.len(), 32);
}

#[cfg(feature = "rand")]
#[test]
fn test_dynamic_random_read_only() {
    let secret = DynamicRandom::generate(32);
    let exposed: &[u8] = secret.expose_secret();
    assert_eq!(exposed.len(), 32);
}

#[cfg(feature = "encoding-hex")]
#[test]
fn test_hex_string_read_only() {
    let secret = HexString::new("deadbeef".to_string()).unwrap();
    let exposed: &str = secret.expose_secret();
    assert_eq!(exposed, "deadbeef");
}

#[cfg(feature = "encoding-base64")]
#[test]
fn test_base64_string_read_only() {
    let secret = Base64String::new("ZGVhZGJlZWY".to_string()).unwrap();
    let exposed: &str = secret.expose_secret();
    assert_eq!(exposed, "ZGVhZGJlZWY");
}

#[cfg(feature = "encoding-bech32")]
#[test]
fn test_bech32_string_read_only() {
    let secret =
        Bech32String::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()).unwrap();
    let exposed: &str = secret.expose_secret();
    assert!(exposed.contains("bc1q"));
}
