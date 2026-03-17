use secure_gate::{Dynamic, Fixed};
use zeroize::Zeroize;

// Helper type that asserts zeroization happened in its Drop
#[derive(Zeroize)]
struct ZeroCheck([u8; 32]);

impl Drop for ZeroCheck {
    fn drop(&mut self) {
        // This runs AFTER Fixed/Dynamic's Drop has zeroized the inner value
        assert!(
            self.0.iter().all(|&b| b == 0),
            "Automatic zeroize-on-drop FAILED — memory was not zeroed"
        );
    }
}

#[test]
fn fixed_auto_zeroize_on_drop() {
    // When _secret goes out of scope, Fixed's Drop runs → calls zeroize()
    let _secret = Fixed::new(ZeroCheck([0xAA; 32]));
    // ZeroCheck's Drop then asserts it was zeroed
}

#[test]
#[cfg(feature = "alloc")]
fn dynamic_vec_auto_zeroize_on_drop() {
    let _secret: Dynamic<Vec<u8>> = Dynamic::new(vec![0xAAu8; 32]);
    // Dynamic's Drop runs → zeroizes the Vec (including spare capacity)
}

#[test]
#[cfg(feature = "alloc")]
fn dynamic_string_auto_zeroize_on_drop() {
    let _secret: Dynamic<String> = Dynamic::new("secret".to_string());
    // Same as above — String is zeroized on drop
}
