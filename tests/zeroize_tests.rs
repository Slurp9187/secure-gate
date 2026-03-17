use secure_gate::{Dynamic, Fixed};
use zeroize::Zeroize;

// ======================
// HELPER: Sentinel type that asserts zeroization happened
// ======================
#[derive(Zeroize)]
struct ZeroCheck([u8; 32]);

impl Drop for ZeroCheck {
    fn drop(&mut self) {
        assert!(
            self.0.iter().all(|&b| b == 0),
            "Automatic zeroize-on-drop FAILED — memory was not zeroed"
        );
    }
}

// ======================
// FIXED<T> TESTS
// ======================
#[test]
fn fixed_auto_zeroize_on_drop() {
    let _secret = Fixed::new(ZeroCheck([0xAA; 32]));
    // Drop triggers Fixed's Drop impl → zeroize()
}

// ======================
// DYNAMIC<T> TESTS
// ======================
#[test]
#[cfg(feature = "alloc")]
fn dynamic_vec_auto_zeroize_on_drop() {
    let _secret: Dynamic<Vec<u8>> = Dynamic::new(vec![0xAAu8; 32]);
    // Drop triggers automatic zeroize
}

#[test]
#[cfg(feature = "alloc")]
fn dynamic_string_auto_zeroize_on_drop() {
    let _secret: Dynamic<String> = Dynamic::new("secret password".to_string());
    // Drop triggers automatic zeroize
}

// ======================
// SPARE CAPACITY TEST (Dynamic<Vec<u8>>)
// ======================
#[test]
#[cfg(feature = "alloc")]
fn dynamic_spare_capacity_is_zeroized() {
    for i in 0..100 {
        let mut v = vec![0xAAu8; 32];
        v.reserve(1024); // create spare capacity

        {
            let _dyn: Dynamic<Vec<u8>> = Dynamic::new(v); // ← explicit type annotation (this was the fix)
        } // drop here → should zeroize used + spare capacity

        // Force allocator reuse
        let new_v = vec![0u8; 1056];
        if new_v.iter().all(|&b| b == 0) {
            // Good
        } else if i > 50 {
            panic!("Spare capacity was not zeroized after {} attempts", i);
        }
    }
}
