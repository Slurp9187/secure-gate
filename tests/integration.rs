// tests/integration.rs
// Final test suite — proves everything works

use secure_gate_0_5_0::{fixed_alias, secure, Dynamic, Fixed};

#[test]
fn basic_usage_and_deref() {
    let mut key = Fixed::new([0u8; 32]);
    let mut pw = Dynamic::<String>::new("hunter2".to_string());

    assert_eq!(key.len(), 32);
    assert_eq!(pw.len(), 7);
    assert_eq!(&*pw, "hunter2");

    pw.push('!');
    key[0] = 1;

    assert_eq!(&*pw, "hunter2!");
    assert_eq!(key[0], 1);

    let s: &str = &pw;
    assert_eq!(s, "hunter2!");
}

#[test]
fn fixed_is_truly_zero_cost() {
    let key = Fixed::new([0u8; 32]);
    assert_eq!(core::mem::size_of_val(&key), 32);
}

#[test]
fn macros_work_perfectly() {
    fixed_alias!(MyKey, 32); // ← updated
    let k1: MyKey = [42u8; 32].into();
    let k2 = MyKey::new([42u8; 32]);
    assert_eq!(k1.0, k2.0);

    let iv = secure!([u8; 16], [1u8; 16]);
    assert_eq!(iv.0, [1u8; 16]);
}

#[test]
fn debug_is_redacted() {
    let key = Fixed::new([0u8; 32]);
    let pw = Dynamic::<String>::new("hunter2".to_string());

    let key_debug = format!("{key:?}");
    let pw_debug = format!("{pw:?}");

    assert_eq!(key_debug, "[REDACTED]");
    assert_eq!(pw_debug, "[REDACTED]");

    let key_pretty = format!("{key:#?}");
    let pw_pretty = format!("{pw:#?}");

    assert_eq!(key_pretty, "[REDACTED]");
    assert_eq!(pw_pretty, "[REDACTED]");
}

#[test]
fn clone_dynamic_is_isolated() {
    let pw1 = Dynamic::<String>::new("original".to_string());
    let pw2 = pw1.clone();

    let mut pw1_mut = pw1.clone();
    pw1_mut.push('!');

    assert_eq!(&*pw1, "original");
    assert_eq!(&*pw2, "original");
    assert_eq!(&*pw1_mut, "original!");
}

#[test]
fn into_inner_extracts() {
    let key = Fixed::new([1u8; 32]);
    assert_eq!(key.into_inner(), [1u8; 32]);

    let pw = Dynamic::<String>::new("secret".to_string());
    let boxed = pw.into_inner();
    assert_eq!(&*boxed, "secret");
}

#[cfg(feature = "zeroize")]
#[test]
fn zeroize_on_drop_wipes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WIPED: AtomicBool = AtomicBool::new(false);

    #[derive(zeroize::ZeroizeOnDrop)]
    struct MySecret([u8; 32]);

    impl zeroize::Zeroize for MySecret {
        fn zeroize(&mut self) {
            WIPED.store(true, Ordering::SeqCst);
            self.0.zeroize();
        }
    }

    {
        let _key = Fixed::new(MySecret([42u8; 32]));
        let _pw = Dynamic::new(MySecret([42u8; 32]));
    }

    assert!(
        WIPED.load(Ordering::SeqCst),
        "Zeroize was not called on drop"
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_roundtrip_fixed() {
    fixed_alias!(SerdeKey, 32); // ← updated
    let key = SerdeKey::new([42u8; 32]);
    let json = serde_json::to_string(&key).unwrap();
    let key2: SerdeKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key.0, key2.0);
}

#[cfg(feature = "serde")]
#[test]
fn serde_dynamic_serializes() {
    let pw = Dynamic::<String>::new("hunter2".to_string());
    let json = serde_json::to_string(&pw).unwrap();
    assert_eq!(json, "\"hunter2\"");
}
