use secure_gate_0_5_0::{Dynamic, Fixed};

// tests/integration.rs
#[test]
fn it_works() {
    let key = Fixed::new([0u8; 32]);

    // Option 1 — turbofish (recommended)
    let pw = Dynamic::<String>::new("hunter2".to_string());

    // Option 2 — type ascription (also works)
    // let pw: Dynamic<String> = Dynamicnas::new("hunter2".to_string());

    assert_eq!(key.len(), 32);
    assert_eq!(pw.len(), 7);
    assert_eq!(&*pw, "hunter2");

    println!("{key:?}"); // Fixed<[REDACTED]>
    println!("{pw:?}"); // Dynamic<[REDACTED]>
}
