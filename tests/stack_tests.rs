#[cfg(feature = "stack")]
#[test]
fn test_stack_key() {
    use secure_gate::stack::key32;
    let key = key32([42u8; 32]);
    assert_eq!(key.as_ref(), &[42u8; 32][..]);
}

#[cfg(feature = "stack")]
#[test]
fn test_secure_key_alias_stack() {
    use secure_gate::stack::key32;
    use secure_gate::SecureKey32;
    let key: SecureKey32 = key32([42u8; 32]);
    assert_eq!(key.as_ref(), &[42u8; 32][..]);
}

#[cfg(not(feature = "stack"))]
#[test]
fn test_secure_key_alias_heap() {
    use secure_gate::Secure;
    use secure_gate::SecureKey32;
    let key: SecureKey32 = Secure::new([42u8; 32]);
    assert_eq!(key.expose(), &[42u8; 32][..]);
}
