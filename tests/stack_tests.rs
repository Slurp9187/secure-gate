#[cfg(feature = "stack")]
#[test]
fn test_stack_key() {
    use secure_gate::stack::key32;
    let key = key32([42u8; 32]);
    assert_eq!(key.as_ref(), &[42u8; 32][..]);
}
