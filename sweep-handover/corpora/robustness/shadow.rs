pub fn build(k: &mut Fixed<[u8; 32]>, extra: &[u8]) -> Vec<u8> {
    let v = k.expose_secret_mut();
    v[0] ^= 1;
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(extra);
    v
}
