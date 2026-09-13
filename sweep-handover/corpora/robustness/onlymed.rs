fn leak(d: &mut Dynamic<Vec<u8>>, x: &[u8]) {
    d.with_secret_mut(|v| v.extend(x.iter().copied()));
}
