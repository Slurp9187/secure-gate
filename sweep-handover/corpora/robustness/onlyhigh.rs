fn leak(d: &mut Dynamic<Vec<u8>>, b: u8) {
    d.with_secret_mut(|v| v.push(b));
}
