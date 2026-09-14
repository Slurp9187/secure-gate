// sg-sweep: ignore-file
struct K { v: Vec<u8> }
impl FixedStorage for K {}
fn leak(d: &mut Dynamic<Vec<u8>>) { d.with_secret_mut(|v| v.push(1)); }
