struct K { v: Vec<u8> }
impl FixedStorage for K {} // sg-sweep: allow - reviewed, K is fine
fn leak(d: &mut Dynamic<Vec<u8>>) { d.with_secret_mut(|v| v.push(1)); } // sg-sweep: allow=SG999
