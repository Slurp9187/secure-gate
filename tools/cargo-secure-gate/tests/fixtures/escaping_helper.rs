// The closure hands its `&mut Vec<u8>` to a helper. Whatever growth happens in
// `fill` is in a body this pass never connects to this buffer.
// Must be reported as unresolved: not an error, and not a silence either.
use secure_gate::Dynamic;

fn fill(out: &mut Vec<u8>, material: &[u8]) {
    out.extend_from_slice(material);
}

pub fn build(material: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::new_with(|v| {
        fill(v, material);
    })
}
