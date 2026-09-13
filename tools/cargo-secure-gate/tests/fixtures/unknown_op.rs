// The op vocabulary is a closed list, so an author naming their own method walks
// straight through it. A measured leak -- `buf.put(b)` in a loop, >=960 bytes
// across >=4 blocks -- was reported as nothing at all, and worse, scanning the
// file WITHOUT its declaration said "1 not checked" while adding the declaration
// made it silent. More information must never buy less signal.
use secure_gate::Dynamic;

trait Sink {
    fn stuff_in(&mut self, b: u8);
}

// Unknown method on the buffer: not checked, never silence.
pub fn custom(bytes: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::new_with(|v| {
        for &b in bytes {
            v.stuff_in(b);
        }
    })
}

// Reads do not count as unknown, so a correctly presized fill stays clean.
pub fn reads_are_not_unknown(bytes: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::new_with(|v| {
        v.reserve_exact(bytes.len());
        v.extend_from_slice(bytes);
        let _ = v.len();
    })
}
