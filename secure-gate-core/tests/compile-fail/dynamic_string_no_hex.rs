use secure_gate::Dynamic;
// The trait is in scope — the failure below proves Dynamic<String> genuinely
// lacks the ToHex impl, not merely that an import is missing.
use secure_gate::ToHex;

fn main() {
    // Exercise the trait on a byte-shaped source first. A call that fails to resolve
    // does not count as a use, so without this the import is `unused_imports` under
    // this branch's `-D warnings` CI and that lands in the snapshot. It also makes the
    // claim above literally true rather than merely intended.
    let _ = [0u8; 4].to_hex();

    let secret: Dynamic<String> = Dynamic::new(String::from("not_bytes"));
    // Dynamic<String> must NOT have encoding methods — only Dynamic<Vec<u8>> does.
    let _ = secret.to_hex();
}
