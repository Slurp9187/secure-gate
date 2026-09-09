use secure_gate::Dynamic;
// The trait is in scope — the failure below proves Dynamic<String> genuinely
// lacks the ToHex impl, not merely that an import is missing.
use secure_gate::ToHex;

fn main() {
    let secret: Dynamic<String> = Dynamic::new(String::from("not_bytes"));
    // Dynamic<String> must NOT have encoding methods — only Dynamic<Vec<u8>> does.
    let _ = secret.to_hex();
}
