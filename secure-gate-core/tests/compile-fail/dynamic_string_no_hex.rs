use secure_gate::Dynamic;

fn main() {
    let secret: Dynamic<String> = Dynamic::new(String::from("not_bytes"));
    // Dynamic<String> must NOT have encoding methods — only Dynamic<Vec<u8>> does.
    let _ = secret.to_hex();
}
