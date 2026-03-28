// Proves that compat::v08::Secret<T> does not implement Deref or DerefMut.
// Users cannot accidentally obtain a reference to the inner value through coercion —
// they must call expose_secret() explicitly, making every access auditable.
use secure_gate_compat::compat::v08::Secret;

fn main() {
    let s: Secret<String> = Secret::new(String::from("hunter2"));
    // E0614: Secret<String> does not implement Deref — no accidental &String coercion.
    let _ = *s;
}
