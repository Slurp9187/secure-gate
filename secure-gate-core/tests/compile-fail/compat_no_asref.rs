// Proves that compat::v08::Secret<T> does not implement AsRef<str>.
// Without this guarantee, a function accepting &impl AsRef<str> could receive a
// secret by accident, silently bypassing the explicit-access requirement.
use secure_gate::compat::v08::Secret;

fn needs_str_ref<T: AsRef<str>>(t: &T) {
    let _ = t.as_ref();
}

fn main() {
    let s: Secret<String> = Secret::new(String::from("hunter2"));
    // E0277: Secret<String> does not implement AsRef<str>.
    needs_str_ref(&s);
}
