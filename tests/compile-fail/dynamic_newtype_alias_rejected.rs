//! A type alias must not silently fall through to the reduced generic API.
//!
//! `String` and `Vec<u8>` are matched as literal tokens, so `MyStr` cannot
//! reach the shaped arms. Before the `generic` marker existed this quietly
//! produced a newtype short of the shaped `String` arm: `SecretLen` and
//! `From<&str>`. It must now be a compile error naming the fix.
use secure_gate::dynamic_newtype;

type MyStr = String;

dynamic_newtype!(pub Password, MyStr);

fn main() {}
