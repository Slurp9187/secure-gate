extern crate alloc;

use alloc::string::String;
use secure_gate::Dynamic;
use secure_gate::Fixed;

fn main() {
    let fixed = Fixed::new([0u8; 32]);
    let _ = serde_json::to_string(&fixed);

    let dyn_str = Dynamic::new(String::from("test"));
    let _ = serde_json::to_string(&dyn_str);
}
