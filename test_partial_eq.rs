use secure_gate::{Fixed, Dynamic};

fn main() {
    // Test Fixed<T> equality
    let fixed1 = Fixed::new([1, 2, 3]);
    let fixed2 = Fixed::new([1, 2, 3]);
    let fixed3 = Fixed::new([1, 2, 4]);

    assert_eq!(fixed1, fixed2);
    assert_ne!(fixed1, fixed3);
    println!("Fixed<T> equality works!");

    // Test Dynamic<T> equality
    let dyn1: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    let dyn2: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
    let dyn3: Dynamic<Vec<u8>> = vec![1, 2, 4].into();

    assert_eq!(dyn1, dyn2);
    assert_ne!(dyn1, dyn3);
    println!("Dynamic<T> equality works!");

    // Test with strings
    let str1: Dynamic<String> = "hello".into();
    let str2: Dynamic<String> = "hello".into();
    let str3: Dynamic<String> = "world".into();

    assert_eq!(str1, str2);
    assert_ne!(str1, str3);
    println!("Dynamic<String> equality works!");

    println!("All PartialEq tests passed!");
}
