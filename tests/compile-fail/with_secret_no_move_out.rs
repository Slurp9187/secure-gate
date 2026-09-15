//! Moving a secret out of a reveal borrow must not compile.
//!
//! `with_secret` and `expose_secret` lend `&T`. They constrain *access*, not what the
//! body does with the bytes: where the inner type is `Copy`, `*p` silently materialises
//! an owned copy that nothing zeroizes. See "4. Copying the secret out of a reveal
//! borrow" in SECURITY.md.
//!
//! Where the inner type is **not** `Copy`, the borrow checker closes that path for free.
//! This fixture pins that half of the boundary, because SECURITY.md scopes its claim on
//! exactly this behaviour and a scoped claim that stops being true is worse than none.
//!
//! It deliberately says nothing about the copy-*through* forms — `to_vec`, `clone`,
//! `to_string` — which do compile on these same types. Those are pinned from the other
//! side by `tests/reveal_copy_out.rs`, and conflating the two is the mistake this pair
//! of tests exists to prevent.

use secure_gate::{Dynamic, Fixed, RevealSecret};

fn main() {
    // 1. `Vec<u8>` is not `Copy`, so moving out of the shared borrow is E0507.
    let dv: Dynamic<Vec<u8>> = Dynamic::new(vec![1u8, 2, 3]);
    let _moved: Vec<u8> = dv.with_secret(|v| *v);

    // 2. Same for `String`.
    let ds: Dynamic<String> = Dynamic::new(String::from("s"));
    let _moved_s: String = ds.with_secret(|s| *s);

    // 3. `Fixed<T>` has a destructor, and a type with a destructor cannot be `Copy`
    //    (E0184). A nested `Fixed` is therefore immune for the *opposite* reason to the
    //    two above: not because its storage is heap-backed, but because zeroize-on-drop
    //    and `Copy` are mutually exclusive. The same argument covers
    //    `Fixed<zeroize::Zeroizing<T>>`.
    let nested: Fixed<Fixed<[u8; 32]>> = Fixed::new(Fixed::new([5u8; 32]));
    let _moved_n: Fixed<[u8; 32]> = nested.with_secret(|p| *p);

    // 4. `expose_secret` is the same borrow without the closure around it.
    let _moved_e: Vec<u8> = *dv.expose_secret();
}
