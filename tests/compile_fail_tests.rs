// ==========================================================================
// tests/compile_fail_tests.rs
// ==========================================================================
// Compile-fail tests using trybuild - verifies that certain code patterns
// are properly rejected at compile time for security reasons.

#[test]
#[cfg(not(miri))]
fn fixed_alias_zero_size_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/fixed_alias_zero_size.rs");
}

// // This case asserts serde-bound misuse diagnostics for wrapper serialization.
// // It requires both alloc-backed Dynamic<T> and serde Serialize impls to exist.
// #[cfg(all(feature = "alloc", feature = "serde-serialize"))]
// #[test]
// fn serializable_secret_misuse() {
//     let t = trybuild::TestCases::new();
//     t.compile_fail("tests/compile-fail/serializable_secret_misuse.rs");
// }
