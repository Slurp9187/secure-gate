// ==========================================================================
// tests/compile_fail_tests.rs
// ==========================================================================
// Compile-fail tests using trybuild — verifies that certain code patterns
// are properly rejected at compile time for security reasons.
//
// To regenerate .stderr files after a toolchain upgrade:
//   TRYBUILD=overwrite cargo test compile_fail

#[test]
#[cfg(not(miri))]
fn fixed_alias_zero_size_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/fixed_alias_zero_size.rs");
}

// Compile-fail test for SerializableSecret opt-in requirement.
// Skipped under Miri because trybuild spawns cargo subprocesses (forbidden syscalls).
#[cfg(all(feature = "alloc", feature = "serde-serialize"))]
#[cfg(not(miri))]
#[test]
fn serializable_secret_misuse() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/serializable_secret_misuse.rs");
}

// Compile-fail test: Dynamic<String> must not expose encoding methods (hex, base64, etc.)
// These methods are intentionally defined only on Dynamic<Vec<u8>>.
#[cfg(all(feature = "alloc", feature = "encoding-hex"))]
#[cfg(not(miri))]
#[test]
fn dynamic_string_no_hex_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/dynamic_string_no_hex.rs");
}
