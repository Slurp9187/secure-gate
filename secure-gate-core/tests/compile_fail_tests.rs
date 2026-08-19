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

// Compile-fail tests: the secret wrappers must not implement `Deref` or `AsRef`.
//
// This is the crate's load-bearing "no implicit access" claim, so it is enforced by the
// compiler rather than only asserted in SECURITY.md. The boundary is deliberate: the
// output wrappers returned by extraction (`InnerSecret`, `EncodedSecret`) *do* deref.
// See "Where accident-prevention ends" in the crate docs.
#[cfg(not(miri))]
#[test]
fn fixed_no_deref_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/fixed_no_deref.rs");
}

#[cfg(feature = "alloc")]
#[cfg(not(miri))]
#[test]
fn dynamic_no_deref_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/dynamic_no_deref.rs");
}
