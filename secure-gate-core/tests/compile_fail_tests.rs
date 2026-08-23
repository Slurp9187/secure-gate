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

// Compile-fail test: `EncodedSecret` must not implement `Display`. Debug redaction
// teaches callers the type is log-safe; a transparent `Display` on the same type would
// punish exactly those callers. `&*encoded` remains available for intentional writes.
#[cfg(all(feature = "alloc", feature = "encoding-hex"))]
#[cfg(not(miri))]
#[test]
fn encoded_secret_no_display_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/encoded_secret_no_display.rs");
}

// Compile-fail test: `SecretLen` must stay narrow. `RevealSecret` covers every
// inner type (including local user-defined ones), but a custom inner type has
// no meaningful length — `len()` on it must not compile even with `SecretLen`
// in scope.
#[cfg(not(miri))]
#[test]
fn custom_inner_no_len_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/custom_inner_no_len.rs");
}
