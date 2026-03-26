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

// ── secrecy-compat explicit-access enforcement (issue_104 §2) ────────────────

/// Secret<T> must not implement Deref — no accidental &T coercion through *.
#[cfg(feature = "secrecy-compat")]
#[cfg(not(miri))]
#[test]
fn compat_no_deref() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/compat_no_deref.rs");
}

/// Secret<T> must not implement AsRef<str> — no silent coercion to string slices.
#[cfg(feature = "secrecy-compat")]
#[cfg(not(miri))]
#[test]
fn compat_no_asref() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/compat_no_asref.rs");
}

/// Debug for Secret<T> requires T: DebugSecret — types must opt-in to prevent
/// accidental secret exposure through logging / tracing / panic messages.
#[cfg(feature = "secrecy-compat")]
#[cfg(not(miri))]
#[test]
fn compat_no_debug_without_marker() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/compat_no_debug_without_marker.rs");
}
