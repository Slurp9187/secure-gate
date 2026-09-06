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

// Compile-fail tests: `derive: [Clone]` and `derive: [Serialize]` on a generated
// newtype are rejected with an explanatory message. Neither can be forwarded from
// the wrapper (both need a marker impl on the inner type that downstream crates
// cannot write), so a generated impl would have to route around the opt-in marker
// system. The newtype is local to the caller's crate, so callers who genuinely
// want either write the impl by hand where the decision stays visible.
#[cfg(not(miri))]
#[test]
fn newtype_derive_clone_rejected_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_derive_clone_rejected.rs");
}

#[cfg(not(miri))]
#[test]
fn newtype_derive_serialize_rejected_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_derive_serialize_rejected.rs");
}

// Compile-fail test: `dynamic_newtype!` must reject an inner type that is not one
// of the shaped literals (`String`, `Vec<u8>`) rather than silently degrading to
// the reduced generic API. `macro_rules!` matches tokens, not resolved types, so a
// type alias or fully-qualified path cannot reach the shaped arms; the caller must
// either write the literal or opt in with `generic <type>`.
#[cfg(feature = "alloc")]
#[cfg(not(miri))]
#[test]
fn dynamic_newtype_alias_rejected_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/dynamic_newtype_alias_rejected.rs");
}

// Compile-fail test: nominal separation actually holds. Two `fixed_newtype!` types
// of the same `N` are distinct types, so swapping key roles at a call site is
// E0308 — the defect class the macros exist to catch, which `fixed_alias!` cannot.
#[cfg(not(miri))]
#[test]
fn newtype_cross_role_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_cross_role.rs");
}

// Compile-fail test: `fixed_newtype!` rejects `N = 0`, matching `fixed_alias!`.
#[cfg(not(miri))]
#[test]
fn newtype_zero_size_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_zero_size.rs");
}

// Compile-fail test: a user-added `Drop` on a generated newtype makes the wrapped
// field unmovable (E0509), costing `into_inner`. No `Drop` is needed — the wrapper
// runs its own — so this pins the diagnostic for a documented trap.
#[cfg(not(miri))]
#[test]
fn newtype_manual_drop_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_manual_drop.rs");
}

// Compile-fail test (R2): no `From<Wrapper>` is generated, so an alias-typed value
// cannot flow into a newtype through `.into()`. Base access is opt-in via
// `derive: [WrapperAccess]`; without it the only path is a `with_secret` round trip.
#[cfg(feature = "alloc")]
#[cfg(not(miri))]
#[test]
fn newtype_no_from_wrapper_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_no_from_wrapper.rs");
}

// Compile-fail test (R3): generated newtypes do not `Deref` to their base wrapper.
#[cfg(feature = "alloc")]
#[cfg(not(miri))]
#[test]
fn newtype_no_deref_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_no_deref.rs");
}

// Compile-fail test (R5): a hand-written `Serialize` on one newtype does not make a
// sibling newtype over the same base serializable.
#[cfg(all(feature = "alloc", feature = "serde-serialize"))]
#[cfg(not(miri))]
#[test]
fn newtype_sibling_not_serializable_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_sibling_not_serializable.rs");
}

// Compile-fail test (R2, direction): `FromWrapper` and `IntoWrapper` are independent.
// A type with only the outbound token has no `from_wrapper`; one with only the
// inbound token has no `into_wrapper`. A boundary type needs neither; `IntoWrapper`
// on a secret role is a downgrade into the pool of plain aliases sharing its base.
#[cfg(feature = "alloc")]
#[cfg(not(miri))]
#[test]
fn newtype_directional_access_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/newtype_directional_access.rs");
}
