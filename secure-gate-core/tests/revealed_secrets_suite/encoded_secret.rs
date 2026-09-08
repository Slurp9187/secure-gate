#![cfg(feature = "alloc")]

use secure_gate::EncodedSecret;

#[cfg(feature = "encoding-hex")]
use secure_gate::{Fixed, ToHex};

#[cfg(feature = "encoding-hex")]
fn sample_hex_secret() -> EncodedSecret {
    Fixed::new([0xDEu8, 0xAD, 0xBE, 0xEF]).to_hex()
}

#[test]
fn encoded_secret_needs_drop() {
    assert!(core::mem::needs_drop::<EncodedSecret>());
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_debug_is_redacted() {
    let encoded = sample_hex_secret();
    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
    assert_eq!(format!("{encoded:#?}"), "[REDACTED]");
}

// `EncodedSecret` has no `Display`: `{}` on it is a compile error, so a caller who
// learned from `{:?}` that the type is log-safe cannot be surprised by `{}`. Writing the
// value out stays available, but must name the deref. The compile-fail counterpart is
// tests/compile-fail/encoded_secret_no_display.rs.
#[cfg(feature = "encoding-hex")]
#[test]
// `format!("{}", &*encoded)` is the documented migration from the removed `Display`;
// clippy's `to_string()` suggestion is a different path and not what this asserts.
#[allow(clippy::useless_format)]
fn encoded_secret_content_requires_explicit_deref() {
    let encoded = sample_hex_secret();
    assert_eq!(format!("{}", &*encoded), "deadbeef");
    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_deref_to_str() {
    let encoded = sample_hex_secret();
    assert_eq!(&*encoded, "deadbeef");
    assert_eq!(encoded.len(), 8);
    assert!(!encoded.is_empty());
}

/// `Deref<Target = str>` is the single door out; the `AsRef<str>` / `AsRef<[u8]>`
/// impls were removed because they reached nothing `Deref` does not.
#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_deref_is_the_only_door() {
    let encoded = sample_hex_secret();

    // Coercion, explicit reborrow, and inherent `str` methods all still work.
    let as_str: &str = &encoded;
    assert_eq!(as_str, "deadbeef");
    assert_eq!(&*encoded, "deadbeef");
    assert_eq!(encoded.len(), 8);
    assert!(encoded.starts_with("dead"));
    assert_eq!(encoded.as_bytes(), b"deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_into_inner_returns_string() {
    let encoded = sample_hex_secret();
    let plain = encoded.into_inner();
    assert_eq!(plain, "deadbeef");
}

#[cfg(feature = "encoding-hex")]
#[test]
// See above: the `format!("{}", &*encoded)` form is the point of the assertion.
#[allow(clippy::useless_format)]
fn encoded_secret_empty_string() {
    let empty: [u8; 0] = [];
    let encoded = empty.to_hex();

    assert_eq!(format!("{encoded:?}"), "[REDACTED]");
    assert_eq!(format!("{}", &*encoded), "");
    assert_eq!(&*encoded, "");
    assert!(encoded.is_empty());

    let as_str: &str = &encoded;
    assert_eq!(as_str, "");
    assert_eq!(encoded.as_bytes(), b"");

    let encoded = empty.to_hex();
    let plain = encoded.into_inner();
    assert_eq!(plain, "");

    let encoded = empty.to_hex();
    let protected = encoded.into_zeroizing();
    assert_eq!(&*protected, "");
}

// The empty case above is the degenerate one: `assert_eq!(&*protected, "")` would still
// pass if `into_zeroizing` threw the buffer away and returned `Zeroizing::default()`.
// This is the case that pins the content. The wipe-on-drop half of the contract needs an
// allocator to observe, so it lives in tests/heap_zeroize.rs
// (`check_into_zeroizing_string_zeroed`); the two together cover the method.
#[cfg(feature = "encoding-hex")]
#[test]
fn encoded_secret_into_zeroizing_carries_the_content() {
    let expected = "deadbeef";

    let encoded = sample_hex_secret();
    assert_eq!(
        &*encoded, expected,
        "precondition: the wrapper holds the encoding"
    );

    // Content, and then the stronger claim: it is the *same* buffer, not a copy of it.
    // Equality alone would pass for an implementation that cloned, so the pointer is what
    // makes "hands over" true rather than merely plausible. Same pattern as
    // `dynamic_into_inner_moves_without_copying` in tests/zeroize_tests.rs.
    let encoded = sample_hex_secret();
    let buffer_before = encoded.as_ptr();
    let protected = encoded.into_zeroizing();
    assert_eq!(
        &**protected, expected,
        "into_zeroizing must hand over the encoding, not an empty or default String"
    );
    assert_eq!(
        protected.as_ptr(),
        buffer_before,
        "into_zeroizing copied the buffer instead of moving it"
    );

    // `into_zeroizing` is a *partial* downgrade, and this is the half that is lost:
    // `Zeroizing<String>` derives `Debug`, so the encoded secret prints in the clear --
    // emphatically not `[REDACTED]`. The type's own docs promise exactly that. If a
    // future `zeroize` starts redacting, this assert fails and the claim in
    // `EncodedSecret::into_zeroizing` needs rewriting; that is the point of pinning it,
    // not an accident of the dependency version.
    //
    // The rendering is deliberately reduced to a bool before the assert, and never
    // interpolated into the failure message. It is a plaintext copy derived from the
    // wrapper, and formatting one into a panic is the precise pattern this crate tells
    // callers to avoid; CodeQL's `rust/cleartext-logging` rule flags it, correctly, even
    // though the fixture here is the literal `0xDEADBEEF`. Keep it out of the message.
    let prints_in_clear = format!("{protected:?}").contains(expected);
    assert!(
        prints_in_clear,
        "zeroize's Debug no longer prints the value in the clear; fix into_zeroizing's docs"
    );
}
