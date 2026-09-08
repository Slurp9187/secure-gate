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
// The `format!` call *is* the assertion: `format!("{}", &*encoded)` is the migration
// path the #149 changelog gives callers, so it has to be exercised as a format string.
// `.to_string()`, which clippy suggests, would stop testing that path.
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

    let protected = sample_hex_secret().into_zeroizing();
    assert_eq!(
        &**protected, expected,
        "into_zeroizing must hand over the same bytes, not a fresh String"
    );
    assert_eq!(protected.len(), expected.len());

    // `into_zeroizing` is a *partial* downgrade, and this is the half that is lost:
    // `Zeroizing<String>` derives `Debug`, so the encoded secret prints in the clear.
    // The type's own docs say so. If a future `zeroize` starts redacting, this assert
    // fails and the claim in `EncodedSecret::into_zeroizing` needs rewriting -- that is
    // the point of pinning it, not an accident of the dependency version.
    let rendered = format!("{protected:?}");
    assert!(
        rendered.contains(expected),
        "zeroize no longer prints the wrapped value ({rendered:?});          update the into_zeroizing docs, which promise the opposite"
    );
    assert_ne!(
        rendered, "[REDACTED]",
        "redaction does not survive into_zeroizing -- that is the documented trade"
    );
}
