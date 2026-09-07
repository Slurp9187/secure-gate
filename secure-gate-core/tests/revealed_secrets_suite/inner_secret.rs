use secure_gate::{Fixed, InnerSecret, RevealSecret};

#[cfg(feature = "alloc")]
use secure_gate::Dynamic;

fn sample_fixed_inner_secret() -> InnerSecret<[u8; 4]> {
    Fixed::new([0xDEu8, 0xAD, 0xBE, 0xEF]).into_inner()
}

#[test]
fn inner_secret_needs_drop() {
    assert!(core::mem::needs_drop::<InnerSecret<[u8; 4]>>());
}

#[test]
fn inner_secret_debug_is_redacted() {
    let inner = sample_fixed_inner_secret();
    assert_eq!(format!("{inner:?}"), "[REDACTED]");
    assert_eq!(format!("{inner:#?}"), "[REDACTED]");
}

#[test]
fn inner_secret_deref_array_payload() {
    let inner = sample_fixed_inner_secret();
    assert_eq!(&*inner, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn inner_secret_into_zeroizing_array_payload() {
    let inner = sample_fixed_inner_secret();
    let protected = inner.into_zeroizing();
    assert_eq!(&*protected, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_dynamic_string_payload() {
    let secret = Dynamic::<String>::new("hunter2".to_string());
    let inner: InnerSecret<String> = secret.into_inner();

    assert_eq!(format!("{inner:?}"), "[REDACTED]");
    assert_eq!(&*inner, "hunter2");
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_dynamic_vec_payload() {
    let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
    let inner: InnerSecret<Vec<u8>> = secret.into_inner();

    assert_eq!(format!("{inner:?}"), "[REDACTED]");
    assert_eq!(&*inner, &[1, 2, 3, 4]);
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_empty_string_edge_case() {
    let secret = Dynamic::<String>::new(String::new());
    let inner: InnerSecret<String> = secret.into_inner();

    assert_eq!(&*inner, "");
    assert!(inner.is_empty());

    let protected = inner.into_zeroizing();
    assert_eq!(&*protected, "");
    assert!(protected.is_empty());
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_empty_vec_edge_case() {
    let secret: Dynamic<Vec<u8>> = Dynamic::new(Vec::new());
    let inner: InnerSecret<Vec<u8>> = secret.into_inner();

    assert!(inner.is_empty());

    let protected = inner.into_zeroizing();
    assert!(protected.is_empty());
}

// --- Clone: the method-resolution hole ------------------------------------
//
// Before `impl Clone for InnerSecret<T>`, `inner.clone()` compiled but autoderefed to
// `T::clone`, yielding a bare unprotected `T` from a call site that names no exit.
// These tests pin the resolution to `InnerSecret` and are the regression guard.

#[test]
fn inner_secret_clone_resolves_to_wrapper_not_inner_array() {
    let inner = sample_fixed_inner_secret();
    // Type annotation is the assertion: if `clone` autoderefs to `<[u8; 4]>::clone`,
    // this is a type error.
    let cloned: InnerSecret<[u8; 4]> = inner.clone();
    assert_eq!(&*cloned, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(&*inner, &*cloned);
}

#[test]
fn inner_secret_clone_stays_redacted_and_drops_independently() {
    let inner = sample_fixed_inner_secret();
    let cloned = inner.clone();
    assert_eq!(format!("{cloned:?}"), "[REDACTED]");
    assert!(core::mem::needs_drop::<InnerSecret<[u8; 4]>>());
    drop(inner);
    // The clone owns its own buffer and survives the original's zeroizing drop.
    assert_eq!(&*cloned, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_clone_resolves_to_wrapper_not_inner_string() {
    let inner: InnerSecret<String> = Dynamic::<String>::new("hunter2".to_string()).into_inner();
    // The original footgun: this used to bind a naked `String`.
    let cloned: InnerSecret<String> = inner.clone();
    assert_eq!(&**cloned, "hunter2");
    assert_eq!(format!("{cloned:?}"), "[REDACTED]");
}

#[cfg(feature = "alloc")]
#[test]
fn inner_secret_clone_is_not_gated_on_cloneable_secret() {
    // `String` deliberately does not implement `CloneableSecret` (orphan rule), so
    // `Dynamic<String>` itself is not cloneable. The extracted `InnerSecret` still is:
    // gating here would only restore the silent `String::clone` fallthrough.
    let inner: InnerSecret<String> = Dynamic::<String>::new("hunter2".to_string()).into_inner();
    let _cloned: InnerSecret<String> = inner.clone();
}

/// The owned handoff: one call from `InnerSecret` to the plain value, no clone.
///
/// Before this existed, `InnerSecret` was a dead end — `into_zeroizing()` returns a
/// `Zeroizing<T>`, which deliberately exposes no way to move its contents out, so the
/// only route to an owned value was cloning through the deref.
#[cfg(feature = "alloc")]
#[test]
fn inner_secret_into_inner_moves_the_value_out() {
    use secure_gate::{Dynamic, Fixed, RevealSecret};

    // Heap value: the returned Vec must be the same allocation, not a copy.
    let original = vec![1u8, 2, 3, 4];
    let ptr = original.as_ptr();
    let secret: Dynamic<Vec<u8>> = Dynamic::new(original);
    // One call from the wrapper — the handoff people actually reach for.
    let v: Vec<u8> = secret.into_plain();
    assert_eq!(v, vec![1, 2, 3, 4]);
    assert_eq!(v.as_ptr(), ptr, "value was copied instead of moved");

    // Stack value, including an array size past `Default`'s 32-element limit.
    let key: [u8; 64] = Fixed::new([0xABu8; 64]).into_plain();
    assert_eq!(key, [0xABu8; 64]);

    // String inner type.
    // The two-step form still works when you already hold an InnerSecret.
    let s: String = Dynamic::<String>::new(String::from("hunter2"))
        .into_inner()
        .into_plain();
    assert_eq!(s, "hunter2");
}

/// `into_zeroizing` still works and still protects — the new escape hatch is additive.
#[cfg(feature = "alloc")]
#[test]
fn inner_secret_into_zeroizing_still_available() {
    use secure_gate::{Dynamic, RevealSecret};

    let z = Dynamic::<Vec<u8>>::new(vec![9u8; 8])
        .into_inner()
        .into_zeroizing();
    assert_eq!(&*z, &vec![9u8; 8]);
}
