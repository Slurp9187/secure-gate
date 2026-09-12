//! Lifecycle trace for stack-backed newtypes: creation, access, mutation, handoff, end.
//!
//! `tests/heap_zeroize.rs` and `tests/lifecycle_trace_heap.rs` instrument the allocator
//! and can therefore watch a `Dynamic` secret's buffer being wiped before it is freed. A
//! `Fixed` newtype never reaches the allocator, so that instrument cannot see it at all,
//! and this file is deliberately the complement: no `#[global_allocator]`, nothing
//! touching global process state, so it runs in parallel with every other binary in the
//! suite — and so the parts of the lifecycle an allocator cannot reach are traced here.
//!
//! What is left to trace without an allocator is the storage itself and every
//! transition into and out of it. Three techniques are used, in order of preference:
//!
//! 1. **Address identity.** Every read and write tier is asked for the address it
//!    reaches, and those addresses are compared. This is what distinguishes "the API
//!    returned the right bytes" from "the API reached the wrapper's own storage" — a
//!    forwarding layer that copied the secret into a temporary would return equal
//!    bytes from a different address. Addresses are compared, never dereferenced.
//! 2. **A recording inner type.** `Traced` records, inside its own `Zeroize` impl, the
//!    value that was present when the wipe happened. That makes the otherwise invisible
//!    end of life observable: it shows whether a dropped wrapper wiped the real secret
//!    or the inert sentinel that `into_inner` left in its place. No read-after-drop and
//!    no `unsafe`, in the style of `tests/zeroize_tests.rs`.
//! 3. **Value assertions**, for the parts of the contract that are genuinely about
//!    values — that a round trip preserves a payload, that a mutation landed and
//!    touched nothing else.
//!
//! Where the contract is not observable from safe code, the test says so in a comment
//! rather than asserting a weaker thing and implying it proves the stronger one.
//!
//! The shapes below cover every `fixed_newtype!` front end plus a plain `type` alias,
//! because the alias-versus-newtype contrast is the whole point of the nominal types
//! and belongs next to the behaviour it is contrasted with.

use core::cell::RefCell;
use secure_gate::{
    Fixed, FromSliceError, RevealSecret, RevealSecretMut, SecretLen, SentinelValue, fixed_newtype,
};
use zeroize::Zeroize;

fixed_newtype!(pub K32, 32, "A 32-byte role with the full byte-array surface.");
// The generic arm: an ML-KEM secret polynomial is `[i16; 256]`, as secret as the key it
// came from and not a byte array.
fixed_newtype!(pub Poly, generic [i16; 256], "A non-byte inner type on the reduced surface.");
fixed_newtype!(pub Opened, 32, derive: [WrapperAccess]);
fixed_newtype!(pub Inbound, 32, derive: [FromWrapper]);
fixed_newtype!(pub Outbound, 32, derive: [IntoWrapper]);
// The generic arm again, this time with the outbound token, for the one test below that
// needs to reach the base wrapper of a non-byte inner type.
fixed_newtype!(pub PolyOut, generic [i16; 256], derive: [IntoWrapper]);

/// A plain `type` alias over the same base wrapper — a synonym, not a new type.
type Alias = Fixed<[u8; 32]>;

const SECRET: [u8; 32] = [0xA5; 32];

// ---------------------------------------------------------------------------
// A recording inner type, for the transitions that are otherwise invisible
// ---------------------------------------------------------------------------

thread_local! {
    /// Every value `Traced::zeroize` found in place, in call order.
    ///
    /// Thread-local rather than `static`: libtest gives each `#[test]` its own thread,
    /// and both the wipe and the assertion happen on that thread, so no two tests in
    /// this binary can see each other's records. Nothing here is process-global.
    static WIPED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// An inner type that records the value present at the moment it is wiped.
///
/// It has no `Drop` impl of its own, so the only thing that can record is a `Zeroize`
/// call — which for these wrappers means `Fixed::drop`, or an explicit `.zeroize()`.
/// That is what makes the record unambiguous: one entry per wipe, carrying the value
/// that was actually sitting in the wrapper's storage at the time.
#[derive(Debug, PartialEq, Eq)]
pub struct Traced(u64);

impl Zeroize for Traced {
    fn zeroize(&mut self) {
        let found = self.0;
        WIPED.with_borrow_mut(|w| w.push(found));
        self.0 = 0;
    }
}

/// The inert placeholder `into_inner` leaves behind. Zero is not a representable
/// secret in this test's vocabulary, so seeing it in a wipe record identifies the
/// sentinel unambiguously.
impl SentinelValue for Traced {
    fn sentinel_value() -> Self {
        Self(0)
    }
}

fixed_newtype!(pub Handoff, generic Traced);

/// Drains the wipe record for the current test.
fn wipes() -> Vec<u64> {
    WIPED.with_borrow_mut(core::mem::take)
}

// ---------------------------------------------------------------------------
// 1. Creation into access
// ---------------------------------------------------------------------------

/// Both read tiers of a freshly built newtype reach the wrapper's own storage, and
/// reading does not disturb it.
///
/// The bytes coming back are the cheap half of this property. The addresses are the
/// other half: `with_secret` is documented as a scoped borrow, not a scoped copy, so
/// the closure must be handed the same storage `expose_secret` names. A forwarding
/// layer that materialized a temporary would satisfy a bytes-only assertion while
/// leaving a second copy of the secret on the stack for nothing to wipe.
#[test]
fn every_read_tier_reaches_the_same_storage_and_leaves_it_intact() {
    let key = K32::new(SECRET);

    let direct: *const [u8; 32] = key.expose_secret();
    // The closure cannot *return* its borrow — `with_secret`'s scoping guarantee is
    // exactly that, and the compiler rejects `|bytes| bytes` here — so the address is
    // laundered out as a raw pointer, which carries no lifetime. It is compared and
    // never dereferenced.
    let scoped: *const [u8; 32] = key.with_secret(core::ptr::from_ref);
    assert!(
        core::ptr::eq(direct, scoped),
        "with_secret must borrow the wrapper's storage, not a copy of it"
    );

    assert_eq!(key.expose_secret(), &SECRET);
    key.with_secret(|bytes| assert_eq!(bytes, &SECRET));
    // Reading twice more, after the reads above, pins that no tier consumed or
    // rewrote anything on the way out.
    assert_eq!(key.with_secret(|bytes| bytes[0]), 0xA5);
    assert_eq!(key.expose_secret(), &SECRET);
    assert_eq!(key.len(), 32);
}

/// Every constructor the size-literal arm forwards produces the same 32 bytes, and the
/// length-checked one reports the exact mismatch rather than truncating or padding.
///
/// These four entry points are separate expansions in the macro (`new`, `new_with`,
/// `From`, `TryFrom`), so they can disagree one at a time; the mismatch arm matters
/// because silently accepting a short slice would hand a caller a key with
/// attacker-influenced zero padding.
#[test]
fn every_byte_array_constructor_agrees_on_the_material_it_stores() {
    let from_new = K32::new(SECRET);
    let from_new_with = K32::new_with(|bytes| bytes.copy_from_slice(&SECRET));
    let from_array: K32 = SECRET.into();
    let from_slice = K32::try_from(SECRET.as_slice()).expect("exact length");

    for built in [&from_new, &from_new_with, &from_array, &from_slice] {
        assert_eq!(built.expose_secret(), &SECRET);
    }

    // `new_with` writes into the wrapper's storage, so a closure that fills only part
    // of the array leaves zeroes behind rather than uninitialized bytes.
    let partial = K32::new_with(|bytes| bytes[0] = 1);
    assert_eq!(partial.expose_secret()[0], 1);
    assert_eq!(&partial.expose_secret()[1..], &[0u8; 31]);

    let short = K32::try_from([0u8; 31].as_slice()).expect_err("31 bytes is not 32");
    match short {
        FromSliceError::InvalidLength { expected, got, .. } => {
            assert_eq!((expected, got), (32, 31))
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    assert!(
        K32::try_from([0u8; 33].as_slice()).is_err(),
        "too long fails too"
    );
}

/// The generic arm gives a non-byte inner type the whole access model and nothing
/// shape-specific, and the access it does give reaches the wrapper's storage.
///
/// This is the documented bargain of `generic T`: `new`, both read tiers, both write
/// tiers, redacted `Debug`, `Zeroize`. Deliberately absent are `SecretLen`, `new_with`,
/// `From`/`TryFrom`, the encoders and the RNG constructors — so the length here is
/// read with `with_secret(|c| c.len())` and never with `len()`, which does not exist on
/// this arm. The absence is pinned by the trybuild cases; what is pinned here is that
/// everything the docs promise *is* present works on the real storage.
#[test]
fn the_generic_arm_carries_the_access_model_for_a_non_byte_inner_type() {
    let poly = Poly::new([7i16; 256]);

    let direct: *const [i16; 256] = poly.expose_secret();
    let scoped: *const [i16; 256] = poly.with_secret(core::ptr::from_ref);
    assert!(core::ptr::eq(direct, scoped));

    assert_eq!(poly.with_secret(|coeffs| coeffs.len()), 256);
    assert_eq!(poly.expose_secret()[255], 7);
    assert_eq!(
        poly.with_secret(|coeffs| coeffs.iter().sum::<i16>()),
        7 * 256
    );
    // Reading changed nothing.
    assert_eq!(poly.expose_secret(), &[7i16; 256]);
}

/// Every shape in this file — three derive variants, the alias, and the base wrapper —
/// stores and returns the same bytes through the same access model.
///
/// The point is not that five constructors work. It is that the nominal separation is
/// the *only* difference between them: each one is built from one `SECRET` constant and
/// each one reads back byte-identically, so anything that later diverges between them
/// is a real behavioural difference and not an artifact of how they were built.
#[test]
fn nominal_separation_changes_the_type_and_nothing_about_the_contents() {
    let opened = Opened::new(SECRET);
    let inbound = Inbound::new(SECRET);
    let outbound = Outbound::new(SECRET);
    let alias: Alias = Alias::new(SECRET);
    let base = Fixed::new(SECRET);

    assert_eq!(opened.expose_secret(), &SECRET);
    assert_eq!(inbound.expose_secret(), &SECRET);
    assert_eq!(outbound.expose_secret(), &SECRET);
    assert_eq!(alias.expose_secret(), &SECRET);
    assert_eq!(base.expose_secret(), &SECRET);

    opened.with_secret(|bytes| assert_eq!(bytes, &SECRET));
    inbound.with_secret(|bytes| assert_eq!(bytes, &SECRET));
    outbound.with_secret(|bytes| assert_eq!(bytes, &SECRET));
    alias.with_secret(|bytes| assert_eq!(bytes, &SECRET));
}

// ---------------------------------------------------------------------------
// 2. Mutation
// ---------------------------------------------------------------------------

/// Both write tiers mutate the wrapper's storage in place: the address does not move,
/// the targeted byte changes, and no other byte does.
///
/// "In place" is the security-relevant half. A mutation that rebuilt the wrapper at a
/// new address would leave the pre-mutation secret in the old slot with nothing obliged
/// to wipe it — exactly the stack-residue failure `Fixed`'s own docs warn about for
/// move-by-value. Pinning the address makes that failure visible in a test instead of
/// in a core dump.
#[test]
fn mutation_rewrites_the_wrappers_own_storage_without_moving_it() {
    let mut key = K32::new(SECRET);
    // Compared as raw pointers rather than integers: no cast, nothing dereferenced.
    let before: *const u8 = key.expose_secret().as_ptr();

    key.with_secret_mut(|bytes| bytes[0] = 0x11);
    assert_eq!(
        key.expose_secret().as_ptr(),
        before,
        "scoped mutation must not relocate the secret"
    );
    // Read back through a *fresh* borrow rather than trusting the closure's view.
    assert_eq!(key.expose_secret()[0], 0x11);
    assert_eq!(
        &key.expose_secret()[1..],
        &[0xA5u8; 31],
        "nothing else moved"
    );

    key.expose_secret_mut()[31] = 0x22;
    assert_eq!(key.expose_secret().as_ptr(), before);
    assert_eq!(key.expose_secret()[31], 0x22);
    assert_eq!(&key.expose_secret()[1..31], &[0xA5u8; 30]);
    assert_eq!(
        key.expose_secret()[0],
        0x11,
        "the earlier mutation survived"
    );

    // The mutable escape hatch hands out the same storage the read tiers name.
    let read: *const u8 = key.expose_secret().as_ptr();
    let write: *mut u8 = key.expose_secret_mut().as_mut_ptr();
    assert_eq!(write.cast_const(), read);
}

/// The key-rotation pattern from the README overwrites the old material in place and
/// leaves the donor untouched.
///
/// This is the realistic mutation: fresh material is copied *into* an existing wrapper
/// rather than a new wrapper replacing the old binding, precisely so the old key is
/// overwritten where it sits instead of being abandoned in a stale stack slot. The
/// assertions are the two things that make it worth recommending — the destination's
/// storage does not move, and the source is still a live secret afterwards (a copy, not
/// a move, so the donor's own zeroize-on-drop still covers it).
#[test]
fn the_readme_rotation_pattern_overwrites_the_old_key_where_it_sits() {
    let mut key = K32::new(SECRET);
    let slot: *const u8 = key.expose_secret().as_ptr();
    let next = K32::new([0x5Au8; 32]);

    next.with_secret(|fresh| key.with_secret_mut(|old| old.copy_from_slice(fresh)));

    assert_eq!(key.expose_secret().as_ptr(), slot);
    assert_eq!(key.expose_secret(), &[0x5Au8; 32], "the new key landed");
    assert!(
        key.expose_secret() != &SECRET,
        "no byte of the old key survived the rotation"
    );
    assert_eq!(
        next.expose_secret(),
        &[0x5Au8; 32],
        "the donor was read, not consumed — it still owns its own wipe"
    );
}

/// Coefficients mutate through the generic arm's slice, in place, without disturbing
/// their neighbours.
///
/// The generic arm forwards `RevealSecretMut` the same way the byte arms do, but its
/// inner type is multi-byte, so an indexing or element-size mistake in the forwarding
/// would corrupt adjacent coefficients rather than producing an obvious failure. The
/// untouched-neighbour assertions are what catch that.
#[test]
fn generic_arm_coefficients_mutate_in_place_through_the_slice() {
    let mut poly = Poly::new([0i16; 256]);
    let slot: *const i16 = poly.expose_secret().as_ptr();

    poly.with_secret_mut(|coeffs| coeffs[0] = -3329);
    poly.expose_secret_mut()[255] = 1664;

    assert_eq!(poly.expose_secret().as_ptr(), slot);
    assert_eq!(poly.expose_secret()[0], -3329);
    assert_eq!(poly.expose_secret()[255], 1664);
    assert!(
        poly.with_secret(|coeffs| coeffs[1..255].iter().all(|&c| c == 0)),
        "the 254 coefficients between them were not touched"
    );
}

// ---------------------------------------------------------------------------
// 3. Handoff — into_inner
// ---------------------------------------------------------------------------

/// `into_inner` hands back the real material and ends the wrapper's protection.
///
/// Two claims in one test because they are the same transition seen from both sides.
/// The returned array is the secret that went in, and it is an *ordinary* array: its
/// `Debug` prints the bytes, it has no zeroize-on-drop, and the caller owns it from
/// there. Asserting that the redaction is gone is the honest way to pin "protection
/// ends here" — it is the one consequence of the handoff that safe code can see.
#[test]
fn into_inner_returns_the_real_material_and_drops_the_protection_with_it() {
    let key = K32::new(SECRET);
    let owned: [u8; 32] = key.into_inner();

    assert_eq!(owned, SECRET, "the caller receives the real material");
    let shown = format!("{owned:?}");
    assert_ne!(shown, "[REDACTED]", "a plain array is not redacted");
    assert!(
        shown.starts_with("[165, 165,"),
        "it prints its own bytes: {shown}"
    );

    // What is NOT observable here: the consumed wrapper. `into_inner` takes `self` by
    // value, so by the time this line runs the wrapper is gone and no safe code can
    // inspect the slot it occupied. The observable part of the sentinel contract is
    // the bound itself — `into_inner` requires `Inner: SentinelValue` — and the
    // sentinel value it constructs, which for a byte array is all-default:
    assert_eq!(<[u8; 32] as SentinelValue>::sentinel_value(), [0u8; 32]);
    // ...so `Fixed::drop` then zeroizes an already-zero array, as its docs claim.
    // `into_inner_leaves_an_inert_sentinel_where_the_secret_was` below makes the
    // substitution itself observable, using an inner type that records its own wipe.
    assert_eq!(
        <[i16; 256] as SentinelValue>::sentinel_value(),
        [0i16; 256],
        "the same holds for the generic arm's inner type"
    );

    // Also not asserted here, deliberately: `into_inner`'s docs say "nothing is
    // copied", and for `Dynamic` that is literally a pointer move — pinned by
    // `dynamic_into_inner_moves_without_copying` in tests/zeroize_tests.rs, which
    // compares the heap buffer's address before and after. A stack array has no such
    // indirection: `core::mem::replace` must read the bytes out to the caller's slot and
    // write the sentinel into the wrapper's. So on this arm the guarantee is "moved, not
    // duplicated-and-retained" — one copy survives the call, and it is the caller's —
    // rather than "no bytes were transferred". The address comparison that would show
    // this is not a stable property (the two slots may coincide once the wrapper is
    // dead and the optimizer has had its way), so it is described and not asserted.
}

/// A dropped wrapper wipes the material it is still holding.
///
/// This is the positive control for the recording inner type, and it is what makes the
/// next test meaningful: it shows that a wipe *is* recorded, and that what gets
/// recorded is the live secret when no handoff intervened. Without it, an empty record
/// in the next test could mean "the sentinel was wiped" or "recording never worked".
#[test]
fn dropping_a_newtype_wipes_the_material_it_still_holds() {
    assert!(wipes().is_empty(), "precondition: nothing recorded yet");

    let held = Handoff::new(Traced(0xDEAD_BEEF));
    assert_eq!(held.with_secret(|t| t.0), 0xDEAD_BEEF);
    drop(held);

    assert_eq!(
        wipes(),
        vec![0xDEAD_BEEF],
        "the wrapper's Drop zeroized the real secret, once"
    );
}

/// After `into_inner`, the wrapper's own storage holds the inert sentinel — so what its
/// `Drop` wipes is the placeholder, not the secret the caller now owns.
///
/// This is the claim in `RevealSecret::into_inner`'s docs ("the value is moved out and
/// an inert `SentinelValue` is left for the wrapper's `Drop` to zeroize in its place")
/// made observable. `Traced` records the value present when the wipe happens, so a
/// record of `0` — the sentinel — means the real material was gone from the wrapper
/// before its `Drop` ran. A record of the secret would mean `into_inner` had copied the
/// material out and left the original behind, which is the failure this contract exists
/// to prevent.
#[test]
fn into_inner_leaves_an_inert_sentinel_where_the_secret_was() {
    assert!(wipes().is_empty(), "precondition: nothing recorded yet");

    let wrapper = Handoff::new(Traced(0xC0FFEE));
    let owned: Traced = wrapper.into_inner();

    assert_eq!(owned, Traced(0xC0FFEE), "the caller got the real material");
    assert_eq!(
        wipes(),
        vec![0],
        "the wrapper wiped the sentinel, not the secret — and wiped exactly once"
    );
    // `owned` has no Drop and no ZeroizeOnDrop, so dropping it at the end of this test
    // records nothing: protection really did end at the handoff. That is the same
    // property the byte-array test reads as a missing `[REDACTED]`.
}

/// `into_inner` on the generic arm returns the non-byte inner value, including any
/// mutation made while it was still protected.
///
/// The handoff and the mutation paths are forwarded by different parts of the macro, so
/// the interesting case is the two together: material that was changed in place must be
/// what the move-out produces, not the value the wrapper was constructed from.
#[test]
fn into_inner_on_the_generic_arm_returns_the_mutated_inner_value() {
    let mut poly = Poly::new([1i16; 256]);
    poly.with_secret_mut(|coeffs| coeffs[128] = -1);

    let owned: [i16; 256] = poly.into_inner();
    assert_eq!(owned[128], -1);
    assert_eq!(owned[127], 1);
    assert_eq!(owned.iter().filter(|&&c| c == 1).count(), 255);
    assert_ne!(format!("{owned:?}"), "[REDACTED]");
}

// ---------------------------------------------------------------------------
// 3. Handoff — directional base-wrapper access
// ---------------------------------------------------------------------------

/// `WrapperAccess` round-trips base wrapper to newtype and back with the payload
/// intact, and the borrowing accessors borrow rather than consume.
///
/// Base-wrapper access is a security boundary: it is the only way, short of a
/// `with_secret` rebuild, for material to change role. So the properties worth pinning
/// are that the round trip preserves the payload exactly, that `as_wrapper` /
/// `as_wrapper_mut` reach the *same* storage the newtype's own tiers reach (they drop
/// the label, not the protection, and they leave the value in place), and that what
/// comes back out of `into_wrapper` is still a protected `Fixed`.
#[test]
fn wrapper_access_round_trips_the_payload_and_borrows_without_consuming() {
    let base = Fixed::new(SECRET);
    let mut opened = Opened::from_wrapper(base);
    assert_eq!(opened.expose_secret(), &SECRET, "inbound kept every byte");

    // Borrowing, not consuming: `opened` is still usable after both accessors, and
    // both name the same storage its own read tier names.
    let through_newtype: *const [u8; 32] = opened.expose_secret();
    let through_wrapper: *const [u8; 32] = opened.as_wrapper().expose_secret();
    assert!(
        core::ptr::eq(through_newtype, through_wrapper),
        "repr(transparent): the label does not add a layer of storage"
    );
    assert_eq!(opened.as_wrapper().len(), 32);

    // A mutation made through the borrowed base wrapper is visible through the
    // newtype, because there is only one place for it to land.
    opened
        .as_wrapper_mut()
        .with_secret_mut(|bytes| bytes[0] = 0x77);
    assert_eq!(opened.expose_secret()[0], 0x77);
    assert_eq!(&opened.expose_secret()[1..], &[0xA5u8; 31]);

    // Outbound: the label is dropped, the protection is not.
    let returned: Fixed<[u8; 32]> = opened.into_wrapper();
    assert_eq!(returned.expose_secret()[0], 0x77);
    assert_eq!(&returned.expose_secret()[1..], &[0xA5u8; 31]);
    assert_eq!(
        format!("{returned:?}"),
        "[REDACTED]",
        "into_wrapper drops the label, not the protection"
    );
}

/// Each directional token opens exactly the direction it names, and neither direction
/// alters the payload.
///
/// `FromWrapper` admits a base-typed value into the role; `IntoWrapper` lets material
/// leave toward the base type. The absences — `Inbound::into_wrapper`,
/// `Outbound::from_wrapper` — are compile errors and are pinned by
/// `tests/compile-fail/newtype_directional_access.rs`; a runtime test cannot observe a
/// method that does not exist. What it can observe, and what matters once the token is
/// granted, is that the crossing is byte-exact in the direction that is open.
#[test]
fn each_directional_token_opens_its_own_direction_byte_exactly() {
    // Inbound: base value in, read back through the newtype.
    let inbound = Inbound::from_wrapper(Fixed::new(SECRET));
    assert_eq!(inbound.expose_secret(), &SECRET);
    inbound.with_secret(|bytes| assert_eq!(bytes, &SECRET));

    // Outbound: borrow toward the base, then leave toward it.
    let outbound = Outbound::new(SECRET);
    assert_eq!(outbound.as_wrapper().expose_secret(), &SECRET);
    let escaped: Fixed<[u8; 32]> = outbound.into_wrapper();
    assert_eq!(escaped.expose_secret(), &SECRET);
    assert_eq!(format!("{escaped:?}"), "[REDACTED]");

    // The two tokens are one-way each, so a full base -> role -> base circuit needs
    // both of them; `Opened` has both, and the payload survives the circuit.
    let circuit: Fixed<[u8; 32]> = Opened::from_wrapper(Fixed::new(SECRET)).into_wrapper();
    assert_eq!(circuit.expose_secret(), &SECRET);
}

/// An alias *is* its base type; a newtype is not, and needs `from_wrapper` to admit one.
///
/// This is the asymmetry the nominal types exist for, pinned with code that compiles:
/// a `Fixed<[u8; 32]>` value is already an `Alias`, passes to a function expecting
/// either spelling, and needs no conversion in either direction — while the same value
/// reaches `Opened` only through the opt-in inbound door. The rejection side (a base
/// value where a newtype is expected, `&Newtype` coercing to `&Fixed`) is a compile
/// error covered by the trybuild cases; the acceptance side has to be asserted here,
/// because "these two spellings are interchangeable" is not something a compile-fail
/// test can show.
#[test]
fn an_alias_is_interchangeable_with_its_base_while_a_newtype_needs_a_door() {
    fn first_byte_of_base(secret: &Fixed<[u8; 32]>) -> u8 {
        secret.expose_secret()[0]
    }
    fn first_byte_of_alias(secret: &Alias) -> u8 {
        secret.expose_secret()[0]
    }

    // One value, both spellings, no conversion anywhere: they are the same type.
    let base = Fixed::new(SECRET);
    assert_eq!(first_byte_of_base(&base), 0xA5);
    assert_eq!(first_byte_of_alias(&base), 0xA5);
    let as_alias: Alias = base; // a move, not a conversion
    assert_eq!(first_byte_of_base(&as_alias), 0xA5);

    // The newtype needs the inbound door, and afterwards does not pass as its base —
    // `first_byte_of_base(&opened)` is E0308, pinned by tests/compile-fail.
    let opened = Opened::from_wrapper(as_alias);
    assert_eq!(opened.expose_secret()[0], 0xA5);
    // Reaching base-typed code from the newtype is an explicit, greppable step.
    assert_eq!(first_byte_of_base(opened.as_wrapper()), 0xA5);
}

// ---------------------------------------------------------------------------
// 4. Size and transparency
// ---------------------------------------------------------------------------

/// Every shape is exactly the size of the secret it holds.
///
/// `#[repr(transparent)]` over the wrapper, and `Fixed<T>` holding its `T` inline, is
/// the crate's zero-overhead claim in its most checkable form: a role label, a derive
/// token and an alias all cost zero bytes. A stray field, a discriminant or an
/// unexpected `Option` in a future refactor shows up here first.
#[test]
fn repr_transparent_keeps_every_shape_the_size_of_its_secret() {
    use core::mem::size_of;

    assert_eq!(size_of::<K32>(), 32);
    assert_eq!(size_of::<Opened>(), 32);
    assert_eq!(size_of::<Inbound>(), 32);
    assert_eq!(size_of::<Outbound>(), 32);
    assert_eq!(size_of::<Alias>(), 32);
    assert_eq!(size_of::<Fixed<[u8; 32]>>(), 32);

    // 256 coefficients, two bytes each — the generic arm adds nothing either.
    assert_eq!(size_of::<Poly>(), 512);
    assert_eq!(size_of::<Fixed<[i16; 256]>>(), 512);

    assert_eq!(size_of::<Handoff>(), size_of::<Traced>());
    assert_eq!(size_of::<Handoff>(), size_of::<u64>());
}

// ---------------------------------------------------------------------------
// 5. Redaction across the lifecycle, and the end of life
// ---------------------------------------------------------------------------

/// `Debug` prints `[REDACTED]` at every stage of the lifecycle, for every shape.
///
/// Redaction is one `write_str` in a macro expansion, which makes it the property most
/// likely to be lost silently in a refactor: nothing else stops compiling, and the
/// secret simply starts appearing in logs and panic messages. So it is checked fresh,
/// after mutation, after a base-wrapper round trip, and in the alternate `{:#?}` form
/// that a `derive(Debug)` on a containing struct would reach for.
#[test]
fn debug_stays_redacted_at_every_stage_for_every_shape() {
    let mut key = K32::new(SECRET);
    assert_eq!(format!("{key:?}"), "[REDACTED]", "fresh");
    key.with_secret_mut(|bytes| bytes[0] = 0);
    assert_eq!(format!("{key:?}"), "[REDACTED]", "after mutation");
    assert_eq!(format!("{key:#?}"), "[REDACTED]", "alternate form too");

    let mut poly = Poly::new([9i16; 256]);
    assert_eq!(format!("{poly:?}"), "[REDACTED]");
    poly.with_secret_mut(|coeffs| coeffs[0] = 0);
    assert_eq!(format!("{poly:?}"), "[REDACTED]");

    let opened = Opened::from_wrapper(Fixed::new(SECRET));
    assert_eq!(
        format!("{opened:?}"),
        "[REDACTED]",
        "after inbound crossing"
    );
    let base = opened.into_wrapper();
    assert_eq!(format!("{base:?}"), "[REDACTED]", "after outbound crossing");
    let relabelled = Opened::from_wrapper(base);
    assert_eq!(
        format!("{relabelled:?}"),
        "[REDACTED]",
        "after a full circuit"
    );

    assert_eq!(format!("{:?}", Inbound::new(SECRET)), "[REDACTED]");
    assert_eq!(format!("{:?}", Outbound::new(SECRET)), "[REDACTED]");
    assert_eq!(format!("{:?}", Alias::new(SECRET)), "[REDACTED]");
    assert_eq!(format!("{:?}", Handoff::new(Traced(1))), "[REDACTED]");
}

/// The forwarded `Zeroize` reaches the secret through every layer of labelling.
///
/// `zeroize()` is the one end-of-life step a test can observe directly on a
/// stack-backed secret, and the macros forward it per newtype, so a missing forward
/// would leave a type whose `Drop` wipes nothing. Each shape is wiped and then read
/// back through the access model — through `as_wrapper` as well, to confirm the wipe
/// reached the single shared storage and not a copy.
#[test]
fn the_forwarded_zeroize_reaches_the_secret_through_every_label() {
    let mut key = K32::new(SECRET);
    key.zeroize();
    assert_eq!(key.expose_secret(), &[0u8; 32]);

    let mut poly = Poly::new([0x7Fi16; 256]);
    poly.zeroize();
    assert_eq!(poly.expose_secret(), &[0i16; 256]);

    let mut opened = Opened::from_wrapper(Fixed::new(SECRET));
    opened.zeroize();
    assert_eq!(opened.expose_secret(), &[0u8; 32]);
    assert_eq!(opened.as_wrapper().expose_secret(), &[0u8; 32]);

    let mut alias = Alias::new(SECRET);
    alias.zeroize();
    assert_eq!(alias.expose_secret(), &[0u8; 32]);

    // And the marker that says this happens on drop too is forwarded with it.
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<K32>();
    assert_zeroize_on_drop::<Poly>();
    assert_zeroize_on_drop::<Opened>();
    assert_zeroize_on_drop::<Inbound>();
    assert_zeroize_on_drop::<Outbound>();
    assert_zeroize_on_drop::<Alias>();
    assert_zeroize_on_drop::<Handoff>();
}

/// A newtype really has drop glue, so the wipe above is not merely available but
/// scheduled.
///
/// `[u8; 32]` needs no drop of its own, so `needs_drop` on a 32-byte newtype can only
/// be true because the wrapper inside it carries a real `Drop` impl that the
/// `#[repr(transparent)]` label did not discard. This is the same argument
/// `tests/zeroize_tests.rs` makes for `Fixed` itself, extended to the generated types
/// one step further out.
#[test]
fn every_shape_carries_real_drop_glue() {
    assert!(core::mem::needs_drop::<K32>());
    assert!(core::mem::needs_drop::<Poly>());
    assert!(core::mem::needs_drop::<Opened>());
    assert!(core::mem::needs_drop::<Inbound>());
    assert!(core::mem::needs_drop::<Outbound>());
    assert!(core::mem::needs_drop::<Alias>());
    assert!(core::mem::needs_drop::<Handoff>());
}

/// The generic arm's reduced surface is a property of the label, not of the protection:
/// a newtype that also holds `IntoWrapper` reaches `SecretLen` through its base wrapper
/// in one call.
///
/// This is worth pinning because the two facts are easy to state as one. `fixed_newtype!`
/// withholds `SecretLen` from the `generic` arm on the grounds that "a length in elements
/// is not the byte length callers expect" — but `impl SecretLen for Fixed<[T; N]>` exists
/// and answers both questions correctly (`len()` in elements, `byte_len()` in bytes), so
/// the capability is present one layer down and `IntoWrapper` is enough to reach it.
/// Anyone treating the reduced surface as a guarantee that a `generic` newtype cannot be
/// measured should grant the outbound token with that in mind. See the note in the final
/// report: the macro's stated rationale does not match what the base wrapper provides,
/// though the forwarding behaviour itself is exactly as documented.
#[test]
fn the_reduced_surface_is_a_label_property_that_intowrapper_reopens() {
    let poly = PolyOut::new([1i16; 256]);

    // `poly.len()` does not compile — `SecretLen` is not forwarded by this arm.
    // One audited step down, it is there, and it is not even wrong about bytes:
    assert_eq!(poly.as_wrapper().len(), 256, "elements");
    assert_eq!(
        poly.as_wrapper().byte_len(),
        512,
        "bytes, size_of::<i16>() included"
    );

    // The handoff still behaves the same at the end of that step.
    let base: Fixed<[i16; 256]> = poly.into_wrapper();
    assert_eq!(format!("{base:?}"), "[REDACTED]");
    assert_eq!(base.into_inner()[0], 1);
}
