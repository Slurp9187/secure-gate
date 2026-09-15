// Tests for `SlotWriter` -- a write cursor over a borrowed `&mut [u8]` slot.
//
// `SlotWriter` itself needs neither `alloc` nor `std`: it operates on any slice, stack or
// heap, which is why most of this file runs unconditionally. Two groups are gated:
// the `io::Write` impl (behind `std`, at the bottom of `src/slot_writer.rs`), and the
// composition test that drives a real `Dynamic::new_with` (behind `alloc`, since
// `Dynamic` itself is). The `Fixed::new_with` composition test needs neither -- `Fixed`
// is always available -- and runs alongside the core cursor tests.

#[cfg(feature = "alloc")]
extern crate alloc;

use secure_gate::{Fixed, RevealSecret, SlotWriter};

#[cfg(feature = "alloc")]
use secure_gate::Dynamic;

// === push_slice: order, position, remaining ===

#[test]
fn push_slice_appends_in_order_and_tracks_position() {
    let mut buf = [0u8; 8];
    let mut w = SlotWriter::new(&mut buf);

    assert_eq!(w.position(), 0);
    assert_eq!(w.remaining(), 8);

    w.push_slice(&[1, 2, 3]);
    assert_eq!(w.position(), 3);
    assert_eq!(w.remaining(), 5);

    w.push_slice(&[4, 5]);
    assert_eq!(w.position(), 5);
    assert_eq!(w.remaining(), 3);

    w.push_slice(&[6, 7, 8]);
    assert_eq!(w.position(), 8);
    assert_eq!(w.remaining(), 0);

    // Three separate calls land contiguously, in call order -- not just each slice
    // internally correct, but concatenated the way append semantics promise.
    assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
}

// === is_full ===

#[test]
fn is_full_only_at_the_exact_boundary() {
    let mut buf = [0u8; 4];
    let mut w = SlotWriter::new(&mut buf);

    assert!(!w.is_full(), "nothing written yet");

    w.push_slice(&[9, 9, 9]);
    assert!(!w.is_full(), "3 of 4 bytes written -- one byte still open");

    w.push_byte(9);
    assert!(w.is_full(), "4th byte lands exactly on the boundary");
}

// === Zero tail ===

/// Anything left unwritten keeps whatever was already in the slot -- `SlotWriter` never
/// clears on its own account. For a zero-initialized buffer, which is what every sized
/// constructor in this crate hands the closure, that means an untouched tail reads as
/// real zero bytes rather than garbage. This is the 40-bit-RC4-key shape referenced in
/// the crate docs: 5 derived bytes, then 11 zeros the key schedule consumes as input, not
/// padding to be trimmed.
#[test]
fn unwritten_tail_stays_zero() {
    let mut buf = [0u8; 16];
    let mut w = SlotWriter::new(&mut buf);
    w.push_slice(&[1, 2, 3, 4, 5]);

    assert_eq!(w.position(), 5);
    assert_eq!(w.remaining(), 11);
    assert_eq!(&buf[..5], &[1, 2, 3, 4, 5]);
    assert_eq!(&buf[5..16], &[0u8; 11]);
}

// === push_byte ===

#[test]
fn push_byte_appends_one_byte_at_a_time() {
    let mut buf = [0u8; 3];
    let mut w = SlotWriter::new(&mut buf);

    w.push_byte(0xAA);
    assert_eq!(w.position(), 1);
    w.push_byte(0xBB);
    assert_eq!(w.position(), 2);
    w.push_byte(0xCC);
    assert_eq!(w.position(), 3);
    assert!(w.is_full());

    assert_eq!(buf, [0xAA, 0xBB, 0xCC]);
}

// === Overrun panics ===
//
// `push_slice`'s assert message names the shortfall: "SlotWriter overrun: N more byte(s)
// than the slot holds (W wanted, R remaining)". The substring below is the part of that
// message that is stable regardless of the exact numbers, so it stays correct if the
// wording around the counts changes.

#[test]
#[should_panic(expected = "SlotWriter overrun")]
fn push_slice_past_the_end_panics() {
    let mut buf = [0u8; 4];
    let mut w = SlotWriter::new(&mut buf);
    w.push_slice(&[1, 2, 3, 4, 5]); // 1 byte more than the 4-byte slot holds
}

#[test]
#[should_panic(expected = "SlotWriter overrun")]
fn push_byte_on_a_full_slot_panics() {
    let mut buf = [0u8; 1];
    let mut w = SlotWriter::new(&mut buf);
    w.push_byte(1); // fills the slot
    w.push_byte(2); // and this one has nowhere to go
}

// === Exact fit does not panic ===
//
// The boundary is where off-by-one errors hide: a slice whose length equals exactly what
// remains must be accepted, not treated as one byte too many.

#[test]
fn exact_fit_does_not_panic() {
    let mut buf = [0u8; 6];
    let mut w = SlotWriter::new(&mut buf);
    w.push_slice(&[1, 2, 3, 4, 5, 6]); // fills to the last byte, no more, no less

    assert!(w.is_full());
    assert_eq!(w.remaining(), 0);
    assert_eq!(w.position(), 6);
    assert_eq!(buf, [1, 2, 3, 4, 5, 6]);
}

#[test]
fn exact_fit_via_push_byte_does_not_panic() {
    let mut buf = [0u8; 2];
    let mut w = SlotWriter::new(&mut buf);
    w.push_byte(7);
    w.push_byte(8); // lands exactly on the last slot -- must not panic
    assert!(w.is_full());
}

// === Zero-length slot ===
//
// Constructing a zero-length `Fixed` is a compile error, but not because the type is
// refused. `impl<T: FixedStorage, const N: usize> FixedStorage for [T; N]` in
// `src/traits/fixed_storage.rs` accepts `N = 0` like any other `N`, and naming the type on
// its own -- `type Name = Fixed<[u8; 0]>;` -- still compiles. The guard is the
// `NON_ZERO_SIZED` `const` assertion evaluated in the bodies of `Fixed::new`, `new_with`
// and `try_new_with`, the constructors every other one funnels through, so it is
// post-monomorphization: it fires at the construction site, during codegen, and `cargo
// check` never reaches it. That is why `tests/compile-fail/fixed_zero_size.rs` has a
// compile-pass companion -- it puts `trybuild` into `cargo build` mode, without which the
// compile-fail case passes clean.
//
// `Dynamic::<Vec<u8>>::new_with(0, ..)` has no counterpart to that guard: `len` is a
// runtime value, and neither `new_with` nor `try_new_with` rejects 0 -- both just build a
// `vec![0u8; len]` and hand the closure `&mut v[..]`, which at `len == 0` is an empty
// slice. So the call is legal and the empty slot is reachable only through `Dynamic`, and
// only at this cursor layer does it get direct coverage: a zero-length slice is "full" the
// instant it exists, with nothing to write and nothing to remain.

#[test]
fn zero_length_slot_is_full_immediately() {
    let mut buf: [u8; 0] = [];
    let mut w = SlotWriter::new(&mut buf);

    assert!(
        w.is_full(),
        "a slot with no bytes has nothing left to write"
    );
    assert_eq!(w.remaining(), 0);
    assert_eq!(w.position(), 0);

    // An empty push asks for no room, so it is accepted even though the slot is already
    // "full" -- same reasoning as the empty io::Write case below: `is_full` means no
    // room for anything, not that further zero-sized writes are refused.
    w.push_slice(&[]);
    assert!(w.is_full());
    assert_eq!(w.position(), 0);
}

#[test]
#[should_panic(expected = "SlotWriter overrun")]
fn zero_length_slot_panics_on_push_byte() {
    let mut buf: [u8; 0] = [];
    let mut w = SlotWriter::new(&mut buf);
    w.push_byte(1); // one byte wanted, zero capacity to put it in
}

// === Debug redaction ===
//
// `SlotWriter` borrows the live secret buffer for the duration of `new_with`, so a naive
// `#[derive(Debug)]` over `slot: &mut [u8]` prints the bytes themselves -- the whole secret,
// in plaintext, into whatever the caller passes the formatted value to (a log line, a panic
// message, an assertion failure from a test harness). `Debug` must instead redact the slot
// while still reporting the cursor state (`pos` / how much is written vs. remaining), since
// that state is what makes the output useful for debugging a length mismatch without ever
// being useful for recovering the secret.

#[test]
fn debug_redacts_slot_bytes_but_reports_cursor_state() {
    // A recognisable, non-zero payload -- if any of these four bytes show up in the
    // formatted output, in either decimal or hex, the Debug impl is leaking the secret.
    let mut buf = [0u8; 6];
    let mut w = SlotWriter::new(&mut buf);
    w.push_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(w.position(), 4);
    assert_eq!(w.remaining(), 2);

    let out = format!("{w:?}");

    // Decimal renderings of the four bytes: 0xDE=222, 0xAD=173, 0xBE=190, 0xEF=239.
    for decimal in ["222", "173", "190", "239"] {
        assert!(
            !out.contains(decimal),
            "Debug output leaks a secret byte as decimal {decimal}: {out}"
        );
    }
    // Hex renderings, upper- and lower-case, with no assumption of a `0x` prefix.
    for hex in ["de", "DE", "ad", "AD", "be", "BE", "ef", "EF"] {
        assert!(
            !out.contains(hex),
            "Debug output leaks a secret byte as hex {hex}: {out}"
        );
    }

    // The cursor state is not secret and must still be legible: 4 bytes written, 2
    // remaining. These numbers do not collide with any of the excluded byte renderings
    // above, so their presence here is a positive signal, not a coincidence.
    assert!(
        out.contains(&w.position().to_string()),
        "Debug output should report the position (4): {out}"
    );
    assert!(
        out.contains(&w.remaining().to_string()),
        "Debug output should report what remains (2): {out}"
    );
}

// === io::Write (std) ===
//
// This path exists for foreign code that writes through `std::io::Write` and cannot be
// asked to respect a length up front -- a serializer, an encoder, a hasher's output sink.
// Overrun there is reported as `ErrorKind::WriteZero`, the interface's own way of saying
// "refused", rather than as the panic `push_slice` uses.

#[cfg(feature = "std")]
#[test]
fn write_returns_write_zero_when_full() {
    use std::io::{ErrorKind, Write};

    let mut buf = [0u8; 4];
    let mut w = SlotWriter::new(&mut buf);
    w.write_all(&[1, 2, 3, 4]).unwrap();
    assert!(w.is_full());

    let err = w.write(&[5]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WriteZero);
    // The slot itself is untouched by the refused write.
    assert_eq!(buf, [1, 2, 3, 4]);
}

#[cfg(feature = "std")]
#[test]
fn write_short_write_returns_bytes_accepted() {
    use std::io::Write;

    let mut buf = [0u8; 4];
    let mut w = SlotWriter::new(&mut buf);

    // `Write::write` is contractually allowed to accept less than the whole buffer; this
    // is that case. 6 bytes offered, only 4 fit, and the return value must say 4 -- not
    // panic, and not silently drop the other 2 while claiming success.
    let n = w.write(&[1, 2, 3, 4, 5, 6]).unwrap();
    assert_eq!(n, 4);
    assert!(w.is_full());

    assert_eq!(buf, [1, 2, 3, 4]);
}

#[cfg(feature = "std")]
#[test]
fn write_empty_buf_on_a_full_slot_is_ok_not_write_zero() {
    use std::io::Write;

    // An empty write asks for no room, so it must succeed even with zero bytes
    // remaining -- `WriteZero` means "you wanted space and there wasn't any", which does
    // not apply when nothing was wanted.
    let mut buf = [0u8; 2];
    let mut w = SlotWriter::new(&mut buf);
    w.write_all(&[1, 2]).unwrap();
    assert!(w.is_full());
    assert_eq!(w.write(&[]).unwrap(), 0);
}

#[cfg(feature = "std")]
#[test]
fn write_all_on_overrun_commits_the_prefix_before_returning_write_zero() {
    use std::io::{ErrorKind, Write};

    // `write_all`'s default impl loops calling `write` until the buffer is exhausted or
    // an error surfaces, advancing past whatever each `write` accepted. It is not
    // transactional: it has no way to undo the bytes a prior `write` already copied into
    // the slot before a later call fails. Here the first `write` accepts the 4 bytes
    // that fit and copies them in; the second call, for the 2 leftover bytes against a
    // now-full slot, is what returns `WriteZero`. `write_all` surfaces that error as its
    // own -- but the first call's 4 bytes are already sitting in `buf`, committed.
    //
    // This is the state a caller inherits if it treats the `Err` as "nothing happened":
    // real secret material landed in the slot, alongside an error that looks like a
    // clean refusal.
    let mut buf = [0u8; 4];
    let mut w = SlotWriter::new(&mut buf);

    let err = w.write_all(&[1, 2, 3, 4, 5, 6]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WriteZero);

    // The prefix that did fit is not rolled back on the error path.
    assert_eq!(buf, [1, 2, 3, 4]);
}

// === Composition: SlotWriter driving a real sized constructor ===
//
// This is the reason the type exists. `Fixed::new_with` / `Dynamic::new_with` hand the
// closure a slot whose length is already decided by the caller, which is what makes
// growth -- and the reallocation hazard that motivated removing the old zero-capacity
// `new_with` -- inexpressible. `SlotWriter` restores append-shaped writes on top of that
// fixed slot instead of the caller computing offsets by hand.

#[test]
fn drives_fixed_new_with_labeled_concatenation() {
    const LABEL: &[u8] = b"secure-gate";
    let suite_id = [0x11u8; 2];
    let context = [0x22u8; 3];

    // 11 + 2 + 3 = 16: the slot is exactly the sum of the parts, so `is_full()` at the
    // end is itself an assertion that the length arithmetic was right.
    let secret = Fixed::<[u8; 16]>::new_with(|slot| {
        let mut w = SlotWriter::new(slot);
        w.push_slice(LABEL);
        w.push_slice(&suite_id);
        w.push_slice(&context);
        assert!(w.is_full());
    });

    secret.with_secret(|s| {
        assert_eq!(&s[..11], LABEL);
        assert_eq!(&s[11..13], &suite_id);
        assert_eq!(&s[13..], &context);
    });
}

#[cfg(feature = "alloc")]
#[test]
fn drives_dynamic_new_with_labeled_concatenation() {
    const LABEL: &[u8] = b"HPKE";
    let suite_id = [0xAAu8; 3];
    let ikm = [0xBBu8; 9];

    // 4 + 3 + 9 = 16, chosen by the caller up front and handed to `new_with` as `len` --
    // there is no capacity beyond it for a wayward write to silently land in.
    let secret = Dynamic::<Vec<u8>>::new_with(16, |slot| {
        let mut w = SlotWriter::new(slot);
        w.push_slice(LABEL);
        w.push_slice(&suite_id);
        w.push_slice(&ikm);
        assert!(w.is_full());
    });

    secret.with_secret(|s| {
        assert_eq!(s.len(), 16);
        assert_eq!(&s[..4], LABEL);
        assert_eq!(&s[4..7], &suite_id);
        assert_eq!(&s[7..], &ikm);
    });
}
