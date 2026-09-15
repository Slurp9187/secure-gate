//! Append-shaped writing into a fixed slot.
//!
//! > **Import path:** `use secure_gate::SlotWriter;`
//!
//! The sized constructors — [`Fixed::new_with`](crate::Fixed::new_with) and
//! [`Dynamic::new_with`](crate::Dynamic::new_with) — hand the closure a slot whose
//! length is already decided, which is what makes growth, and therefore the
//! reallocation hazard, inexpressible. The cost is that concatenation becomes offset
//! arithmetic:
//!
//! ```text
//! slot[..7].copy_from_slice(LABEL);
//! slot[7..7 + id.len()].copy_from_slice(suite_id);   // and so on, by hand
//! ```
//!
//! That trades a reallocation hazard for an **offset** hazard, and in wire-format code
//! it is the worse of the two: a wrong bound derives the wrong key and still runs. This
//! type keeps the slot as the primitive and restores the append shape on top of it.

/// A write cursor over a fixed-length slot.
///
/// Writes advance a position and **panic on overrun** rather than truncating or wrapping
/// — running past the end of a secret's buffer is a bug, not a condition to recover
/// from, and the panic names the shortfall.
///
/// The slot is not owned here. Zeroization remains the wrapper's, so a `SlotWriter`
/// borrowed from inside `new_with` inherits the same panic-safety: unwinding drops the
/// wrapper's `Zeroizing`, which wipes whatever was written.
///
/// # Examples
///
/// RFC 9180-style labeled concatenation, where the length is the sum of the parts. Here
/// every part has a length the compiler knows, so the total is a constant and the
/// wrapper is a [`Fixed`](crate::Fixed):
///
/// ```rust
/// use secure_gate::{Fixed, RevealSecret, SlotWriter};
///
/// const LABEL: &[u8] = b"HPKE-v1";
/// let suite_id = [0xAAu8; 3];
/// let ikm = [0xBBu8; 6];
///
/// let secret = Fixed::<[u8; 16]>::new_with(|slot| {
///     let mut w = SlotWriter::new(slot);
///     w.push_slice(LABEL);
///     w.push_slice(&suite_id);
///     w.push_slice(&ikm);
///     assert!(w.is_full());
/// });
///
/// assert_eq!(&secret.expose_secret()[..7], LABEL);
/// ```
///
/// The same concatenation when the parts are sized at runtime. This is the commoner
/// shape for a real wire format — a suite identifier and an IKM that arrived over the
/// network have no length the compiler can see — and the only thing that changes is
/// which constructor takes the sum: [`Dynamic::new_with`](crate::Dynamic::new_with)
/// accepts the total as a value, so `SlotWriter` serves it exactly as it serves the
/// constant case. There is no reason to reach for an oversized `Fixed` plus a separate
/// logical length:
///
/// ```rust
/// # #[cfg(feature = "alloc")] {
/// use secure_gate::{Dynamic, RevealSecret, SlotWriter};
///
/// const LABEL: &[u8] = b"HPKE-v1";
/// let suite_id: Vec<u8> = vec![0xAA; 3];   // lengths known only at run time
/// let ikm: Vec<u8> = vec![0xBB; 6];
///
/// let total = LABEL.len() + suite_id.len() + ikm.len();
///
/// let secret = Dynamic::<Vec<u8>>::new_with(total, |slot| {
///     let mut w = SlotWriter::new(slot);
///     w.push_slice(LABEL);
///     w.push_slice(&suite_id);
///     w.push_slice(&ikm);
///     assert!(w.is_full());   // the sum and the writes agreed
/// });
///
/// assert_eq!(secret.expose_secret().len(), total);
/// assert_eq!(&secret.expose_secret()[..7], LABEL);
/// # }
/// ```
///
/// # The zero tail is inherited, not imposed
///
/// A `SlotWriter` never clears anything. It copies the bytes it is handed and leaves
/// every other byte exactly as it found it, so what an unwritten tail holds is a fact
/// about the slot you passed to [`new`](Self::new), not a guarantee this type supplies.
///
/// Over a slot from a sized constructor that fact is zeros, by documented contract
/// rather than by luck: [`Fixed::new_with`](crate::Fixed::new_with) starts from
/// [`SentinelValue::sentinel_value`](crate::SentinelValue::sentinel_value), which is
/// `[0u8; N]` for a byte array, and [`Dynamic::new_with`](crate::Dynamic::new_with)
/// allocates `len` zero bytes and documents the zero fill as input callers may rely on.
/// For those two slots — and for a stack buffer you zeroed yourself — a short write is
/// not undefined; it is a zero tail, which is frequently what a format wants:
///
/// ```rust
/// use secure_gate::{Fixed, RevealSecret, SlotWriter};
///
/// let key = Fixed::<[u8; 16]>::new_with(|slot| {
///     let mut w = SlotWriter::new(slot);
///     w.push_slice(&[1, 2, 3, 4, 5]);   // 40-bit key, zero-padded to 16
/// });
/// assert_eq!(&key.expose_secret()[5..], &[0u8; 11]);
/// ```
///
/// Over any other slot the tail is whatever was there before, and two of those are
/// traps. One is a scratch buffer reused for a second key. The other is rewriting a
/// wrapper in place — `SlotWriter::new(&mut secret.expose_secret_mut()[..])` — where the
/// bytes already in the slot are the *previous secret*. Write fewer bytes than the
/// previous pass did and the untouched tail is stale key material that the next
/// derivation consumes as input: a wrong key that still runs, which is the failure mode
/// this type exists to remove rather than to introduce by a different route. Build a new
/// wrapper with a sized `new_with` instead of rewriting one in place; failing that, zero
/// the slot before wrapping it, or write it to [`is_full`](Self::is_full) so that no byte
/// of the old contents survives.
///
/// # `Debug` shows the cursor, never the slot
///
/// `{:?}` prints `position`, `remaining` and `len`, and no byte of the slot — see the
/// `Debug` impl below for the exact rendering and for why it is hand-written.
pub struct SlotWriter<'a> {
    slot: &'a mut [u8],
    pos: usize,
}

impl<'a> SlotWriter<'a> {
    /// Wraps a slot, positioned at its start.
    ///
    /// # Precondition: a zeroed slot, unless every byte will be written
    ///
    /// Any `&mut [u8]` is accepted and nothing here zeroes it, so the slot's current
    /// contents survive as the tail of whatever you write. Either write the slot to
    /// [`is_full`](Self::is_full), in which case nothing of the old contents is left, or
    /// pass a slot that is already zeroed — the ones
    /// [`Fixed::new_with`](crate::Fixed::new_with) and
    /// [`Dynamic::new_with`](crate::Dynamic::new_with) hand their closures both are, by
    /// documented contract. Neither, and an unwritten tail holds whatever the buffer held
    /// before, which for a reused scratch buffer or a wrapper being rewritten in place is
    /// the previous secret. The type-level section
    /// [*The zero tail is inherited, not imposed*](#the-zero-tail-is-inherited-not-imposed)
    /// spells out what that costs.
    #[inline]
    pub fn new(slot: &'a mut [u8]) -> Self {
        Self { slot, pos: 0 }
    }

    /// Appends `bytes` and advances past them.
    ///
    /// # Panics
    ///
    /// If `bytes` does not fit in the remaining space. The message names how much was
    /// wanted and how much was left, because the useful question when this fires is
    /// which length calculation was wrong.
    #[inline]
    pub fn push_slice(&mut self, bytes: &[u8]) {
        let end = self
            .pos
            .checked_add(bytes.len())
            .expect("slot position overflow");
        assert!(
            end <= self.slot.len(),
            "SlotWriter overrun: {} more byte(s) than the slot holds ({} wanted, {} remaining)",
            end - self.slot.len(),
            bytes.len(),
            self.remaining(),
        );
        self.slot[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
    }

    /// Appends one byte and advances past it.
    ///
    /// # Panics
    ///
    /// If the slot is already full.
    #[inline]
    pub fn push_byte(&mut self, byte: u8) {
        self.push_slice(&[byte]);
    }

    /// Bytes written so far.
    #[inline]
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes still unwritten.
    ///
    /// These keep whatever the slot already held — zeros when the slot came from
    /// [`Fixed::new_with`](crate::Fixed::new_with) or
    /// [`Dynamic::new_with`](crate::Dynamic::new_with), which is the case the zero-tail
    /// contract covers, and the buffer's previous contents otherwise. See
    /// [*The zero tail is inherited, not imposed*](#the-zero-tail-is-inherited-not-imposed).
    #[inline]
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.slot.len() - self.pos
    }

    /// Whether every byte of the slot has been written.
    ///
    /// Useful as an assertion at the end of a wire-format build, where a slot that is
    /// not full usually means a length calculation disagreed with the writes.
    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.pos == self.slot.len()
    }
}

/// Prints cursor state — `position`, `remaining`, `len` — and never a byte of the slot.
///
/// Hand-written rather than derived, and the difference is not cosmetic. The one data
/// field here is `slot: &'a mut [u8]`, so a derived `Debug` printed the borrowed bytes
/// verbatim: a writer six bytes into an eight-byte slot rendered as
/// `SlotWriter { slot: [222, 173, 190, 239, 202, 254, 0, 0], pos: 6 }` — live secret
/// material, in decimal, in whatever log line the `{:?}` went to. A `SlotWriter` is alive
/// exactly while the slot holds that material, and the case this type is built for, a
/// wire format whose offsets are hard to get right, is precisely the case where someone
/// reaches for `dbg!`. Every other secret-bearing type in the crate hand-writes `Debug`
/// for the same reason; [`Fixed`](crate::Fixed), [`Dynamic`](crate::Dynamic) and
/// [`EncodedSecret`](crate::EncodedSecret) print a flat `[REDACTED]`.
///
/// This one prints the cursor rather than `[REDACTED]` because the cursor is the thing
/// worth seeing when an offset is wrong, and it is not secret material: `len` is the slot
/// length the caller chose and passed to the constructor, and `position` counts the bytes
/// that caller wrote. None of the three numbers depends on the *value* of any byte,
/// written or unwritten — which is what makes the output safe to put in a log and safe
/// to rely on.
///
/// ```rust
/// use secure_gate::{Fixed, SlotWriter};
///
/// let secret = Fixed::<[u8; 8]>::new_with(|slot| {
///     let mut w = SlotWriter::new(slot);
///     w.push_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
///
///     let shown = format!("{:?}", w);
///     assert_eq!(shown, "SlotWriter { position: 6, remaining: 2, len: 8 }");
///     assert!(!shown.contains("222"), "0xDE is 222, which the derived impl printed");
/// });
/// assert_eq!(format!("{:?}", secret), "[REDACTED]");
/// ```
impl core::fmt::Debug for SlotWriter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlotWriter")
            .field("position", &self.pos)
            .field("remaining", &self.remaining())
            .field("len", &self.slot.len())
            .finish()
    }
}

/// Writes into the slot, failing rather than panicking when it is full.
///
/// Present so a slot can be handed to code that writes through [`std::io::Write`] — a
/// serializer, an encoder, a hasher's output sink. Overrun is reported as
/// [`ErrorKind::WriteZero`](std::io::ErrorKind::WriteZero) rather than as a panic,
/// because a `Write` implementation returning an error is how that interface expects to
/// refuse.
///
/// Note the difference from [`push_slice`](SlotWriter::push_slice), which panics: this
/// path exists for foreign code that cannot be asked to respect a length, so an error is
/// the only way to tell it to stop.
///
/// # Which call reports the overrun, and what the slot holds when it does
///
/// Panic-versus-error is not the whole of the difference. The other half is *when* the
/// refusal arrives and what is in the slot by then. [`push_slice`](SlotWriter::push_slice)
/// checks the whole length before it copies anything, so an overrun there leaves the slot
/// byte-for-byte as it was. `write` cannot do that and stay inside its contract:
/// [`Write::write`](std::io::Write::write) is defined to accept a prefix and report how
/// much it took, so an oversized `buf` is a **short write** — `min(buf.len(),
/// remaining())` bytes are copied, `Ok(n)` comes back, and `WriteZero` appears only on a
/// *later* call, once the slot has no room left at all.
///
/// | Call | Oversized payload | Slot afterwards |
/// |------|-------------------|-----------------|
/// | [`push_slice`](SlotWriter::push_slice) | panics, naming the shortfall | untouched — the check runs before any copy |
/// | [`write_all`](std::io::Write::write_all) | `Err` of kind `WriteZero` | holds the bytes that fit |
/// | [`write`](std::io::Write::write) | `Ok(n)` with `n < buf.len()`, no error | holds the bytes that fit |
///
/// So `write_all` is the call that surfaces overrun as an error, and it is the one to
/// prefer. A bare `write` whose return value is ignored surfaces nothing at all: the
/// weaker signal in the likelier case, since dropping a `write` count on the floor is the
/// mistake `write_all` exists to prevent.
///
/// Either way, and unlike `push_slice`, a fill driven through this impl can leave a
/// **partial value** in the slot: the bytes that fit, with whatever the slot already held
/// behind them. That is indistinguishable, by inspection of the slot, from a deliberate
/// short write. Assert the length you meant to reach instead —
/// [`is_full`](SlotWriter::is_full) when the writes were supposed to fill the slot,
/// [`position`](SlotWriter::position) or [`remaining`](SlotWriter::remaining) when they
/// were not — which is the same post-condition the `push_slice` example asserts, applied
/// to a fill you did not write yourself:
///
/// ```rust
/// use std::io::{ErrorKind, Write};
/// use secure_gate::{Fixed, RevealSecret, SlotWriter};
///
/// let truncated = Fixed::<[u8; 4]>::new_with(|slot| {
///     let mut w = SlotWriter::new(slot);
///
///     let err = w.write_all(&[1, 2, 3, 4, 5, 6]).unwrap_err();
///     assert_eq!(err.kind(), ErrorKind::WriteZero);
///
///     // The slot is NOT untouched: four bytes were taken before the refusal.
///     assert!(w.is_full());
///     assert_eq!(w.remaining(), 0);
/// });
/// assert_eq!(truncated.expose_secret(), &[1, 2, 3, 4]);
/// ```
#[cfg(feature = "std")]
impl std::io::Write for SlotWriter<'_> {
    /// Copies `min(buf.len(), remaining())` bytes and returns that count.
    ///
    /// An oversized `buf` is a short write, not an error: the return value is the only
    /// place the shortfall is reported, so a caller that ignores it gets a silently
    /// truncated slot. [`WriteZero`](std::io::ErrorKind::WriteZero) is returned only when
    /// space is wanted and none remains; an empty `buf` wants none and always succeeds
    /// with `Ok(0)`.
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.remaining() == 0 && !buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "SlotWriter is full",
            ));
        }
        let n = core::cmp::min(buf.len(), self.remaining());
        let end = self.pos + n;
        self.slot[self.pos..end].copy_from_slice(&buf[..n]);
        self.pos = end;
        Ok(n)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
