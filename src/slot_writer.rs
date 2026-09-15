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
/// RFC 9180-style labeled concatenation, where the length is the sum of the parts:
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
/// Anything left unwritten keeps the slot's zeros, so a short write is not undefined —
/// it is a zero tail, which is frequently what a format wants:
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
#[derive(Debug)]
pub struct SlotWriter<'a> {
    slot: &'a mut [u8],
    pos: usize,
}

impl<'a> SlotWriter<'a> {
    /// Wraps a slot, positioned at its start.
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

    /// Bytes still unwritten. These hold the slot's zeros unless written.
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
#[cfg(feature = "std")]
impl std::io::Write for SlotWriter<'_> {
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
