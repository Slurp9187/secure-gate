// ==========================================================================
// src/rng.rs
// ==========================================================================
use crate::{Dynamic, Fixed};
use rand::rngs::OsRng;
use rand::TryRngCore;

/// Fixed-length cryptographically secure random value.
///
/// Can only be constructed via `.generate()` — guarantees freshness from the OS RNG.
pub struct FixedRng<const N: usize>(Fixed<[u8; N]>);

impl<const N: usize> FixedRng<N> {
    /// Generate a fresh random value using the OS RNG.
    ///
    /// Panics on RNG failure — this is intentional and correct for high-assurance crypto code.
    pub fn generate() -> Self {
        let mut bytes = [0u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failed — this should never happen on supported platforms");
        Self(Fixed::new(bytes))
    }

    /// Expose the secret bytes (read-only).
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8; N] {
        self.0.expose_secret()
    }

    /// Returns the fixed length of this random value.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true if the random value has zero length.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> core::fmt::Debug for FixedRng<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Heap-allocated cryptographically secure random bytes.
pub struct DynamicRng(Dynamic<Vec<u8>>);

impl DynamicRng {
    /// Generate a fresh random byte vector of the given length.
    pub fn generate(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failed — this should never happen on supported platforms");
        Self(Dynamic::from(bytes))
    }

    /// Generate a random alphanumeric string (base62) of exact length.
    ///
    /// Uses unbiased rejection sampling — cryptographically sound.
    pub fn generate_string(len: usize) -> Dynamic<String> {
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let byte = loop {
                let val = OsRng
                    .try_next_u32()
                    .expect("OsRng failed — this should never happen on supported platforms");
                let candidate = val % 62;
                if val < (u32::MAX / 62) * 62 {
                    break candidate as u8;
                }
            };
            let c = if byte < 10 {
                (b'0' + byte) as char
            } else if byte < 36 {
                (b'a' + (byte - 10)) as char
            } else {
                (b'A' + (byte - 36)) as char
            };
            s.push(c);
        }
        Dynamic::from(s)
    }

    /// Expose the secret bytes (read-only).
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Returns the length of the random byte vector.
    /// This is public metadata — does **not** expose the secret.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the random byte vector is empty.
    /// This is public metadata — does **not** expose the secret.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume and return the inner `Dynamic<Vec<u8>>`.
    #[inline(always)]
    pub fn into_inner(self) -> Dynamic<Vec<u8>> {
        self.0
    }
}

impl core::fmt::Debug for DynamicRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
