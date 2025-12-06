// ==========================================================================
// src/rng.rs
// ==========================================================================

use crate::{Dynamic, Fixed};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::cell::RefCell;

thread_local! {
    static OS_RNG: RefCell<OsRng> = const { RefCell::new(OsRng) };
}

pub struct FixedRng<const N: usize>(Fixed<[u8; N]>);

impl<const N: usize> FixedRng<N> {
    #[inline(always)]
    pub fn generate() -> Self {
        let mut bytes = [0u8; N];
        OS_RNG.with(|cell| {
            cell.borrow_mut()
                .try_fill_bytes(&mut bytes)
                .expect("OsRng failed — this should never happen on supported platforms");
        });
        Self(Fixed::new(bytes))
    }

    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0 .0
    }
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

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

pub struct DynamicRng(Dynamic<Vec<u8>>);

impl DynamicRng {
    #[inline(always)]
    pub fn generate(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OS_RNG.with(|cell| {
            cell.borrow_mut()
                .try_fill_bytes(&mut bytes)
                .expect("OsRng failed — this should never happen on supported platforms");
        });
        Self(Dynamic::from(bytes))
    }

    #[inline]
    pub fn generate_string(len: usize) -> Dynamic<String> {
        let mut s = String::with_capacity(len);
        OS_RNG.with(|cell| {
            let mut rng = cell.borrow_mut();
            for _ in 0..len {
                let byte = rng.try_next_u32().expect("OsRng failed") % 62;
                let c = if byte < 10 {
                    (b'0' + byte as u8) as char
                } else if byte < 36 {
                    (b'a' + (byte - 10) as u8) as char
                } else {
                    (b'A' + (byte - 36) as u8) as char
                };
                s.push(c);
            }
        });
        Dynamic::from(s)
    }

    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.expose_secret().is_empty()
    }

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
