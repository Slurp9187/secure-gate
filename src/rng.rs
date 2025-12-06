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
    pub fn rng() -> Self {
        let mut bytes = [0u8; N];
        OS_RNG.with(|rng| {
            rng.borrow_mut()
                .try_fill_bytes(&mut bytes)
                .expect("OsRng failed — this should never happen");
        });
        Self(Fixed(bytes))
    }

    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0 .0
    }
}

impl<const N: usize> core::ops::Deref for FixedRng<N> {
    type Target = Fixed<[u8; N]>;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for FixedRng<N> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> core::fmt::Debug for FixedRng<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED_RANDOM]")
    }
}

pub struct DynamicRng(Dynamic<Vec<u8>>);

impl DynamicRng {
    #[inline(always)]
    pub fn rng(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OS_RNG.with(|rng| {
            rng.borrow_mut()
                .try_fill_bytes(&mut bytes)
                .expect("OsRng failed — this should never happen");
        });
        Self(Dynamic::new(bytes))
    }

    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0 .0
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0 .0.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0 .0.is_empty()
    }
}

impl core::ops::Deref for DynamicRng {
    type Target = Dynamic<Vec<u8>>;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for DynamicRng {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::fmt::Debug for DynamicRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED_RANDOM]")
    }
}
