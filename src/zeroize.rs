// src/zeroize.rs
// Full zeroize integration — only exists when feature is enabled

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "zeroize")]
use secrecy::SecretBox;

// Zeroizing versions — opt-in, non-breaking
#[cfg(feature = "zeroize")]
pub type FixedZeroizing<T> = Zeroizing<T>;

#[cfg(feature = "zeroize")]
pub type DynamicZeroizing<T: ?Sized> = SecretBox<T>;

// Easy conversion
#[cfg(feature = "zeroize")]
impl<T: Copy + Zeroize> From<crate::Fixed<T>> for FixedZeroizing<T> {
    fn from(fixed: crate::Fixed<T>) -> Self {
        Zeroizing::new(fixed.0)
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> From<crate::Dynamic<T>> for DynamicZeroizing<T> {
    fn from(dynamic: crate::Dynamic<T>) -> Self {
        SecretBox::new(dynamic.0)
    }
}

// Auto-wipe on drop — this is the real security
#[cfg(feature = "zeroize")]
impl<T: Copy + Zeroize> ZeroizeOnDrop for crate::Fixed<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for crate::Dynamic<T> {}
