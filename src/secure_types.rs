// =================================================================================
// src/secure_types.rs
// =================================================================================

//! # `secure-types` — Inspired by `secrecy`: Zero-overhead, feature-gated secrets
//!
//! A thin, `no_std`-friendly wrapper for sensitive data (keys, passwords, etc.).
//! - Explicit access via `ExposeSecret` trait.
//! - Auto-zeroization on drop (via `zeroize`).
//! - Redacted in `Debug`.
//! - Fallback to plain `T` when `zeroize` disabled.
//! - Ergonomic: `secure!()` macro + type aliases.
//!
//! ## Features
//! - `zeroize` (default): Enables `SecretBox<T>` + wiping.
//! - `serde`: Deserialize support; Serialize opt-in via `SerializableSecret`.
//!

use alloc::string::ToString;
#[cfg(all(feature = "serde", feature = "zeroize"))]
use secrecy::SerializableSecret;
#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
#[cfg(feature = "serde")]
use serde::{de, Serialize, Serializer};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

// Helper trait for downcast in finish_mut (under zeroize only)
#[cfg(feature = "zeroize")]
use core::any::Any;
#[cfg(feature = "zeroize")]
pub(crate) trait AsAnyMut {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
#[cfg(feature = "zeroize")]
impl<T: 'static> AsAnyMut for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// Other imports
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    convert::Infallible,
    fmt::{self, Debug},
    str::FromStr,
};

#[cfg(not(feature = "zeroize"))]
/// Fallback `ExposeSecret` trait when `zeroize` feature is disabled.
/// Provides explicit, auditable access to the inner secret value.
pub trait ExposeSecret<T: ?Sized> {
    /// Expose the secret: auditable access point.
    fn expose_secret(&self) -> &T;
}
#[cfg(not(feature = "zeroize"))]
/// Fallback `ExposeSecretMut` trait when `zeroize` feature is disabled.
/// Provides explicit, auditable mutable access to the inner secret value.
pub trait ExposeSecretMut<T: ?Sized> {
    /// Expose mutable secret.
    fn expose_secret_mut(&mut self) -> &mut T;
}
/// Core secure wrapper: `SecretBox<T>` (gated) or `Box<T>`.
#[cfg(feature = "zeroize")]
pub struct Secure<T: Zeroize + ?Sized>(SecretBox<T>);
#[cfg(not(feature = "zeroize"))]
/// Fallback secure wrapper when `zeroize` feature is disabled.
/// Wraps the value in `Box<T>` for heap allocation without zeroization.
pub struct Secure<T: ?Sized>(Box<T>);
#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> Secure<T> {
    /// Create from value.
    #[inline]
    pub fn new(value: T) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Sized> Secure<T> {
    /// Create from value.
    #[inline]
    pub fn new(value: T) -> Self {
        Self(Box::new(value))
    }
}
#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Secure<T> {
    /// Expose immutable reference.
    #[inline]
    pub fn expose(&self) -> &T {
        self.0.expose_secret()
    }
    /// Expose mutable reference.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Secure<T> {
    /// Expose immutable reference.
    #[inline]
    pub fn expose(&self) -> &T {
        &self.0
    }
    /// Expose mutable reference.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
// FIXED: Restore type name in Debug for consistency with fallback + test expectations
// Includes "Secure<[REDACTED]>" without quotes/leaks
#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Debug for Secure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<[REDACTED]>")
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Debug for Secure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<[REDACTED]>")
    }
}
#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ExposeSecret<T> for Secure<T> {
    fn expose_secret(&self) -> &T {
        self.0.expose_secret()
    }
}
#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ExposeSecretMut<T> for Secure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecret<T> for Secure<T> {
    fn expose_secret(&self) -> &T {
        self.expose()
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecretMut<T> for Secure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_mut()
    }
}
#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Clone for Secure<T> {
    fn clone(&self) -> Self {
        Self::init_with(|| self.expose().clone())
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Clone + ?Sized> Clone for Secure<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Default for Secure<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Default + Sized> Default for Secure<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

// Specific impl for Secure<Vec<u8>>
#[cfg(feature = "zeroize")]
impl Zeroize for Secure<Vec<u8>> {
    fn zeroize(&mut self) {
        self.expose_mut().as_mut_slice().zeroize();
    }
}

// String safe fallback (zeroize-only, no unsafe-wipe)
#[cfg(all(feature = "zeroize", not(feature = "unsafe-wipe")))]
impl Zeroize for Secure<String> {
    fn zeroize(&mut self) {
        let len = self.expose().len();
        let zeros = "\0".repeat(len);
        self.expose_mut().replace_range(..len, &zeros);
    }
}

// String unsafe full-cap (unsafe-wipe feature)
#[cfg(feature = "unsafe-wipe")]
impl Zeroize for Secure<String> {
    fn zeroize(&mut self) {
        use core::hint::black_box;

        // Pre-fetch for borrow hygiene + timing poison
        let original_len = self.expose().len();
        let original_cap = self.expose().capacity();

        black_box((original_len, original_cap));

        let s = self.expose_mut();
        // Std req: Unsafe call, but Secure pins/guarded
        let vec = unsafe { s.as_mut_vec() };

        // SAFETY: Own full alloc [0..cap]; bounded writes, no reallocs mid-wipe
        unsafe {
            use core::sync;

            let ptr = vec.as_mut_ptr();
            let len = vec.len();
            let cap = vec.capacity();

            // Invariant: Cap >= len (Secure's job to uphold)
            debug_assert!(cap >= len, "Cap < len: Secure invariant broken");

            // Unified full-wipe: Payload + slack in one bounded call
            // Volatile via ptr API
            // core::ptr::write_bytes(ptr, 0u8, cap);  // alternate wipe version
            core::slice::from_raw_parts_mut(ptr, cap).zeroize(); // gold standard

            // Dual defense: Opt-fence + mask
            sync::atomic::compiler_fence(sync::atomic::Ordering::SeqCst);
            // Shadow pad for var
            let _dummy = [0u8; 1024];
            black_box(&_dummy);
        }

        // Post-check: Drift detector
        debug_assert_eq!(s.len(), original_len, "Len drifted");
        debug_assert_eq!(s.capacity(), original_cap, "Cap drifted");
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ZeroizeOnDrop for Secure<T> {}
#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Secure<T> {
    /// Init with closure (clone + zeroize local).
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self(SecretBox::init_with(ctr))
    }
    /// Fallible init with closure.
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        SecretBox::try_init_with(ctr).map(Self)
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Sized> Secure<T> {
    /// Init with closure (clone + zeroize local).
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self::new(ctr())
    }
    /// Fallible init with closure.
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        ctr().map(Self::new)
    }
}
#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Secure<T> {
    /// Init in-place with mut closure.
    pub fn init_with_mut(ctr: impl FnOnce(&mut T)) -> Self {
        Self(SecretBox::init_with_mut(ctr))
    }
}
#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Secure<T> {
    /// Extract the inner value as `Box<T>`, zeroizing the original wrapper.
    ///
    /// # Security Note
    /// This clones the secret for extraction (unavoidable for ownership transfer).
    /// The source is explicitly zeroized before return to mitigate leaks.
    /// Use only for FFI/handover—re-wrap immediately in a new `Secure` if needed.
    /// Prefer scoped `expose_mut()` for mutations to avoid extraction entirely.
    pub fn into_inner(mut self) -> Box<T> {
        let value = self.0.expose_secret().clone(); // Safe clone (preserves Zeroize if T implements)
        self.0.zeroize(); // Explicit wipe of original (redundant with drop, but immediate)
        Box::new(value)
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Secure<T> {
    /// Consume and return the inner boxed value.
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}
#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<'de, T> de::Deserialize<'de> for Secure<T>
where
    T: de::Deserialize<'de> + Zeroize + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = T::deserialize(deserializer)?;
        Ok(Self::new(value))
    }
}
#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<'de, T> de::Deserialize<'de> for Secure<T>
where
    T: de::Deserialize<'de> + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::new)
    }
}
#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<T> Serialize for Secure<T>
where
    T: SerializableSecret + Serialize + Sized + Zeroize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose().serialize(serializer)
    }
}
#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<T> Serialize for Secure<T>
where
    T: Serialize + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose().serialize(serializer)
    }
}
#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized + 'static> Secure<T> {
    /// After mutations, call this to shrink capacity (for `Vec<u8>`, `String`) and
    /// minimize potential leaks from excess allocation. Uses `shrink_to_fit()`—best-effort only;
    /// does *not* guarantee zeroing of freed bytes (they may linger until overwritten by allocator/OS).
    /// For dynamic types, zeroization on drop covers only up to `.len()`.
    ///
    /// # Security Note
    /// Prefer avoiding large buffers with secrets, then truncating—create sized-from-start where possible.
    /// No-op for fixed-size types (e.g., `[u8; 32]`).
    pub fn finish_mut(&mut self) -> &mut T {
        if let Some(v) = self.expose_mut().as_any_mut().downcast_mut::<Vec<u8>>() {
            v.shrink_to_fit();
        } else if let Some(s) = self.expose_mut().as_any_mut().downcast_mut::<String>() {
            s.shrink_to_fit();
        }
        self.expose_mut()
    }
}

/// Secure byte slice: `Secure<[u8]>` (From<Vec<u8>>).
pub type SecureBytes = Secure<[u8]>;
impl From<Vec<u8>> for SecureBytes {
    fn from(vec: Vec<u8>) -> Self {
        let boxed = vec.into_boxed_slice();
        #[cfg(feature = "zeroize")]
        {
            Self(SecretBox::new(boxed))
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self(boxed)
        }
    }
}
#[cfg(feature = "zeroize")]
impl Clone for SecureBytes
where
    [u8]: Zeroize,
{
    fn clone(&self) -> Self {
        Self::from(self.expose().to_vec())
    }
}
#[cfg(not(feature = "zeroize"))]
impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_vec())
    }
}
/// Secure string: `Secure<str>` (From<String>, From<&str>, FromStr).
pub type SecureStr = Secure<str>;
impl From<String> for SecureStr {
    fn from(s: String) -> Self {
        let boxed = s.into_boxed_str();
        #[cfg(feature = "zeroize")]
        {
            Self(SecretBox::new(boxed))
        }
        #[cfg(not(feature = "zeroize"))]
        {
            Self(boxed)
        }
    }
}
impl From<&str> for SecureStr {
    fn from(s: &str) -> Self {
        Self::from(String::from(s))
    }
}
impl FromStr for SecureStr {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}
#[cfg(feature = "zeroize")]
impl Clone for SecureStr {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_string())
    }
}
#[cfg(not(feature = "zeroize"))]
impl Clone for SecureStr {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_string())
    }
}

/// Recommended for nearly all password use — immutable, zero-realloc, safest
/// Uses secrecy::SecretBox<str> under the hood
#[cfg(feature = "zeroize")]
pub type SecurePassword = Secure<SecretBox<str>>;

/// Explicitly mutable password — only when you need to grow/append at runtime
/// e.g. building credentials incrementally
#[cfg(feature = "zeroize")]
pub type SecurePasswordMut = Secure<SecretBox<String>>;

/// Fallback aliases when zeroize disabled
#[cfg(not(feature = "zeroize"))]
pub type SecurePassword = Secure<String>;

/// Fallback `From` impls for `SecurePassword` when `zeroize` feature is disabled
/// (treats as plain `Secure<String>`)
#[cfg(not(feature = "zeroize"))]
impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

#[cfg(not(feature = "zeroize"))]
impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// From<&str> and From<String> for SecurePassword (zeroize mode, immutable)
#[cfg(feature = "zeroize")]
impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        Self::new(SecretBox::new(s.into()))
    }
}

#[cfg(feature = "zeroize")]
impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        Self::new(SecretBox::new(s.into_boxed_str()))
    }
}

/// From<&str> and From<String> for SecurePasswordMut (zeroize mode, mutable)
#[cfg(feature = "zeroize")]
impl From<&str> for SecurePasswordMut {
    fn from(s: &str) -> Self {
        Self::new(SecretBox::new(Box::new(s.to_string())))
    }
}

#[cfg(feature = "zeroize")]
impl From<String> for SecurePasswordMut {
    fn from(s: String) -> Self {
        Self::new(SecretBox::new(Box::new(s)))
    }
}

/// Secure 32-byte key (e.g., for AES-256).
pub type SecureKey32 = Secure<[u8; 32]>;
/// Secure 64-byte key (e.g., for longer hashes).
pub type SecureKey64 = Secure<[u8; 64]>;
/// Secure IV (16 bytes, e.g., for AES-GCM).
pub type SecureIv = Secure<[u8; 16]>;
/// Secure salt (16 bytes).
pub type SecureSalt = Secure<[u8; 16]>;
/// Secure 12-byte nonce (e.g., for ChaCha20-Poly1305).
pub type SecureNonce12 = Secure<[u8; 12]>;
/// Secure 16-byte nonce (e.g., for AES-GCM).
pub type SecureNonce16 = Secure<[u8; 16]>;
/// Secure 24-byte nonce.
pub type SecureNonce24 = Secure<[u8; 24]>;
