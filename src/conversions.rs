// ==========================================================================
// src/conversions.rs
// ==========================================================================

// Allow unsafe_code when conversions is enabled (needed for hex string validation)
// but forbid it when neither conversions nor zeroize is enabled
#![cfg_attr(
    not(any(feature = "zeroize", feature = "conversions")),
    forbid(unsafe_code)
)]

#[cfg(feature = "conversions")]
use alloc::string::String;
#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;

/// Extension trait for safe, explicit conversions of secret byte data.
///
/// All methods require the caller to first call `.expose_secret()` (or `.expose_secret_mut()`).
/// This makes every secret access loud, grep-able, and auditable.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "conversions")]
/// # {
/// # use secure_gate::{fixed_alias, SecureConversionsExt};
/// # fixed_alias!(Aes256Key, 32);
/// # let key = Aes256Key::from([0x42u8; 32]);
/// # let hex = key.expose_secret().to_hex();         // → "424242..."
/// # let b64 = key.expose_secret().to_base64url();   // URL-safe, no padding
/// # assert_eq!(hex, "4242424242424242424242424242424242424242424242424242424242424242");
/// # }
/// ```
// Trait is available when either conversions or ct-eq is enabled
#[cfg(any(feature = "conversions", feature = "ct-eq"))]
pub trait SecureConversionsExt {
    /// Encode secret bytes as lowercase hexadecimal.
    #[cfg(feature = "conversions")]
    fn to_hex(&self) -> String;

    /// Encode secret bytes as uppercase hexadecimal.
    #[cfg(feature = "conversions")]
    fn to_hex_upper(&self) -> String;

    /// Encode secret bytes as URL-safe base64 (no padding).
    #[cfg(feature = "conversions")]
    fn to_base64url(&self) -> String;

    /// Constant-time equality comparison.
    ///
    /// Returns `true` if the two secrets are equal, `false` otherwise.
    /// Uses `subtle::ConstantTimeEq` under the hood – safe against timing attacks.
    #[cfg(feature = "ct-eq")]
    fn ct_eq(&self, other: &Self) -> bool;
}

#[cfg(any(feature = "conversions", feature = "ct-eq"))]
impl SecureConversionsExt for [u8] {
    #[cfg(feature = "conversions")]
    #[inline(always)]
    fn to_hex(&self) -> String {
        hex::encode(self)
    }

    #[cfg(feature = "conversions")]
    #[inline(always)]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }

    #[cfg(feature = "conversions")]
    #[inline(always)]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }

    #[cfg(feature = "ct-eq")]
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

#[cfg(any(feature = "conversions", feature = "ct-eq"))]
impl<const N: usize> SecureConversionsExt for [u8; N] {
    #[cfg(feature = "conversions")]
    #[inline(always)]
    fn to_hex(&self) -> String {
        hex::encode(self)
    }

    #[cfg(feature = "conversions")]
    #[inline(always)]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }

    #[cfg(feature = "conversions")]
    #[inline(always)]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }

    #[cfg(feature = "ct-eq")]
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self.as_slice(), other.as_slice()).into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexString — validated, lowercase hex wrapper
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "conversions")]
#[derive(Debug)]
pub struct HexString(crate::Dynamic<String>);

#[cfg(feature = "conversions")]
impl HexString {
    /// Create a new `HexString` from a `String`, validating it in-place.
    ///
    /// The input `String` is consumed. If validation fails and the `zeroize` feature
    /// is enabled, the rejected bytes are zeroized before the error is returned.
    ///
    /// Validation rules:
    /// - Even length
    /// - Only ASCII hex digits (`0-9`, `a-f`, `A-F`)
    /// - Uppercase letters are normalized to lowercase
    ///
    /// Zero extra allocations are performed – everything happens on the original buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err("invalid hex string")` if validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::conversions::HexString;
    /// let valid = HexString::new("deadbeef".to_string()).unwrap();
    /// assert_eq!(valid.expose_secret(), "deadbeef");
    /// ```
    pub fn new(mut s: String) -> Result<Self, &'static str> {
        // Fast early check – hex strings must have even length
        if s.len() % 2 != 0 {
            zeroize_input(&mut s);
            return Err("invalid hex string");
        }

        // Work directly on the underlying bytes – no copies
        let bytes = unsafe { s.as_mut_vec() };
        let mut valid = true;
        for b in bytes.iter_mut() {
            match *b {
                b'A'..=b'F' => *b += 32, // 'A' → 'a'
                b'a'..=b'f' | b'0'..=b'9' => {}
                _ => valid = false,
            }
        }

        if valid {
            Ok(Self(crate::Dynamic::new(s)))
        } else {
            zeroize_input(&mut s);
            Err("invalid hex string")
        }
    }

    /// Decode the validated hex string back into raw bytes.
    ///
    /// Panics if the internal string is somehow invalid (impossible under correct usage).
    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(self.0.expose_secret()).expect("HexString is always valid")
    }

    /// Number of bytes the decoded hex string represents.
    pub const fn byte_len(&self) -> usize {
        self.0.expose_secret().len() / 2
    }
}

// Private helper – wipes rejected input when `zeroize` is enabled
#[cfg(feature = "conversions")]
#[inline(always)]
#[allow(clippy::ptr_arg)] // Need &mut String for as_mut_vec()
fn zeroize_input(s: &mut String) {
    #[cfg(feature = "zeroize")]
    {
        // SAFETY: String's internal buffer is valid for writes of its current length
        let vec = unsafe { s.as_mut_vec() };
        zeroize::Zeroize::zeroize(vec);
    }
    #[cfg(not(feature = "zeroize"))]
    {
        let _ = s; // Suppress unused variable warning when zeroize is disabled
    }
}

#[cfg(feature = "conversions")]
impl core::ops::Deref for HexString {
    type Target = crate::Dynamic<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Constant-time equality for hex strings – prevents timing attacks when ct-eq enabled
#[cfg(all(feature = "conversions", feature = "ct-eq"))]
#[cfg(all(feature = "conversions", feature = "ct-eq"))]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .expose_secret()
            .as_bytes()
            .ct_eq(other.0.expose_secret().as_bytes())
    }
}

#[cfg(all(feature = "conversions", not(feature = "ct-eq")))]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[cfg(all(feature = "conversions", feature = "ct-eq"))]
impl Eq for HexString {}

// Fallback: Standard string equality when ct-eq not enabled (secure enough for validation)
#[cfg(all(feature = "conversions", not(feature = "ct-eq")))]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[cfg(all(feature = "conversions", not(feature = "ct-eq")))]
impl Eq for HexString {}

#[cfg(feature = "conversions")]
impl Clone for HexString {
    fn clone(&self) -> Self {
        let cloned_string = self.0.expose_secret().clone();
        HexString(crate::Dynamic::new(cloned_string))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RandomHex — only constructible from fresh RNG
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(all(feature = "rand", feature = "conversions"))]
#[derive(Debug)]
pub struct RandomHex(HexString);

#[cfg(all(feature = "rand", feature = "conversions"))]
impl RandomHex {
    /// Internal constructor – only called by `FixedRng<N>::random_hex()`.
    pub(crate) fn new_fresh(hex: HexString) -> Self {
        Self(hex)
    }

    /// Decode the random hex string back into raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Number of bytes the decoded hex string represents.
    pub const fn byte_len(&self) -> usize {
        self.0.byte_len()
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl core::ops::Deref for RandomHex {
    type Target = HexString;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl PartialEq for RandomHex {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl Eq for RandomHex {}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl<const N: usize> crate::rng::FixedRng<N> {
    /// Generate a fresh random value and immediately return it as a validated,
    /// lower-case hex string.
    ///
    /// The intermediate random bytes are zeroized as soon as the hex string is created.
    ///
    /// # Example
    ///
    /// ```
    /// # use secure_gate::{fixed_alias_rng, conversions::RandomHex};
    /// fixed_alias_rng!(BackupCode, 16);
    /// let hex: RandomHex = BackupCode::random_hex();
    /// println!("backup code: {}", hex.expose_secret());
    /// ```
    pub fn random_hex() -> RandomHex {
        let hex = {
            let fresh_rng = Self::generate();
            hex::encode(fresh_rng.expose_secret())
        }; // fresh_rng dropped and zeroized here
        RandomHex::new_fresh(HexString(crate::Dynamic::new(hex)))
    }
}
