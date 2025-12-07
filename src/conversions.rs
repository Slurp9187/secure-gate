// ==========================================================================
// src/conversions.rs
// ==========================================================================

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]

#[cfg(feature = "conversions")]
use alloc::string::String;
#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;
#[cfg(feature = "conversions")]
use zeroize::Zeroize;

/// Extension trait for safe, explicit conversions of secret byte data.
///
/// All methods require the caller to first call `.expose_secret()` (or `.expose_secret_mut()`).
/// This makes every secret access loud, grep-able, and auditable.
///
/// # Example
///
/// ```
/// # use secure_gate::{fixed_alias, SecureConversionsExt};
/// fixed_alias!(Aes256Key, 32);
/// let key = Aes256Key::from([0x42u8; 32]);
/// let hex = key.expose_secret().to_hex();         // → "424242..."
/// let b64 = key.expose_secret().to_base64url();   // URL-safe, no padding
/// # assert_eq!(hex, "4242424242424242424242424242424242424242424242424242424242424242");
/// ```
#[cfg(feature = "conversions")]
pub trait SecureConversionsExt {
    /// Encode secret bytes as lowercase hexadecimal.
    fn to_hex(&self) -> String;

    /// Encode secret bytes as uppercase hexadecimal.
    fn to_hex_upper(&self) -> String;

    /// Encode secret bytes as URL-safe base64 (no padding).
    fn to_base64url(&self) -> String;

    /// Constant-time equality comparison.
    ///
    /// Returns `true` if the two secrets are equal, `false` otherwise.
    /// Uses `subtle::ConstantTimeEq` under the hood – safe against timing attacks.
    fn ct_eq(&self, other: &Self) -> bool;
}

#[cfg(feature = "conversions")]
impl SecureConversionsExt for [u8] {
    #[inline(always)]
    fn to_hex(&self) -> String {
        hex::encode(self)
    }

    #[inline(always)]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }

    #[inline(always)]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }

    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

#[cfg(feature = "conversions")]
impl<const N: usize> SecureConversionsExt for [u8; N] {
    #[inline(always)]
    fn to_hex(&self) -> String {
        hex::encode(self)
    }

    #[inline(always)]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }

    #[inline(always)]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }

    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self.as_slice(), other.as_slice()).into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexString — validated, lowercase hex wrapper
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "conversions")]
#[derive(Clone, Debug)]
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
fn zeroize_input(s: &mut String) {
    #[cfg(feature = "zeroize")]
    {
        // SAFETY: String's internal buffer is valid for writes of its current length
        let vec = unsafe { s.as_mut_vec() };
        vec.zeroize();
    }
}

#[cfg(feature = "conversions")]
impl core::ops::Deref for HexString {
    type Target = crate::Dynamic<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Manual constant-time equality – prevents timing attacks on hex strings
#[cfg(feature = "conversions")]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .expose_secret()
            .as_bytes()
            .ct_eq(other.0.expose_secret().as_bytes())
    }
}

#[cfg(feature = "conversions")]
impl Eq for HexString {}

// ─────────────────────────────────────────────────────────────────────────────
// RandomHex — only constructible from fresh RNG
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(all(feature = "rand", feature = "conversions"))]
#[derive(Clone, Debug)]
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
        self.0.eq(&other.0)
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
