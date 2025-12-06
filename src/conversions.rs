// ==========================================================================
// src/conversions.rs
// ==========================================================================
#[cfg(feature = "conversions")]
use alloc::string::String;
#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;

#[cfg(feature = "conversions")]
pub trait SecureConversionsExt {
    fn to_hex(&self) -> String;
    fn to_hex_upper(&self) -> String;
    fn to_base64url(&self) -> String;
    fn ct_eq(&self, other: &Self) -> bool;
}

#[cfg(feature = "conversions")]
impl SecureConversionsExt for [u8] {
    #[inline]
    fn to_hex(&self) -> String {
        hex::encode(self)
    }
    #[inline]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }
    #[inline]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }
    #[inline]
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

#[cfg(feature = "conversions")]
impl<const N: usize> SecureConversionsExt for [u8; N] {
    #[inline]
    fn to_hex(&self) -> String {
        hex::encode(self)
    }
    #[inline]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }
    #[inline]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }
    #[inline]
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self.as_slice(), other.as_slice()).into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexString — validated, lowercase hex wrapper
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(feature = "conversions")]
#[derive(Clone, Debug)] // REMOVED PartialEq/Eq derive
pub struct HexString(crate::Dynamic<String>);

#[cfg(feature = "conversions")]
impl HexString {
    pub fn new(s: String) -> Result<Self, &'static str> {
        let lower = s.to_ascii_lowercase();
        if lower.len() % 2 != 0 || !lower.chars().all(|c| c.is_ascii_hexdigit()) {
            Err("invalid hex string")
        } else {
            Ok(Self(crate::Dynamic::new(lower)))
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(self.0.expose_secret()).expect("HexString is always valid")
    }

    pub fn byte_len(&self) -> usize {
        self.0.expose_secret().len() / 2
    }
}

#[cfg(feature = "conversions")]
impl core::ops::Deref for HexString {
    type Target = crate::Dynamic<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(feature = "conversions", feature = "zeroize"))]
impl secrecy::ExposeSecret<String> for HexString {
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

// Manual constant-time PartialEq (safe, since we're under conversions)
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
#[derive(Clone, Debug)] // REMOVED PartialEq/Eq derive
pub struct RandomHex(HexString);

#[cfg(all(feature = "rand", feature = "conversions"))]
impl RandomHex {
    pub(crate) fn new_fresh(hex: HexString) -> Self {
        Self(hex)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
    pub fn byte_len(&self) -> usize {
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

#[cfg(all(feature = "rand", feature = "conversions", feature = "zeroize"))]
impl secrecy::ExposeSecret<String> for RandomHex {
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

// Manual constant-time PartialEq (safe)
#[cfg(all(feature = "rand", feature = "conversions"))]
impl PartialEq for RandomHex {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0) // Delegates to HexString's ct_eq impl
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl Eq for RandomHex {}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl<const N: usize> crate::rng::FixedRng<N> {
    pub fn random_hex() -> RandomHex {
        // Scoped block to limit the lifetime of the temporary FixedRng<N>
        let hex = {
            let fresh_rng = Self::generate(); // temporary owns the secret
            hex::encode(fresh_rng.expose_secret()) // borrow only for encoding
        }; // ← fresh_rng dropped here → zeroized immediately (if zeroize enabled)

        RandomHex::new_fresh(HexString(crate::Dynamic::new(hex)))
    }
}
