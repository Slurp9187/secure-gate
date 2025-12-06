// ==========================================================================
// src/conversions.rs
// ==========================================================================

#[cfg(feature = "conversions")]
use alloc::string::String;

#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;

#[cfg(all(feature = "rand", feature = "conversions"))]
use secrecy::ExposeSecret;

#[cfg(feature = "conversions")]
pub trait SecureConversionsExt: sealed::Sealed {
    fn to_hex(&self) -> String;
    fn to_hex_upper(&self) -> String;
    fn to_hex_lowercase(&self) -> String;
    fn to_base64url(&self) -> String;
    fn ct_eq(&self, other: &Self) -> bool;
}

#[cfg(feature = "conversions")]
mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::Dynamic<Vec<u8>> {}
}

#[cfg(feature = "conversions")]
impl SecureConversionsExt for crate::Dynamic<Vec<u8>> {
    #[inline]
    fn to_hex(&self) -> String {
        hex::encode(self.expose_secret())
    }

    #[inline]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self.expose_secret())
    }

    #[inline]
    fn to_hex_lowercase(&self) -> String {
        hex::encode(self.expose_secret()).to_ascii_lowercase()
    }

    #[inline]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.expose_secret())
    }

    #[inline]
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(
            self.expose_secret().as_slice(),
            other.expose_secret().as_slice(),
        )
        .into()
    }
}

#[cfg(feature = "conversions")]
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[cfg(feature = "conversions")]
impl ExposeSecret<String> for HexString {
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RandomHex(pub HexString);

#[cfg(all(feature = "rand", feature = "conversions"))]
impl RandomHex {
    pub fn new(hex: HexString) -> Self {
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
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl ExposeSecret<String> for RandomHex {
    #[inline(always)]
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl<const N: usize> crate::rng::FixedRng<N> {
    pub fn random_hex() -> RandomHex {
        let rng = Self::generate();
        let bytes = rng.expose_secret();
        let hex = hex::encode(bytes);
        let validated = HexString(crate::Dynamic::new(hex));
        RandomHex(validated)
    }
}
