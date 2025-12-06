#[cfg(feature = "conversions")]
use alloc::string::String;

#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;

#[cfg(all(feature = "rand", feature = "conversions"))]
use secrecy::ExposeSecret;

pub trait SecureConversionsExt {
    fn to_hex(&self) -> String;
    fn to_hex_upper(&self) -> String;
    fn to_hex_lowercase(&self) -> String;
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
    fn to_hex_lowercase(&self) -> String {
        hex::encode(self).to_ascii_lowercase()
    }

    #[inline]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }

    #[inline]
    fn ct_eq(&self, other: &[u8]) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

#[cfg(feature = "conversions")]
trait _AssertNoImplForFixed {}
#[cfg(feature = "conversions")]
impl<T> _AssertNoImplForFixed for T where T: SecureConversionsExt {}

#[cfg(feature = "conversions")]
impl<const N: usize> _AssertNoImplForFixed for crate::Fixed<[u8; N]> {}

#[cfg(feature = "conversions")]
#[derive(Clone, Debug, PartialEq)]
pub struct HexString(crate::Dynamic<String>);

#[cfg(feature = "conversions")]
impl HexString {
    pub fn new(s: String) -> Result<Self, &'static str> {
        let lower = s.to_lowercase();
        if lower.len() % 2 != 0 || !lower.chars().all(|c| c.is_ascii_hexdigit()) {
            Err("Invalid hex: must be even length with 0-9a-fA-F chars")
        } else {
            Ok(Self(crate::Dynamic::new(lower)))
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(self.expose_secret()).expect("Validated hex")
    }

    pub fn byte_len(&self) -> usize {
        self.expose_secret().len() / 2
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
#[derive(Clone, Debug, PartialEq)]
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
    #[inline(always)]
    pub fn random_hex() -> RandomHex {
        let rng = Self::rng();
        let hex_str = rng.expose_secret().to_hex_lowercase();
        let hex_string = HexString::new(hex_str).expect("hex::encode always produces valid hex");
        RandomHex::new(hex_string)
    }
}
