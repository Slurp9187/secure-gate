use arbitrary::{Arbitrary, Unstructured};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use secure_gate::{Dynamic, Fixed, ToBech32};

#[derive(Debug)]
pub struct FuzzFixed32(pub Fixed<[u8; 32]>);

#[derive(Debug)]
pub struct FuzzFixed16(pub Fixed<[u8; 16]>);

#[derive(Debug)]
pub struct FuzzDynamicVec(pub Dynamic<Vec<u8>>);

#[derive(Debug)]
pub struct FuzzDynamicString(pub Dynamic<String>);

/// Generates valid hex-encoded strings from fuzzer bytes
#[derive(Debug)]
pub struct FuzzHexString(pub String);

/// Generates valid base64url-encoded strings from fuzzer bytes
#[derive(Debug)]
pub struct FuzzBase64String(pub String);

/// Generates bech32-encoded strings using secure-gate's ToBech32 trait
/// so they round-trip correctly with try_from_bech32.
#[derive(Debug)]
pub struct FuzzBech32String(pub String);

/// Generates structured JSON strings for serde testing
#[derive(Debug)]
pub struct FuzzJsonPayload(pub String);

/// Command-driven mutation enum for diverse mutation sequences
#[derive(Debug, Arbitrary)]
pub enum FuzzAction {
    PushByte(u8),
    ExtendFromSlice(Vec<u8>),
    Truncate(usize),
    Clear,
    Reverse,
    ShrinkToFit,
    Zeroize,
}

impl<'a> Arbitrary<'a> for FuzzFixed32 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut arr = [0u8; 32];
        u.fill_buffer(&mut arr)?;
        Ok(FuzzFixed32(Fixed::new(arr)))
    }
}

impl<'a> Arbitrary<'a> for FuzzFixed16 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut arr = [0u8; 16];
        u.fill_buffer(&mut arr)?;
        Ok(FuzzFixed16(Fixed::new(arr)))
    }
}

impl<'a> Arbitrary<'a> for FuzzDynamicVec {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let vec: Vec<u8> = Arbitrary::arbitrary(u)?;
        // Cap to 4096 bytes to prevent OOM
        let capped = if vec.len() > 4096 { vec[..4096].to_vec() } else { vec };
        Ok(FuzzDynamicVec(Dynamic::new(capped)))
    }
}

impl<'a> Arbitrary<'a> for FuzzDynamicString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let s: String = Arbitrary::arbitrary(u)?;
        // Cap to 2048 chars to prevent OOM
        let capped: String = if s.len() > 2048 { s.chars().take(2048).collect() } else { s };
        Ok(FuzzDynamicString(Dynamic::new(capped)))
    }
}

impl<'a> Arbitrary<'a> for FuzzHexString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: Vec<u8> = Arbitrary::arbitrary(u)?;
        let capped = if bytes.len() > 512 { &bytes[..512] } else { &bytes[..] };
        Ok(FuzzHexString(hex::encode(capped)))
    }
}

impl<'a> Arbitrary<'a> for FuzzBase64String {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: Vec<u8> = Arbitrary::arbitrary(u)?;
        let capped = if bytes.len() > 512 { &bytes[..512] } else { &bytes[..] };
        Ok(FuzzBase64String(URL_SAFE_NO_PAD.encode(capped)))
    }
}

impl<'a> Arbitrary<'a> for FuzzBech32String {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let hrp_raw: Vec<u8> = Arbitrary::arbitrary(u)?;
        let data: Vec<u8> = Arbitrary::arbitrary(u)?;

        // Build a valid lowercase-alphanumeric HRP (bech32 requirement)
        let hrp: String = hrp_raw
            .iter()
            .take(20)
            .filter(|&&b| b.is_ascii_lowercase() || b.is_ascii_digit())
            .map(|&b| b as char)
            .collect();
        let hrp = if hrp.is_empty() { "fuzz".to_string() } else { hrp };

        // Cap data to avoid enormous bech32 strings
        let capped = if data.len() > 256 { &data[..256] } else { &data[..] };

        // Encode with secure-gate's ToBech32 so round-trips via try_from_bech32 work
        match capped.try_to_bech32(&hrp, None) {
            Ok(encoded) => Ok(FuzzBech32String(encoded)),
            Err(_) => Ok(FuzzBech32String("fuzz1vehk7cnpwgry9h76".to_string())),
        }
    }
}

impl<'a> Arbitrary<'a> for FuzzJsonPayload {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let json_type = u.choose(&["string", "array", "object", "number", "bool", "null"])?;

        let json = match *json_type {
            "string" => {
                let s: String = Arbitrary::arbitrary(u)?;
                // Escape the string minimally to keep valid JSON
                let safe: String = s
                    .chars()
                    .take(256)
                    .flat_map(|c| {
                        if c == '"' || c == '\\' {
                            vec!['\\', c]
                        } else if c.is_control() {
                            vec![]
                        } else {
                            vec![c]
                        }
                    })
                    .collect();
                format!("\"{}\"", safe)
            }
            "array" => {
                let len: u8 = Arbitrary::arbitrary(u)?;
                let len = len.min(32) as usize;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    let v: u8 = Arbitrary::arbitrary(u)?;
                    items.push(v.to_string());
                }
                format!("[{}]", items.join(","))
            }
            "object" => {
                let len: u8 = Arbitrary::arbitrary(u)?;
                let len = len.min(8) as usize;
                let mut pairs = Vec::with_capacity(len);
                for _ in 0..len {
                    let key: String = Arbitrary::arbitrary(u)?;
                    let safe_key: String = key
                        .chars()
                        .take(16)
                        .filter(|c| c.is_alphanumeric())
                        .collect();
                    let val: u32 = Arbitrary::arbitrary(u)?;
                    if !safe_key.is_empty() {
                        pairs.push(format!("\"{}\":{}", safe_key, val));
                    }
                }
                format!("{{{}}}", pairs.join(","))
            }
            "number" => {
                let n: i32 = Arbitrary::arbitrary(u)?;
                n.to_string()
            }
            "bool" => {
                let b: bool = Arbitrary::arbitrary(u)?;
                b.to_string()
            }
            "null" => "null".to_string(),
            _ => "0".to_string(),
        };

        Ok(FuzzJsonPayload(json))
    }
}
