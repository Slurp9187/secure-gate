### Full Revised Action Plan: Add Base64, Bech32 (with Bech32m), and Keep Existing Hex Encoding Support

This consolidated plan implements **all** discussed improvements in a cohesive, generic way:

1. Extend `FixedRng` and `DynamicRng` with Base64 and Bech32/Bech32m encoding conveniences (mirroring Hex).
2. Upgrade `Bech32String` to support **both Bech32 and Bech32m variants** in a single type (no separate `Bech32mString`).
3. Keep `HexString` and `Base64String` unchanged.
4. Keep `.decode_secret_to_bytes()` on all encoding types.
5. Remain fully generic — no protocol-specific conveniences or HRP restrictions.

#### Phase 1: Dependencies and Setup
- Update `Cargo.toml`:
  ```toml
  [dependencies]
  base64 = { version = "0.22", optional = true }
  bech32 = { version = "0.11", optional = true }  # or latest ≥0.10

  [features]
  encoding-base64 = ["base64"]
  encoding-bech32 = ["bech32"]
  encoding-hex = []  # already exists
  ```
- Ensure `rand` feature exists and is optional.
- Time: 10 minutes.

#### Phase 2: Upgrade `Bech32String` to Support Both Variants (`src/encoding/bech32.rs`)
- Add imports and private enum:
  ```rust
  use bech32::{Bech32, Bech32m, Variant, ToBase32};

  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  enum EncodingVariant {
      Bech32,
      Bech32m,
  }
  ```
- Change struct definition:
  ```rust
  pub struct Bech32String {
      inner: crate::Dynamic<String>,
      variant: EncodingVariant,
  }
  ```
- Update `new()` to detect and preserve variant:
  ```rust
  pub fn new(mut s: String) -> Result<Self, &'static str> {
      match bech32::decode(&s) {
          Ok((hrp, data, variant)) => {
              let normalized = match variant {
                  Variant::Bech32 => bech32::encode::<Bech32>(hrp, &data),
                  Variant::Bech32m => bech32::encode::<Bech32m>(hrp, &data),
              }.expect("re-encoding valid input should succeed");

              let encoding_variant = match variant {
                  Variant::Bech32 => EncodingVariant::Bech32,
                  Variant::Bech32m => EncodingVariant::Bech32m,
              };

              Ok(Self {
                  inner: crate::Dynamic::new(normalized),
                  variant: encoding_variant,
              })
          }
          Err(_) => {
              zeroize_input(&mut s);
              Err("invalid bech32 string")
          }
      }
  }
  ```
- Update `new_unchecked` to require variant:
  ```rust
  pub(crate) fn new_unchecked(s: String, variant: EncodingVariant) -> Self {
      Self {
          inner: crate::Dynamic::new(s),
          variant,
      }
  }
  ```
- Add query methods:
  ```rust
  impl Bech32String {
      pub fn variant(&self) -> EncodingVariant {
          self.variant
      }

      pub fn is_bech32(&self) -> bool {
          self.variant == EncodingVariant::Bech32
      }

      pub fn is_bech32m(&self) -> bool {
          self.variant == EncodingVariant::Bech32m
      }

      // Keep existing: expose_secret(), decode_secret_to_bytes(), hrp(), len(), etc.
      // decode_secret_to_bytes() unchanged — bech32::decode ignores variant for data extraction
  }
  ```
- Update `Debug`, `PartialEq`, etc. to use `inner` as before.
- Time: 30–40 minutes.

#### Phase 3: Implement Base64 Encoding on `FixedRng` and `DynamicRng` (`src/random.rs`)
- Add block for `FixedRng`:
  ```rust
  #[cfg(all(feature = "rand", feature = "encoding-base64"))]
  impl<const N: usize> FixedRng<N> {
      pub fn into_base64(self) -> crate::encoding::base64::Base64String {
          use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
          let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
          crate::encoding::base64::Base64String::new_unchecked(encoded)
      }

      pub fn to_base64(&self) -> crate::encoding::base64::Base64String {
          use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
          let encoded = URL_SAFE_NO_PAD.encode(self.expose_secret());
          crate::encoding::base64::Base64String::new_unchecked(encoded)
      }
  }
  ```
- Add identical block for `DynamicRng` (use `self.expose_secret()` → `&[u8]`).
- Add documentation with generic examples.
- Time: 15 minutes.

#### Phase 4: Implement Bech32/Bech32m Encoding on `FixedRng` and `DynamicRng`
- Add block:
  ```rust
  #[cfg(all(feature = "rand", feature = "encoding-bech32"))]
  impl<const N: usize> FixedRng<N> {
      pub fn into_bech32(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
          use bech32::{Bech32, ToBase32};
          let encoded = bech32::encode::<Bech32>(hrp, self.expose_secret().to_base32(), Bech32)
              .expect("encoding failed");
          crate::encoding::bech32::Bech32String::new_unchecked(encoded, crate::encoding::bech32::EncodingVariant::Bech32)
      }

      pub fn to_bech32(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
          // same as above, borrowing
      }

      pub fn into_bech32m(self, hrp: &str) -> crate::encoding::bech32::Bech32String {
          use bech32::{Bech32m, ToBase32};
          let encoded = bech32::encode::<Bech32m>(hrp, self.expose_secret().to_base32(), Bech32m)
              .expect("encoding failed");
          crate::encoding::bech32::Bech32String::new_unchecked(encoded, crate::encoding::bech32::EncodingVariant::Bech32m)
      }

      pub fn to_bech32m(&self, hrp: &str) -> crate::encoding::bech32::Bech32String {
          // same as above, borrowing
      }
  }
  ```
- Mirror exactly for `DynamicRng`.
- Add clear documentation and examples showing both variants.
- Time: 20 minutes.

#### Phase 5: Documentation
- Update all new methods with examples and panic notes.
- Update module docs in `src/random.rs` and `src/encoding/bech32.rs` to describe new capabilities.
- Time: 20 minutes.

#### Phase 6: Testing
- Add round-trip tests for all encodings:
  ```rust
  #[cfg(all(feature = "rand", feature = "encoding-base64"))]
  #[test]
  fn base64_roundtrip() {
      let rng = FixedRng::<32>::generate();
      let encoded = rng.to_base64();
      assert_eq!(encoded.decode_secret_to_bytes(), rng.expose_secret().to_vec());
  }

  #[cfg(all(feature = "rand", feature = "encoding-bech32"))]
  #[test]
  fn bech32_variants_roundtrip() {
      let rng = FixedRng::<32>::generate();
      let b32 = rng.to_bech32("test");
      assert!(b32.is_bech32());
      assert_eq!(b32.decode_secret_to_bytes(), rng.expose_secret().to_vec());

      let b32m = rng.to_bech32m("test");
      assert!(b32m.is_bech32m());
      assert_eq!(b32m.decode_secret_to_bytes(), rng.expose_secret().to_vec());
  }
  ```
- Test `Bech32String::new()` accepts both valid Bech32 and Bech32m strings.
- Test zero-length, various sizes, `into_*` vs `to_*`.
- Time: 40 minutes.

#### Phase 7: Final Review & Commit
- Verify feature gating.
- Ensure no age-specific or restricted HRPs remain.
- Commit message: "feat: add base64 and full bech32/bech32m encoding support"
- Time: 15 minutes.

#### Total Estimated Time: 2.5–3 hours

This plan delivers a modern, complete, and generic encoding story while preserving the crate’s excellent security and ergonomics.