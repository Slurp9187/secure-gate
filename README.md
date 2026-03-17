  # secure-gate
  `no_std`-compatible wrappers for sensitive data with explicit, auditable exposure.
  
  > 🔒 **Security Notice**: This crate has **not undergone independent audit**.
  > Review the code and [SECURITY.md](SECURITY.md) before production use.
  > Memory safety is guaranteed — **no unsafe code** (`#![forbid(unsafe_code)]`).
  
  `secure-gate` provides `Dynamic<T>` (heap-allocated) and `Fixed<T>` (stack-allocated) wrappers that **force explicit access** to secrets via `.expose_secret()` or scoped `.with_secret()` — preventing accidental leaks while remaining zero-cost and `no_std` + `alloc` compatible.

  For zero-cost performance justification, see [ZERO_COST_WRAPPERS.md](ZERO_COST_WRAPPERS.md).
  
  ## Why secure-gate?
  
  - **Orthogonal encoding/decoding** — per-format traits (e.g., `ToHex`/`FromHexStr`) with symmetric APIs and umbrella traits for aggregation
  - **Extensible** — adding new formats (e.g., base58) requires only one new trait pair + impls
  
  - **Explicit exposure** — no silent `Deref`/`AsRef` leaks
  - **Zeroize on drop** (`zeroize` feature)
  - **Timing-safe equality** (`ct-eq` feature)
  - **Fast probabilistic equality for large secrets** (`ct-eq-hash` → BLAKE3 + fixed digest compare)
  - **Secure random generation** (`rand` feature)
  - **Encoding** (symmetric per-format traits: hex, base64url, bech32/BIP-173, bech32m/BIP-350) + **serde** direct deserialization (binary-safe)
  - **Macros** for ergonomic aliases (`dynamic_alias!`, `fixed_alias!`)
  - **Auditable** — every exposure and encoding call is grep-able

  ## Installation
  
  ```toml
  [dependencies]
  secure-gate = "0.7.0-rc.15"  # or latest stable version
  ```
  
  **Recommended secure defaults**:
  ```toml
  secure-gate = { version = "0.7.0-rc.15", features = ["secure"] }  # zeroize + alloc
  ```
  
  **Batteries-included** (most features):
  ```toml
  secure-gate = { version = "0.7.0-rc.15", features = ["full"] }
  ```
  
  **Minimal** (no zeroize/ct-eq — discouraged for production):
  ```toml
  secure-gate = { version = "0.7.0-rc.15", default-features = false }
  ```

  ## Features

  | Feature                | Description                                                                 |
  |------------------------|-----------------------------------------------------------------------------|
  | `secure` (default)     | Meta: `zeroize` + `alloc` (wiping + heap support) |
  | `zeroize`              | Zero memory on drop                                                         |
  | `ct-eq`                | `ConstantTimeEq` trait (prevents timing attacks)                            |
  | `ct-eq-hash`           | `ConstantTimeEqExt` trait: BLAKE3-based equality (fast for large/variable secrets)     |
  | `rand`                 | Secure random via `OsRng` (`from_random()`)          |
  | `serde`                | Meta: `serde-deserialize` + `serde-serialize`                               |
  | `serde-deserialize`    | Direct deserialization to inner types (binary-safe)                        |
  | `serde-serialize`      | Export secrets (requires `SerializableSecret` marker on inner type)          |
  | `encoding`             | Meta: symmetric per-format encoding/decoding (hex, base64url, bech32/bech32m) — granular sub-features available |
  | `encoding-hex`         | `ToHex` (`.to_hex()`, `.to_hex_upper()`) + `FromHexStr` (`.try_from_hex()`)  |
  | `encoding-base64`      | `ToBase64Url` (`.to_base64url()`) + `FromBase64UrlStr` (`.try_from_base64url()`) |
  | `encoding-bech32`      | Enables Bech32 (BIP-173) encoding/decoding support via the `bech32` crate. Also includes Bech32m compatibility. |
  | `encoding-bech32m`     | Enables strict Bech32m (BIP-350) support. Currently identical to `encoding-bech32` (same dependency), but reserved for future strict variant separation or stricter validation. |
  | `cloneable`            | Opt-in cloning via `CloneableSecret` marker                                   |
  | `insecure`             | Disables `zeroize` + `ct-eq` (testing/low-resource only — strongly discouraged) |
  | `alloc`                | Enables heap-dependent code (`Dynamic<T>`, `Vec<String>` support). Required for most real-world usage. Included in `default`. | Usually enabled |
  | no-alloc       | Explicitly disables heap support (`Dynamic<T>`, Vec/String zeroize, encodings). Use for true no-heap/embedded builds. Conflicts with `alloc` (both can be enabled, but `alloc` takes precedence). | Optional (embedded only) |
  | `std`                  | Enables std-specific enhancements (currently minimal; future-proof). Depends on `alloc`. | Optional |
  | `full`                 | All of the above (convenient for development)                               |

  `no_std` + `alloc` compatible. Disabled features have **zero overhead**.

  ### Quick Feature Guide

  | Goal | Features | Result |
  |------------------|-----------------------------|------------------------------------------------------|
  | Default secure (heap + stack) | `secure` (default) | `Fixed<T>` + `Dynamic<T>`, zeroize, alloc |
  | Secure with no-heap | `secure + no-alloc` | `Fixed<T>` only, zeroize |
  | Minimal (discouraged) | `no-alloc` | `Fixed<T>` only, no zeroize |
  | Full featured | `full` | All features enabled |

  ### Heap vs No-Heap Builds

  secure-gate **defaults to heap-enabled** (via `secure` pulling `alloc`):

  ```toml
  secure-gate = "0.7"  # Fixed<T> + Dynamic<T> + zeroize/alloc
  ```

  For **no-heap / embedded** (only `Fixed<T>`):

  ```toml
  secure-gate = { version = "0.7", default-features = false, features = ["no-alloc"] }  # Minimal, no-heap
  # or with secure (zeroize on Fixed<T>):
  secure-gate = { version = "0.7", features = ["secure", "no-alloc"] }
  ```

  Note: The "pass-through wrapper" principle holds for `Fixed<T>` in all builds (zero-cost explicit exposure + optional zeroize). `Dynamic<T>` requires heap and is unavailable in no-alloc mode.

  **Warning**: Enabling both `alloc` and `no-alloc` features allows `alloc` to take precedence (e.g., with `--all-features` for docs generation or CI). Prefer enabling only one feature for predictable builds.



  ## Quick Start

  ```rust
  #[cfg(feature = "alloc")]
  {
      use secure_gate::{dynamic_alias, fixed_alias, ExposeSecret, ExposeSecretMut};

      dynamic_alias!(pub Password, String);      // Dynamic<String>
      fixed_alias!(pub Aes256Key, 32);           // Fixed<[u8; 32]>

      let mut pw: Password = "hunter2".into();
      let key: Aes256Key = Aes256Key::new([42u8; 32]);  // or [42u8; 32].into() / try_from

      // Scoped (recommended)
      pw.with_secret(|s| println!("length: {}", s.len()));

      // Direct (auditable)
      assert_eq!(pw.expose_secret(), "hunter2");

      // Mutable
      pw.with_secret_mut(|s: &mut String| s.push('!'));
      pw.expose_secret_mut().clear();

      // Symmetric encoding/decoding example (new per-format traits)
      #[cfg(all(feature = "encoding-hex", feature = "encoding-bech32"))]
      {
          use secure_gate::{FromHexStr, ToBech32, ToHex};
          let hex    = key.expose_secret().to_hex();          // "2a2a2a..."
          let bech32 = key.expose_secret().try_to_bech32("key", None).unwrap();  // "key1q..." (BIP-173)
          let roundtrip = hex.try_from_hex().unwrap();        // Decode back
      }
  }
  ```
  
  > **Note**: Encoding API updated in 0.7.0 — old `SecureEncoding` removed in favor of per-format traits (e.g., `ToHex`, `FromHexStr`). Existing code like `data.to_hex()` still works via blanket impls. For new symmetric encoding/decoding, use individual traits or umbrellas (`SecureEncoding`/`SecureDecoding`). Prefer fallible `try_` variants for encoding to avoid panics.
  
  ## Security Model
  
  - **Explicit access only** — `.with_secret()` / `.expose_secret()` required
  - **No implicit leaks** — no `Deref`/`AsRef`/`Copy` by default
  - **Zeroize** on drop (`zeroize` feature)
  - **Timing-safe** equality (optional `ct-eq` feature)
  - **Probabilistic fast equality** for big data (`hash-eq`)
  - **No unsafe code** — enforced with `#![forbid(unsafe_code)]`
  
  Read [SECURITY.md](SECURITY.md) for threat model and mitigations.
  
  ## Recommended Equality
  
  Use **`ct_eq_auto`** — it automatically chooses the best method:
  
  - Small inputs (≤32 bytes default): fast deterministic `ct_eq`
  - Large/variable inputs: fast BLAKE3 hashing + digest compare

  **Performance Tuning**: If benchmarks show a different optimal crossover point on your hardware (e.g., `ct_eq` remains faster up to 64 or 1024 bytes), customize with `ct_eq_auto(&sig_b, Some(n))`.

  ```rust
  #[cfg(feature = "ct-eq-hash")]
  {
      use secure_gate::{Dynamic, ConstantTimeEqExt};

      let sig_a: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();  // e.g. ML-DSA signature
      let sig_b: Dynamic<Vec<u8>> = vec![0xAA; 2048].into();

      // Recommended: smart path selection
      if sig_a.ct_eq_auto(&sig_b, None) {
          // equal
      }
  }
  ```

  Plain `ct_eq_hash` is still available for uniform probabilistic behavior.

  For detailed justification, benchmarks, and tuning guidance, see [CT_EQ_AUTO.md](CT_EQ_AUTO.md).

  ## Advanced Usage

  ### Using `Fixed<T>` and `Dynamic<T>` Directly

  For macro-averse users, construct and expose types directly:

  ```rust
  use secure_gate::{Fixed, ExposeSecret};
  let key: Fixed<[u8; 32]> = Fixed::new([42u8; 32]);
  key.with_secret(|bytes| assert_eq!(bytes.len(), 32));
  ```

  See [`Fixed`] and [`Dynamic`] in the [API docs](https://docs.rs/secure-gate) for full examples.

  ### Polymorphic / Generic Code

  Write functions that accept any secure wrapper via the `ExposeSecret` trait:

  ```rust
  use secure_gate::ExposeSecret;
  fn log_length<S: ExposeSecret>(secret: &S) { println!("length = {}", secret.len()); }
  ```

  ### Macros for Aliases

  `fixed_alias!`, `dynamic_alias!`, `fixed_generic_alias!`, and `dynamic_generic_alias!` create typed newtype wrappers with full visibility control and optional doc strings:

  ```rust
  use secure_gate::fixed_alias;
  fixed_alias!(pub Aes256Key, 32, "32-byte AES-256 key");

  #[cfg(feature = "alloc")]
  {
  use secure_gate::dynamic_alias;
  dynamic_alias!(pub Password, String, "variable-length password");
  }
  ```

  See [`fixed_alias!`], [`dynamic_alias!`], [`fixed_generic_alias!`], and [`dynamic_generic_alias!`] in the [API docs](https://docs.rs/secure-gate) for all visibility forms and compile-time zero-size guards.

  ### Random Generation

  Cryptographically secure randomness via `OsRng` (requires `rand` feature):

  ```rust
  #[cfg(feature = "rand")]
  {
  use secure_gate::Fixed;
  let key: Fixed<[u8; 32]> = Fixed::from_random();
  }
  ```

  See [`Fixed::from_random`] and [`Dynamic::from_random`] in the [API docs](https://docs.rs/secure-gate).

  ### Encoding (symmetric per-format traits)

  secure-gate provides **orthogonal, symmetric encoding/decoding traits**. All methods are blanket-implemented over `AsRef<[u8]>` / `AsRef<str>` — call them directly on wrapper types without `.expose_secret()`:

  - `ToHex` / `FromHexStr` — hex (requires `encoding-hex`)
  - `ToBase64Url` / `FromBase64UrlStr` — base64url (requires `encoding-base64`)
  - `ToBech32` / `FromBech32Str` — BIP-173 Bech32 (requires `encoding-bech32`)
  - `ToBech32m` / `FromBech32mStr` — BIP-350 Bech32m (requires `encoding-bech32m`)

  ```rust
  #[cfg(feature = "encoding-hex")]
  {
  use secure_gate::{Fixed, ToHex};

  let key = Fixed::new([0u8; 32]);
  let hex = key.to_hex();  // direct on wrapper — no .expose_secret() needed
  }
  ```

  See [`ToHex`], [`ToBech32`], [`FromHexStr`], and sibling traits in the [API docs](https://docs.rs/secure-gate) for round-trip examples.

  ### Serde

  `serde-deserialize` decodes directly to the inner type from a binary sequence — no temporary string buffers or format confusion attacks. Serialization requires implementing the `SerializableSecret` marker trait on your inner type.

  See [`SerializableSecret`] in the [API docs](https://docs.rs/secure-gate) for the full example.
  
  ## License
  
  MIT OR Apache-2.0
