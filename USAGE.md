# Secure-Gate — Comprehensive Usage Reference

**Version**: 0.2.3 · `no_std` + `alloc` · Zero-overhead fallbacks

## Crate Features

| Feature           | What it gives you                                  | Example / Why you want it |
|-------------------|-----------------------------------------------------|---------------------------|
| `zeroize` (default) | `SecretBox<T>` + automatic memory wipe on drop/mutate | **Always enable** unless you need absolute minimal binary size |
| `serde`           | `Serialize` / `Deserialize` impls (exposes on serialize) | Persisting secrets (must encrypt output) |
| `unsafe-wipe`     | Fast full-capacity zeroing of `Secure<String>` (no temp alloc) | High-frequency or very large strings (e.g. JWTs, logs) |
| `full`            | All of the above in one flag                        | Quick prototyping |

```rust
// Fast full-capacity wipe (unsafe-wipe)
#[cfg(feature = "unsafe-wipe")]
let mut huge = Secure::new("x".repeat(5_000_000));
huge.expose_mut().push_str("more");
huge.zeroize(); // Entire capacity (not just .len()) wiped instantly
```

## Type Aliases — All 11, with Real-World Examples

| Alias                | Inner type                     | Typical use                                     | Code example |
|----------------------|--------------------------------|--------------------------------------------------|--------------|
| `SecureBytes`        | `[u8]` (from `Vec<u8>`)        | Arbitrary binary secrets                        | ```let
| `SecureIv`           | `[u8; 16]`                     | AES-GCM IV                                      | ```let iv: SecureIv = iv_bytes.into();``` |
| `SecureKey32`        | `[u8; 32]`                     | AES-256, HMAC-SHA256, ed25519 keys              | ```let key: SecureKey32 = rand::random();``` |
| `SecureKey64`        | `[u8; 64]`                     | ed25519 private keys, BLAKE3 keys               | ```let sk: SecureKey64 = rand::thread_rng().gen();``` |
| `SecureNonce12`      | `[u8; 12]`                     | XChaCha20-Poly1305, AES-GCM-SIV                 | ```let nonce: SecureNonce12 = secure!([u8; 12], rand::random());``` |
| `SecureNonce16`      | `[u8; 16]`                     | AES-GCM                                         | ```let nonce: SecureNonce16 = secure!([u8; 16], rand::random());``` |
| `SecureNonce24`      | `[u8; 24]`                     | ChaCha20-Poly1305 (extended)                    | ```let nonce: SecureNonce24 = secure!([u8; 24], rand::random());``` |
| `SecurePassword`     | `SecretBox<str>` / `String`    | Immutable passwords (recommended)               | ```let pw: SecurePassword = "hunter2".into();``` |
| `SecurePasswordMut`  | `SecretBox<String>`            | Building passwords incrementally                | ```let mut pw = SecurePasswordMut::new("user:"); pw.expose_mut().expose_secret_mut().push_str(&input);``` |
| `SecureSalt`         | `[u8; 16]`                     | Argon2, scrypt salts                            | ```let salt: SecureSalt = rand::random();``` |
| `SecureStr`          | `str` (from `String`/`&str`)   | Immutable secret strings                        | ```let s: SecureStr = "license-key".parse().unwrap();``` |

## Core Type: `Secure<T>` — Every Possible Operation

| Operation                     | Code                                                                 | When to use |
|------------------------------|----------------------------------------------------------------------|-------------|
| Clone                        | `let s2 = s.clone();`                                                | Temporary copies |
| Default (empty)              | `let empty: Secure<String> = Secure::default();`                     | Empty buffer |
| Extract (dangerous)          | `let boxed: Box<Vec<u8>> = s.into_inner();`                          | FFI or handover |
| Explicit zeroize             | `s.zeroize();`                                                       | Immediate wipe |
| Init with closure            | `let s = Secure::init_with(|| generate_key());`                      | Wipe local temps |
| Mutable view                 | `s.expose_mut()` or `s.expose_secret_mut()`                          | Change secret |
| On-drop zeroize (auto)       | Just let `s` go out of scope                                         | Normal usage |
| Shrink after mutate          | `s.finish_mut();`                                                    | Reduce slack (dynamic types) |
| Try-init                     | `Secure::try_init_with(|| read_key())`                               | Fallible creation |
| View                         | `s.expose()` or `s.expose_secret()`                                  | Read secret |
| Wrap (array macro)           | `let k = secure!([u8; 32], rand::random());`                         | Fixed keys/nonces |
| Wrap (macro)                 | `let s = secure!(Vec<u8>, vec![1,2,3]);`                             | Shorter |
| Wrap (new)                   | `let s = Secure::new(vec![1,2,3]);`                                  | Basic |

### Clone Isolation Example
```rust
let orig = Secure::new(vec![1,2,3]);
let mut copy = orig.clone();
copy.expose_mut().push(99);
assert_eq!(orig.expose(), &[1,2,3]);   // unchanged
assert_eq!(copy.expose(), &[1,2,3,99]);
```

## Serde Integration — Full Round-Trip Examples

```rust
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct ApiConfig {
    api_key: SecureKey32,
    password: SecurePassword,
    token: SecureBytes,
}

// Save (exposes — encrypt the JSON!)
let cfg = ApiConfig {
    api_key: rand::random(),
    password: "s3cr3t".into(),
    token: token_vec.into(),
};
let json = serde_json::to_string(&cfg.password.expose()).unwrap(); // ← encrypt this!

// Load (auto-wraps)
let loaded: SecurePassword = serde_json::from_str(&json).unwrap();
```

Bincode example (same pattern):
```rust
#[cfg(feature = "serde")]
let bytes = bincode::serialize(&cfg.api_key.expose()).unwrap(); // encrypt!
let key: SecureKey32 = bincode::deserialize(&bytes).unwrap();
```

## Every Real-World Pattern You’ll Ever Need

| Scenario                              | Code snippet                                                                                           |
|---------------------------------------|--------------------------------------------------------------------------------------------------------|
| Build JWT claims with secret          | `let mut claims = Secure::new(String::new()); claims.expose_mut().push_str(&json);`                    |
| Drop all secrets at program exit      | Just let everything go out of scope — zeroized automatically (with `zeroize`)                         |
| Encrypt data (aes-gcm)                | `let cipher = Aes256Gcm::new(key.expose().into()); cipher.encrypt(nonce.expose().into(), payload)?;`   |
| Generate random AES-256 key           | `let key: SecureKey32 = rand::thread_rng().gen();`                                                     |
| Hash password (argon2)                | `let hash = argon2::hash_raw(pw.expose().as_bytes(), salt.expose(), &cfg)?;`                           |
| Parse hex string → key                | `let key: SecureKey32 = Secure::new(hex::decode(hex_str)?.try_into()?);`                               |
| Read password from stdin securely     | `let pw: SecurePasswordMut = rpassword::prompt_password("PW: ")?.into();`                              |
| Secure in-memory cache                | `let cache: HashMap<UserId, Secure<String>> = HashMap::new();`                                         |

## Troubleshooting Cheat Sheet

| Symptom                          | Fix |
|----------------------------------|-----|
| Debug prints secret              | Impossible — always redacted |
| Need absolute minimal binary     | `default-features = false` → plain `Box<T>` |
| No wiping happening              | Enable `zeroize` feature |
| Old data survives after truncate | Dynamic containers only wipe `.len()` — call `finish_mut()` or use fixed size |
| Serde outputs plaintext          | Normal — you must encrypt the serialized bytes |
| Slow `Secure<String>` zeroing    | Enable `unsafe-wipe` |
| `expose_secret` not found        | Enable `zeroize` or use `expose()` |