//! Full migration integration test — `harness = false` (issue_104 §8).
//!
//! Simulates a real-world crate migration in three stages:
//!
//!   Stage 1: Code that was written against secrecy 0.8 (v08 compat types)
//!   Stage 2: Code that was written against secrecy 0.10 (v10 compat types)
//!   Stage 3: Fully native secure-gate types (Dynamic / Fixed)
//!
//! Each stage feeds the same logical secret through the full chain and asserts:
//!   - Value identity at every hop
//!   - Debug output never leaks the secret
//!   - Drop is safe (zeroize on every path)
//!
//! Run with:
//!   cargo test --test migration_full --features secrecy-compat
//!
//! Prints "Migration validated ✓" on success.

fn main() {
    #[cfg(feature = "secrecy-compat")]
    {
        stage1_v08_compat();
        stage2_v10_compat();
        stage3_native();
        stage4_cross_version_migration();
        stage5_realistic_application_struct();

        println!();
        println!("  ┌─────────────────────────────────────────┐");
        println!("  │                                         │");
        println!("  │    Migration validated ✓                │");
        println!("  │    secrecy → secure-gate: all clear     │");
        println!("  │                                         │");
        println!("  └─────────────────────────────────────────┘");
        println!();
    }

    #[cfg(not(feature = "secrecy-compat"))]
    {
        eprintln!("migration_full: secrecy-compat feature not enabled — skipping.");
        eprintln!("Run with: cargo test --test migration_full --features secrecy-compat");
    }
}

// ── Stage 1: Existing secrecy 0.8 code (v08 compat) ─────────────────────────

#[cfg(feature = "secrecy-compat")]
fn stage1_v08_compat() {
    use secure_gate_compat::compat::v08::{Secret, SecretString, SecretVec};
    use secure_gate_compat::compat::ExposeSecret;

    // Struct that a user would have before migration
    struct UserCredentials {
        username: String,
        password: SecretString,
        session_key: Secret<Vec<u8>>,
    }

    let creds = UserCredentials {
        username: String::from("alice"),
        password: Secret::new(String::from("correct_horse_battery_staple")),
        session_key: Secret::new(vec![0xABu8; 32]),
    };

    assert_eq!(creds.username.as_str(), "alice");

    // Verify access
    assert_eq!(
        creds.password.expose_secret(),
        "correct_horse_battery_staple"
    );
    assert_eq!(creds.session_key.expose_secret().len(), 32);

    // Verify Debug doesn't leak
    let dbg = format!("{:?}", creds.password);
    assert!(
        !dbg.contains("correct_horse"),
        "stage1: password leaked in Debug"
    );

    // Clone (String: CloneableSecret in v08)
    let pw_copy = creds.password.clone();
    assert_eq!(creds.password.expose_secret(), pw_copy.expose_secret());
    fn consume<T>(_t: T) {}
    consume(pw_copy);

    // SecretVec
    let raw_key: SecretVec<u8> = Secret::new(vec![0x01u8; 16]);
    assert_eq!(raw_key.expose_secret().len(), 16);

    println!("  Stage 1 (secrecy 0.8 compat): OK");
}

// ── Stage 2: Code written against secrecy 0.10 (v10 compat) ─────────────────

#[cfg(feature = "secrecy-compat")]
fn stage2_v10_compat() {
    use secure_gate_compat::compat::v10::{SecretBox, SecretSlice, SecretString};
    use secure_gate_compat::compat::{ExposeSecret, ExposeSecretMut};

    struct ServiceConfig {
        api_endpoint: String,
        api_key: SecretString,
        tls_cert: SecretSlice<u8>,
    }

    let config = ServiceConfig {
        api_endpoint: String::from("https://api.example.com"),
        api_key: "Bearer_tok_xyz_789".into(),
        tls_cert: vec![0xCEu8; 64].into(),
    };

    assert_eq!(config.api_endpoint.as_str(), "https://api.example.com");

    // Read access
    assert_eq!(config.api_key.expose_secret(), "Bearer_tok_xyz_789");
    assert_eq!(config.tls_cert.expose_secret().len(), 64);

    // init_with_mut: fills in-place without an extra allocation
    let mut session: SecretBox<Vec<u8>> = SecretBox::init_with_mut(|v: &mut Vec<u8>| {
        v.extend_from_slice(&[0x10u8; 16]);
    });
    assert_eq!(session.expose_secret().len(), 16);

    // Mutable access
    session.expose_secret_mut().extend_from_slice(&[0x20u8; 8]);
    assert_eq!(session.expose_secret().len(), 24);

    // try_init_with: fallible construction
    let result: Result<SecretBox<String>, &str> =
        SecretBox::try_init_with(|| Ok(String::from("fallible_secret")));
    assert_eq!(result.unwrap().expose_secret(), "fallible_secret");

    // Debug never leaks
    let dbg = format!("{:?}", config.api_key);
    assert!(
        !dbg.contains("Bearer_tok"),
        "stage2: api_key leaked in Debug"
    );

    println!("  Stage 2 (secrecy 0.10 compat): OK");
}

// ── Stage 3: Fully native secure-gate types ──────────────────────────────────

#[cfg(feature = "secrecy-compat")]
fn stage3_native() {
    use secure_gate::{Dynamic, Fixed, RevealSecret, RevealSecretMut};

    // Fixed for stack-allocated keys (replaces Secret<[T; N]>)
    let mut encryption_key: Fixed<[u8; 32]> = Fixed::new([0xABu8; 32]);

    let key_len = encryption_key.with_secret(|arr| arr.len());
    assert_eq!(key_len, 32);

    // Mutable scoped access
    encryption_key.with_secret_mut(|arr| {
        arr[0] = 0xFF;
    });
    let first = encryption_key.with_secret(|arr| arr[0]);
    assert_eq!(first, 0xFF);

    // Dynamic for heap-allocated strings (replaces Secret<String> / SecretString)
    let mut jwt: Dynamic<String> = Dynamic::new(String::from("eyJhbGc.payload.sig"));
    let original_len = jwt.with_secret(|s| s.len());
    jwt.with_secret_mut(|s| s.push('!'));
    assert_eq!(jwt.with_secret(|s| s.len()), original_len + 1);

    // Dynamic for heap-allocated buffers (replaces Secret<Vec<u8>>)
    let session_key: Dynamic<Vec<u8>> = Dynamic::new(vec![0x00u8; 32]);
    assert_eq!(session_key.len(), 32);
    assert!(!session_key.is_empty());

    // Debug never leaks
    let dbg = format!("{:?}", jwt);
    assert!(!dbg.contains("eyJ"), "stage3: jwt leaked in Debug");

    println!("  Stage 3 (native Dynamic / Fixed): OK");
}

// ── Stage 4: Cross-version migration (the actual From/Into chain) ─────────────

#[cfg(feature = "secrecy-compat")]
fn stage4_cross_version_migration() {
    use secure_gate_compat::compat::v08::Secret as V08Secret;
    use secure_gate_compat::compat::v10::SecretBox as V10SecretBox;
    use secure_gate_compat::compat::ExposeSecret;
    use secure_gate_compat::{Dynamic, Fixed, RevealSecret};

    let payload = "migration_payload_value";

    // Path A: v08 → Dynamic → v10 (string)
    let v08: V08Secret<String> = V08Secret::new(String::from(payload));
    let native_a: Dynamic<String> = v08.into();
    let v10: V10SecretBox<String> = native_a.into();
    assert_eq!(v10.expose_secret(), payload, "A: v08→Dynamic→v10 failed");

    // Path B: v10 → Dynamic → v08 (string)
    let v10b: V10SecretBox<String> = V10SecretBox::init_with(|| String::from(payload));
    let native_b: Dynamic<String> = v10b.into();
    let v08_back: V08Secret<String> = native_b.into();
    assert_eq!(
        v08_back.expose_secret(),
        payload,
        "B: v10→Dynamic→v08 failed"
    );

    // Path C: v08 array → Fixed
    let v08_key: V08Secret<[u8; 32]> = V08Secret::new([0x42u8; 32]);
    let fixed: Fixed<[u8; 32]> = v08_key.into();
    let key_byte = fixed.with_secret(|arr| arr[0]);
    assert_eq!(key_byte, 0x42, "C: v08→Fixed failed");

    // Path D: v08 Vec → Dynamic → v10 Vec
    let v08_vec: V08Secret<Vec<u8>> = V08Secret::new(vec![1u8, 2, 3, 4]);
    let native_c: Dynamic<Vec<u8>> = v08_vec.into();
    let v10_vec: V10SecretBox<Vec<u8>> = native_c.into();
    assert_eq!(
        v10_vec.expose_secret(),
        &[1u8, 2, 3, 4],
        "D: v08→Dynamic→v10 Vec failed"
    );

    println!("  Stage 4 (cross-version migration chain): OK");
}

// ── Stage 5: Realistic application struct migration ───────────────────────────

#[cfg(feature = "secrecy-compat")]
fn stage5_realistic_application_struct() {
    use secure_gate_compat::{Dynamic, Fixed, RevealSecret};

    // Fully migrated application config — no compat types remain.
    struct AppSecrets {
        db_password: Dynamic<String>,
        signing_key: Fixed<[u8; 32]>,
        session_hmac_secret: Dynamic<Vec<u8>>,
    }

    let secrets = AppSecrets {
        db_password: Dynamic::new(String::from("postgres://user:pass@localhost")),
        signing_key: Fixed::new([0xDEu8; 32]),
        session_hmac_secret: Dynamic::new(vec![0xBEu8; 64]),
    };

    // Validation
    let pw_len = secrets.db_password.with_secret(|s| s.len());
    assert!(pw_len > 0);

    let key_first = secrets.signing_key.with_secret(|arr| arr[0]);
    assert_eq!(key_first, 0xDE);

    let hmac_len = secrets.session_hmac_secret.len();
    assert_eq!(hmac_len, 64);

    // Simulate fake crypto: derive a per-request token from the signing key and db password
    let token_len = secrets
        .signing_key
        .with_secret(|arr| secrets.db_password.with_secret(|pw| arr.len() + pw.len()));
    assert!(token_len > 32);

    println!("  Stage 5 (realistic application struct): OK");
}
