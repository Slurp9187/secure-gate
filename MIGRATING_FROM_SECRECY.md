# Migrating from secrecy

This guide covers dropping `secrecy` and using `secure-gate` instead. The
`secrecy-compat` feature provides type- and import-compatible shims for both
major secrecy generations so that migration can be done incrementally.

> **Experimental status**: The `secrecy-compat` migration layer is still
> experimental and has not been validated in production environments yet.
> Test thoroughly in staging before production rollout.
>
> **Goal**: get your code compiling against `secure-gate` immediately (Step 1),
> then replace compat types with native wrappers at your own pace (Steps 2–5).

> **Test suite**: Every pattern in this guide is proven by runnable tests in
> [`tests/compat_suite/`](tests/compat_suite/) (integrated into `cargo test`),
> [`tests/migration_full.rs`](tests/migration_full.rs) (standalone harness),
> and [`tests/compat_suite/examples.rs`](tests/compat_suite/examples.rs)
> (canonical copy-paste examples). Run:
> ```
> cargo test --features secrecy-compat
> cargo test --test migration_full --features secrecy-compat
> ```

---

## Which secrecy version are you on?

| secrecy version | Compat module | Key types                                        |
| --------------- | ------------- | ------------------------------------------------ |
| 0.10.x          | `compat::v10` | `SecretBox<S>`, `SecretString`, `SecretSlice<T>` |
| 0.8.x           | `compat::v08` | `Secret<S>`, `SecretString`, `SecretVec<T>`      |

Shared traits (`ExposeSecret`, `ExposeSecretMut`, `CloneableSecret`,
`SerializableSecret`) and a `zeroize` re-export live in `compat::` (not in the
version sub-module) and work with both generations.

---

## Step 1 — Swap the dependency

```toml
[dependencies]
# Remove:
# secrecy = "0.10"   (or "0.8")

# Add:
secure-gate = { version = "0.9", features = ["secrecy-compat"] }
```

Then do a global find/replace on imports (details below). Your code should
compile without any other changes.

---

## Migrating from secrecy 0.10.x

### Import swap

```rust
// Before
use secrecy::{SecretBox, SecretString, SecretSlice, ExposeSecret, ExposeSecretMut};

// After (one global find/replace)
use secure_gate::compat::v10::{SecretBox, SecretString, SecretSlice};
use secure_gate::compat::{ExposeSecret, ExposeSecretMut};
```

### Type mapping

| secrecy 0.10         | `compat::v10` shim                    | Native secure-gate equivalent                    |
| -------------------- | ------------------------------------- | ------------------------------------------------ |
| `SecretBox<T>`       | `SecretBox<T>`                        | `Dynamic<T>`                                     |
| `SecretString`       | `SecretString` (= `SecretBox<str>`)   | `Dynamic<String>`                                |
| `SecretSlice<T>`     | `SecretSlice<T>` (= `SecretBox<[T]>`) | `Dynamic<Vec<T>>`                                |
| `ExposeSecret<T>`    | `compat::ExposeSecret`                | `RevealSecret` (+ `with_secret`)                 |
| `ExposeSecretMut<T>` | `compat::ExposeSecretMut`             | `RevealSecretMut` (+ `with_secret_mut`)          |
| `CloneableSecret`    | `compat::CloneableSecret`             | `CloneableSecret` (`cloneable` feature)          |
| `SerializableSecret` | `compat::SerializableSecret`          | `SerializableSecret` (`serde-serialize` feature) |
| `zeroize` re-export  | `compat::zeroize`                     | `zeroize` (direct dependency)                    |

### Step-by-step native migration

1. Enable `secrecy-compat` and do the import swap above — done, compiles.
2. Replace `v10::SecretBox<T>` with `Dynamic<T>` using the provided `From` impl:

   ```rust
   use secure_gate::compat::v10::SecretBox;
   use secure_gate::Dynamic;

   // Prefer init_with_mut — avoids the clone-then-zeroize window of init_with
   let compat: SecretBox<String> = SecretBox::init_with_mut(|s| s.push_str("hunter2"));
   let native: Dynamic<String> = compat.into();   // From<SecretBox<S>> for Dynamic<S>
   ```

   > **Note**: The conversion clones the inner value (`SecretBox` has a `Drop`
   > impl so moving out without `unsafe` is not possible). The clone is
   > immediately wrapped in `Dynamic` and the original is zeroized on drop.
   > For zero-copy native construction, build `Dynamic<T>` directly using
   > `new_with` (see step 4).

3. Replace `compat::ExposeSecret` trait bounds with `RevealSecret`. Bridge impls
   on `Dynamic<T>` and `Fixed<[T; N]>` implement both traits, so call sites using
   `.expose_secret()` keep compiling during the transition:

   ```rust
   // During transition — still works
   fn show<S: secure_gate::compat::ExposeSecret<str>>(s: &S) { … }

   // Final form
   fn show<S: secure_gate::RevealSecret>(s: &S) { … }
   ```

4. Prefer scoped construction and access for new code:
   - **Access**: use `with_secret` / `with_secret_mut` closures over `expose_secret`
     — limits borrow lifetime and is the recommended audit pattern.
   - **Construction**: use `new_with` closures when building secrets from computed
     data inline — writes directly into the wrapper's storage, no intermediate copy:

   ```rust
   // Dynamic<Vec<u8>>
   let key = Dynamic::<Vec<u8>>::new_with(|v| v.extend_from_slice(&raw_bytes));

   // Dynamic<String>
   let token = Dynamic::<String>::new_with(|s| s.push_str(&decoded));

   // Fixed<[u8; N]>
   let key = Fixed::<[u8; 32]>::new_with(|arr| arr.copy_from_slice(&raw_bytes));
   ```

   `Dynamic::new(value)` and `Fixed::new(value)` remain available as the ergonomic default.

5. Remove `secrecy-compat` from `Cargo.toml` once all call sites are updated.

### Available `From` conversions (v10 ↔ native)

| From              | To                  | Notes                                       |
| ----------------- | ------------------- | ------------------------------------------- |
| `SecretBox<S>`    | `Dynamic<S>`        | Clones inner; requires `S: Clone + Zeroize` |
| `Dynamic<String>` | `SecretBox<String>` | Clones inner string                         |
| `Dynamic<String>` | `SecretString`      | Clones inner string                         |
| `Dynamic<Vec<S>>` | `SecretBox<Vec<S>>` | Clones inner vec                            |
| `SecretString`    | `Dynamic<String>`   | Clones inner `str`                          |

---

## Migrating from secrecy 0.8.x

### Import swap

```rust
// Before
use secrecy::{Secret, SecretString, SecretVec, DebugSecret, CloneableSecret, ExposeSecret};

// After (one global find/replace)
use secure_gate::compat::v08::{Secret, SecretString, SecretVec, DebugSecret};
use secure_gate::compat::{CloneableSecret, ExposeSecret};
```

### Type mapping

| secrecy 0.8          | `compat::v08` shim                  | Native secure-gate equivalent                          |
| -------------------- | ----------------------------------- | ------------------------------------------------------ |
| `Secret<S>`          | `Secret<S>` (stack/inline)          | `Fixed<[u8; N]>` (arrays) / `Dynamic<T>` (heap)        |
| `SecretString`       | `SecretString` (= `Secret<String>`) | `Dynamic<String>`                                      |
| `SecretVec<T>`       | `SecretVec<T>` (= `Secret<Vec<T>>`) | `Dynamic<Vec<T>>`                                      |
| `SecretBox<S>`       | `SecretBox<S>` (= `Secret<Box<S>>`) | `Dynamic<T>` (prefer `v10::SecretBox` for sized types) |
| `DebugSecret`        | `compat::v08::DebugSecret`          | No equivalent — native types always print `[REDACTED]` |
| `ExposeSecret<S>`    | `compat::ExposeSecret`              | `RevealSecret` (+ `with_secret`)                       |
| `CloneableSecret`    | `compat::CloneableSecret`           | `CloneableSecret` (`cloneable` feature)                |
| `SerializableSecret` | `compat::SerializableSecret`        | `SerializableSecret` (`serde-serialize` feature)       |
| `zeroize` re-export  | `compat::zeroize`                   | `zeroize` (direct dependency)                          |

### Key differences from secrecy 0.10

- `v08::Secret<S>` is **stack-allocated** (stores `S` inline, no `Box`). For heap-allocated secrets, use `v10::SecretBox<S>` or native `Dynamic<T>`.
- No `ExposeSecretMut` — mutable access was added in secrecy 0.9.
- `DebugSecret` trait is required for `Debug` impls on `Secret<S>`. Native wrappers always redact without a marker trait.
- `v08::SecretBox<S>` is `Secret<Box<S>>`, which is different from `v10::SecretBox<S>` (a newtype around `Box<S>` with `?Sized` support). For new code, prefer `v10::SecretBox` or `Dynamic<T>`.

### Step-by-step native migration

1. Enable `secrecy-compat` and do the import swap above — done, compiles.
2. Replace heap-allocated `Secret<String>` / `Secret<Vec<T>>` with `Dynamic<T>`:

   ```rust
   use secure_gate::compat::v08::Secret;
   use secure_gate::Dynamic;

   let old: Secret<String> = Secret::new(String::from("hunter2"));
   let native: Dynamic<String> = old.into();   // From<Secret<String>> for Dynamic<String>
   ```

3. Replace fixed-size array secrets with `Fixed<[T; N]>`:

   ```rust
   use secure_gate::compat::v08::Secret;
   use secure_gate::Fixed;

   let old: Secret<[u8; 32]> = Secret::new([0xABu8; 32]);
   let native: Fixed<[u8; 32]> = old.into();   // From<Secret<[T; N]>> for Fixed<[T; N]>
   ```

4. Prefer scoped construction and access for new code:
   - **Access**: replace `expose_secret()` call sites with `with_secret(|s| …)` closures
     and `compat::ExposeSecret` bounds with `RevealSecret`.
   - **Construction**: use `new_with` closures when building secrets inline — writes
     directly into the wrapper's storage:

   ```rust
   // Fixed<[u8; 32]> — avoids intermediate stack copy
   let key = Fixed::<[u8; 32]>::new_with(|arr| arr.copy_from_slice(&raw_bytes));

   // Dynamic<Vec<u8>>
   let key = Dynamic::<Vec<u8>>::new_with(|v| v.extend_from_slice(&raw_bytes));
   ```

5. Remove `secrecy-compat` from `Cargo.toml` once all call sites are updated.

### Available `From` conversions (v08 ↔ native)

| From              | To                | Notes               |
| ----------------- | ----------------- | ------------------- |
| `Secret<String>`  | `Dynamic<String>` | Clones inner string |
| `Dynamic<String>` | `Secret<String>`  | Clones inner string |
| `Secret<Vec<T>>`  | `Dynamic<Vec<T>>` | Clones inner vec    |
| `Dynamic<Vec<T>>` | `Secret<Vec<T>>`  | Clones inner vec    |
| `Secret<[T; N]>`  | `Fixed<[T; N]>`   | Clones inner array  |
| `Fixed<[T; N]>`   | `Secret<[T; N]>`  | Clones inner array  |

---

## Bridge impls — incremental migration

Native `Dynamic<T>` and `Fixed<[T; N]>` implement `compat::ExposeSecret` and
`compat::ExposeSecretMut` via bridge impls. This means you can replace compat
types one at a time without changing any trait bounds:

```rust
use secure_gate::compat::ExposeSecret;
use secure_gate::Dynamic;

fn process<S: ExposeSecret<str>>(secret: &S) {
    let val = secret.expose_secret();
    // …
}

// Works with a compat type:
let compat: secure_gate::compat::v10::SecretBox<str> = "hi".parse().unwrap();
process(&compat);

// Also works with the native type — no code change at the call site:
let native: Dynamic<String> = Dynamic::new(String::from("hi"));
process(&native);
```

---

## Security notes during migration

- Two access trait families coexist during transition: compat `ExposeSecret` and
  native `RevealSecret`. Audit sweeps must cover **both** — search for
  `expose_secret` **and** `with_secret` / `expose_secret` (native).
- **Compat construction**: prefer `SecretBox::init_with_mut` over `SecretBox::init_with`
  to avoid the clone-then-zeroize window inherent in `init_with`.
- **Native construction**: prefer `Fixed::new_with(|arr| …)` and
  `Dynamic::<Vec<u8>>::new_with(|v| …)` over `new(value)` when constructing secrets
  from computed data inline — these write directly into the wrapper's storage and
  eliminate any intermediate copy.
- See [SECURITY.md](SECURITY.md#wrappers-dynamicrs-fixedrs) for the full stack-residue
  analysis and mitigations.
