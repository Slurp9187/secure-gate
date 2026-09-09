### Secure Gate Crate Restructure Plan

This plan outlines a comprehensive refactor based on our discussion, aiming for better organization, separation of concerns, idiomatic naming, granular features, and improved security/ergonomics. The goal is a more maintainable, scalable crate with clear APIs, while preserving all existing security invariants (explicit exposure, zeroizing, etc.).

The refactor is broken into **phases** with actionable steps and to-dos. Assume you're working from the current codebase (with `conversions.rs`, `rng.rs`, `fixed.rs`, `dynamic.rs`, etc.). Test thoroughly after each phase (unit tests, feature combinations, no-std compatibility).

#### Phase 1: Module Reorganization
Focus: Split and rename modules for clarity. Create `encoding/` subdirectory.

**Steps:**
1. Create `src/encoding/` directory.
2. Move hex-related code from `conversions.rs` to `src/encoding/hex.rs`:
   - `to_hex`, `to_hex_upper` extensions (via new `SecretEncodingExt` trait or inherent methods on `[u8]`/`[u8; N]`).
   - `HexString` struct, validation (`new()`), `to_bytes()`, `byte_len()`.
   - Optional CT `PartialEq` for `HexString` (gated on `ct-eq`).
   - Add internal `new_unchecked()` for trusted hex (e.g., from RNG).
3. Move base64-related code to `src/encoding/base64.rs` (similar to hex).
4. Add `src/encoding/mod.rs`:
   - `#[cfg(feature = "encoding-hex")] pub mod hex;`
   - `#[cfg(feature = "encoding-base64")] pub mod base64;`
5. Delete `conversions.rs`.
6. Rename `src/rng.rs` to `src/random.rs`:
   - Update all imports/re-exports in `lib.rs` (e.g., `pub mod random;`).
   - Update docs to reflect "random number generation".
7. Create `src/eq.rs`:
   - Add `ConstantTimeEq` trait with impls for `[u8]` and `[u8; N]` (using `subtle`).
   - Make trait `pub` for extensibility.

**To-Dos:**
- Update all internal imports (e.g., change `crate::conversions::HexString` to `crate::encoding::hex::HexString`).
- Run `cargo check` and fix any path errors.
- Update any examples in docs/tests to use new paths (e.g., `secure_gate::encoding::hex::HexString`).

#### Phase 2: API Adjustments and Simplifications
Focus: Refine types and methods for ergonomics and security.

**Steps:**
1. Remove `RandomHex` entirely (no wrapper type needed).
2. In `random.rs`, add methods to `FixedRng<N>` (gated on `feature = "rand" && "encoding-hex"`):
   - `into_hex(self) -> encoding::hex::HexString` (consumes self, encodes, zeroizes raw bytes immediately).
   - Optional `to_hex(&self) -> encoding::hex::HexString` (non-consuming, for cases where raw is still needed briefly).
   - Use `HexString::new_unchecked()` for efficiency.
3. Optionally, add `into_hex()` to `Fixed<[u8; N]>` in `fixed.rs` (same gating, delegates to slice encoding).
4. Do NOT add hex methods to `Dynamic` or `DynamicRng` — users can use general encoding extensions on `.expose_secret()`.
5. In `fixed.rs` and `dynamic.rs`, add inherent `ct_eq` methods (gated on `ct-eq`):
   - For `Fixed<[u8; N]>`: delegate to `expose_secret().ct_eq()`.
   - For `Dynamic<T: AsRef<[u8]>>`: delegate similarly.
   - Import `crate::eq::ConstantTimeEq` for delegation.
6. Update encoding extensions:
   - Use a new trait `SecretEncodingExt` in `encoding/mod.rs` (impl on `[u8]` and `[u8; N]`).
   - Ensure methods require `.expose_secret()`.

**To-Dos:**
- Update examples/docs to show new usage (e.g., `BackupCode::generate().into_hex()` instead of `random_hex()`).
- Add deprecation notes if needed for old APIs (e.g., via `#![allow(deprecated)]` or migration guide in README).
- Test: Generate random, encode to hex, verify zeroization (if `zeroize` enabled), check CT equality.
- Ensure `generate_random()` on `Fixed`/`Dynamic` works with new encoding paths.

#### Phase 3: Feature Updates in Cargo.toml
Focus: Make features granular and composable.

**Steps:**
1. Update `[features]` section:
   ```toml
   [features]
   default = ["encoding", "rand"]

   encoding = ["encoding-hex", "encoding-base64"]
   encoding-hex = ["hex"]  # Add actual dep: hex = { version = "...", optional = true }
   encoding-base64 = ["base64"]  # Similar for base64

   ct-eq = ["subtle"]  # dep: subtle = { version = "...", optional = true }
   rand = ["getrandom", "rand_core"]  # Existing deps
   ```
2. Remove old `conversions` feature (replace all `#[cfg(feature = "conversions")]` with new gates).
3. Update dependencies to be optional where possible (e.g., `hex`, `base64`, `subtle`).
4. In code, use combined gates for cross-feature items (e.g., `#[cfg(all(feature = "rand", feature = "encoding-hex"))]` for `into_hex()`).

**To-Dos:**
- Run `cargo build --no-default-features` and test minimal combinations (e.g., only `rand`, only `encoding-hex`).
- Update README with new feature docs (e.g., "Enable `encoding-hex` for hex support").
- Check binary size impact with `cargo bloat` (ensure granular features help minimal builds).

#### Phase 4: Documentation, Testing, and Polish
Focus: Ensure the refactor doesn't break users; add guides.

**Steps:**
1. Update `lib.rs` re-exports for usability (e.g., `pub use encoding::hex::HexString;` if common).
2. Revise all docs:
   - Module-level: Explain `encoding` as "text representations of secrets".
   - `random`: "Fresh random value generation".
   - `eq`: "Constant-time operations".
   - Methods: Emphasize security (e.g., "Consumes self to zeroize raw bytes immediately").
3. Add a `MIGRATION.md` or section in README for breaking changes (e.g., path renames, `RandomHex` removal).
4. Expand tests:
   - Feature-gated tests (use `#[cfg(test)] mod tests { #[cfg(feature = "encoding-hex")] mod hex_tests; }`).
   - Security-focused: Verify zeroization, CT equality timing (via benchmarks if possible).
   - Edge cases: Invalid hex/base64, zero-length, no-std.

**To-Dos:**
- Bump crate version (e.g., to 0.2.0 for breaking changes).
- Run `cargo clippy --all-features` and fix lints.
- `cargo fmt` everything.
- Test on multiple platforms (std/no-std, with/without `zeroize`).
- Publish a pre-release if possible for feedback.

#### Estimated Timeline and Risks
- **Time**: 4-8 hours for an experienced dev (Phase 1-2: 2-3h; Phase 3-4: 2-3h).
- **Risks**: Path/import breaks (mitigate with `cargo check`); feature combos (test matrix: all on/off).
- **Post-Refactor Wins**: Cleaner code, smaller binaries for minimal users, easier to add new encodings (e.g., Bech32).