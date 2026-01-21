# Recommended Improvements & Safety Review for Cloneable Macro Aliases

## Summary
This issue consolidates all feedback and recommendations given during the code review of `cloneable_fixed_alias!` and `cloneable_dynamic_alias!`.

The macros are **correct**, **safe by construction**, and **well-implemented**, but they deliberately trade off one of the strongest safety properties (no accidental cloning) for usability in specific multi-owner/multi-threaded scenarios.

Main goals of the changes below:
- Make the **risk of cloning** extremely visible in documentation
- Prevent silent misuse
- Improve ergonomics and consistency
- Add missing conveniences without weakening invariants

## 1. Documentation & Warning Enhancements
**Priority: High** — most important change to reduce misuse risk.

1. **Add prominent security warning at the top of both macro doc comments**
   - **Rationale**: Cloning secrets increases memory copies → higher attack surface. Users must understand this is an **opt-in relaxation** of normal security rules.
   - **Exact text to add** (place immediately after the macro description):

     ```rust
     /// **SECURITY WARNING**
     /// This macro creates a **deliberately cloneable** secret type.
     /// Cloning increases the number of in-memory copies of the secret,
     /// which raises the risk of leakage via memory dumps, side-channels,
     /// or programming errors.
     ///
     /// Only use this macro when multiple independent copies are semantically required
     /// (e.g. passing secrets to multiple threads, storing in multiple data structures).
     ///
     /// In most cryptographic use-cases, prefer the **non-cloneable** `Fixed` / `Dynamic`
     /// types to enforce move semantics and prevent accidental duplication at compile time.
     ```

2. **Add usage discipline note in examples**
   - **Rationale**: Show safe patterns and explicitly discourage unsafe ones.
   - **Add to examples section** (both macros):

     ```rust
     /// # Safe usage example (multi-threaded)
     /// ```
     /// let key = Aes256Key::from_random();
     /// let key_clone = key.clone(); // explicit, intentional
     /// std::thread::spawn(move || { use_key(key_clone) });
     /// ```
     ///
     /// # Discouraged: accidental cloning
     /// ```compile_fail
     /// let keys: Vec<Aes256Key> = vec![key.clone(), key.clone()]; // avoid this
     /// ```
     ```

3. **Document that CloneableType marker is required**
   - **Rationale**: Reinforces that this is an explicit opt-in, not automatic.
   - **Add after the Clone impl**:

     ```rust
     /// The type also implements `CloneableType` marker trait,
     /// which can be used in generic bounds to require explicit clone opt-in.
     ```

## 2. Missing / Incomplete Implementation Items

1. **Add missing `From` impl in `cloneable_dynamic_alias!`**
   - **Rationale**: `cloneable_fixed_alias!` has `From<[u8; N]>` and `From<&[u8]>`, but dynamic version lacks `From<$type>`.
   - **Fix**:

     ```rust
     impl From<$type> for $name {
         fn from(value: $type) -> Self {
             Self($crate::Dynamic::new(value))
         }
     }
     ```

2. **Consider adding `From<Dynamic<$type>>` (optional)**
   - **Rationale**: Allows easy upgrade from non-cloneable to cloneable wrapper.
   - **If added**:

     ```rust
     impl From<$crate::Dynamic<$type>> for $name {
         fn from(dynamic: $crate::Dynamic<$type>) -> Self {
             Self(dynamic)
         }
     }
     ```

## 3. Ergonomics & Consistency Improvements

1. **Add `#[must_use]` to `Clone` impl (both macros)**
   - **Rationale**: Discourages ignoring clone results.
   - **Fix**:

     ```rust
     #[must_use]
     fn clone(&self) -> Self { … }
     ```

2. **Add `init_with` / `try_init_with` to dynamic version (already present in fixed)**
   - **Rationale**: Consistency between fixed and dynamic cloneable aliases.
   - **Already implemented in your dynamic version** → no action needed.

3. **Consider removing `Deref` in high-paranoia mode (optional future flag)**
   - **Rationale**: Deref exposes full `Dynamic`/`Fixed` API (`.len()`, etc.).
   - **If desired**: Gate behind a cfg or separate macro variant without Deref.

## 4. Testing & Validation Steps

1. **Add compile-fail tests for misuse patterns**
   - **Rationale**: Ensure users can't accidentally rely on automatic Clone.
   - **Suggested tests** (in tests/cloneable.rs):

     ```rust
     #[test]
     #[should_panic(expected = "use cloneable alias")]
     fn non_cloneable_cannot_clone() {
         let a: Fixed<[u8; 32]> = Fixed::from([0u8; 32]);
         let _ = a.clone(); // must fail to compile
     }
     ```

2. **Verify zeroization of clones**
   - **Rationale**: Confirm clones are independently zeroized.
   - **Suggested test** (with zeroize feature):

     ```rust
     #[test]
     #[cfg(feature = "zeroize")]
     fn clone_zeroize_independent() {
         let original = CloneableKey::from([42u8; 32]);
         let clone = original.clone();
         drop(original); // original zeroized
         // clone still valid
         assert_eq!(clone.expose_secret()[0], 42);
         drop(clone); // clone zeroized separately
     }
     ```

## 5. Release & Documentation Tasks

1. **Update crate README**
   - Add section: "Cloneable aliases" with security warning and when to use them.
   - Example:

     ```markdown
     ## Cloneable Aliases
     For cases where cloning is required, use `cloneable_fixed_alias!` / `cloneable_dynamic_alias!`.
     **Warning**: Only use when absolutely necessary — prefer move semantics otherwise.
     ```

2. **Run full test suite**
   - `cargo test --all-features`
   - `cargo clippy --all-features`
   - `cargo doc --open` (check warnings/docs)

## Acceptance Criteria
- [ ] Strong security warning present in both macro docs
- [ ] `From` impl added to cloneable_dynamic_alias!
- [ ] `#[must_use]` on Clone
- [ ] Compile-fail test for non-cloneable types added
- [ ] Zeroize independence test added (if zeroize feature)
- [ ] README updated with cloneable section & warning

## Estimated effort
Low – mostly doc additions, one missing impl, and 2–3 new tests.