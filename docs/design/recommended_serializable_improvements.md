## Instructions for Implementing Recommendations on Serializable Macro Aliases

### Summary
These instructions compile all recommendations from the code review for the serializable_dynamic_alias! and serializable_fixed_alias! macros. They are grouped by subject area (e.g., implementation, documentation), with sub-items enumerated as phases or steps where applicable. Each group includes rationale, exact code changes, expected impact, and verification steps for complete implementation guidance. The macros already implement SerializableType as a marker trait, providing a safe opt-in for users requiring serialization while maintaining security invariants (e.g., explicit exposure, zeroization on drop).

## 1. Implementation Tweaks
These address minor code refinements for safety, consistency, and completeness without altering core functionality.

1. **Tighten Deserialize bound in serializable_dynamic_alias! to DeserializeOwned**
   - **Rationale**: Current Deserialize<'de> allows borrowed data in theory, but Dynamic<T> requires owned T for heap allocation; tightening prevents lifetime issues and adds safety for dynamic types.
   - **Steps**:
     - Phase 1: Update the Deserialize impl in serializable_dynamic_alias! to:
       ```rust
       #[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
       impl<'de> serde::Deserialize<'de> for $name
       where
           $type: serde::de::DeserializeOwned,
       {
           fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
           where
               D: serde::Deserializer<'de>,
           {
               let inner = <$type>::deserialize(deserializer)?;
               Ok(Self::from(inner))
           }
       }
       ```
     - Phase 2: Verify no changes needed for serializable_fixed_alias! (array Deserialize is already owned).
   - **Expected impact**: Safer lifetime handling; prevents subtle bugs with borrowed deserializers.
   - **Verification**: Add compile-fail test with borrowed Deserialize type; run cargo test --features=serde.

2. **Consider splitting Serialize/Deserialize impls behind separate features (optional but recommended)**
   - **Rationale**: Aligns with crate's serde-deserialize/serde-serialize split; allows deserialize-only for safer loading without enabling serialization leaks.
   - **Steps**:
     - Phase 1: Wrap Serialize impl in #[cfg(feature = "serde-serialize")].
     - Phase 2: Wrap Deserialize impl in #[cfg(feature = "serde-deserialize")].
     - Phase 3: Update macro doc: "Serialize requires 'serde-serialize'; Deserialize requires 'serde-deserialize'."
   - **Expected impact**: Finer-grained control; encourages deserialize-only usage.
   - **Verification**: Test compile with partial features (e.g., cargo check --features=serde-deserialize, no serde-serialize); ensure impls are gated.

3. **No further implementation changes needed for DerefMut or error handling**
   - **Rationale**: No DerefMut is correct (prevents accidental mutation); Deserialize error handling uses D::Error — standard and flexible.
   - **Steps**: None — confirm by code audit.
   - **Expected impact**: N/A.
   - **Verification**: Compile with all features; run existing serde tests.

## 2. Documentation Enhancements
These improve clarity, warnings, and user guidance in macro docs to emphasize security trade-offs and usage.

1. **Add strong security warning to both macro docs**
   - **Rationale**: Serialization risks leakage (logs, insecure storage); explicit warning reinforces opt-in nature and encourages non-serializable alternatives.
   - **Steps** (applied to both macros):
     - Phase 1: Insert the following at the top of the macro doc comment (after syntax):
       ```rust
       /// **Warning**: this type is deliberately serializable.
       /// Serialization can lead to accidental leakage (logs, debug output, insecure storage).
       /// Only use when serialization is explicitly required (e.g. trusted config, secure channel).
       /// Prefer non-serializable Fixed / Dynamic when possible to prevent exfiltration.
       ```
     - Phase 2: Ensure warning appears in rustdoc output.
   - **Expected impact**: Reduces misuse; educates users on risks.
   - **Verification**: Run rustdoc and inspect generated docs; check for warning visibility.

2. **Add inline examples to macro docs**
   - **Rationale**: Demonstrates usage, including Serialize and SerializableType, for better discoverability.
   - **Steps** (grouped by macro):
     - For serializable_fixed_alias!: Add after syntax:
       ```rust
       /// # Examples
       /// ```
       /// use secure_gate::serializable_fixed_alias;
       /// serializable_fixed_alias!(pub SerializableKey, 32);
       ///
       /// #[cfg(feature = "serde")]
       /// let key = SerializableKey::from([42u8; 32]);
       /// let json = serde_json::to_string(&key).unwrap();
       /// ```
       ```
     - For serializable_dynamic_alias!: Add similar:
       ```rust
       /// # Examples
       /// ```
       /// use secure_gate::serializable_dynamic_alias;
       /// serializable_dynamic_alias!(pub SerializableToken, Vec<u8>);
       ///
       /// #[cfg(feature = "serde")]
       /// let token = SerializableToken::from(vec![1,2,3]);
       /// let json = serde_json::to_string(&token).unwrap();
       /// ```
       ```
   - **Expected impact**: Better user onboarding; reduces confusion.
   - **Verification**: Run doctests (`cargo test --doc`); confirm examples compile/pass.

## 3. Future Extensions (Optional)
These are non-urgent additions for potential later implementation if user demand arises.

1. **Add optional custom doc parameter**
   - **Rationale**: Allows users to override default doc (e.g., "My custom serializable key").
   - **Steps**:
     - Phase 1: Add arms like ($vis:vis $name:ident, $type:ty, $doc:literal) => { #[doc = $doc] ... }.
     - Phase 2: Update syntax doc to mention optional doc.
   - **Expected impact**: More flexible for users.
   - **Verification**: Test macro expansion with custom doc; check rustdoc.

2. **No extensions needed for DerefMut or additional bounds**
   - **Rationale**: Current impls are sufficient; no DerefMut is intentional for safety.
   - **Steps**: None.
   - **Expected impact**: N/A.
   - **Verification**: Code audit.

## Implementation Plan
- **Priority**: 1 (high: Deserialize bound, warning) > 2 (medium: examples) > 3 (low: future).
- **Testing**: After changes, run `cargo test --all-features`, `cargo clippy --all-features`, `cargo doc --open` to verify.
- **Backward compatibility**: All changes additive/non-breaking.
- **Estimated effort**: Low — mostly doc additions and one bound tweak.