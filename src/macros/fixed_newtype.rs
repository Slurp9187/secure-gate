//! `fixed_newtype!` — nominal newtype over `Fixed<[u8; N]>`.
//!
//! Ships in 0.9.0. Design record:
//! [`docs/nominal_newtypes.md`](https://github.com/Slurp9187/secure-gate/blob/main/docs/design/nominal_newtypes.md) — a repository file, not part of the
//! published crate, so this is a link and not a path.

/// Creates a distinct nominal type wrapping [`Fixed<[u8; N]>`](crate::Fixed).
///
/// Generates a `struct` rather than a `type` alias: two `fixed_newtype!` types
/// of the same `N` are **not** interchangeable, where two `type` aliases of
/// that `N` are one and the same type. Use it when distinct cryptographic
/// roles share a shape — an encryption key and a MAC key are both
/// `Fixed<[u8; 32]>`, and under a plain alias the compiler cannot tell them
/// apart.
///
/// # Syntax
///
/// ```text
/// fixed_newtype!(pub Name, N);                          // public, auto-generated doc
/// fixed_newtype!(pub(crate) Name, N);                   // crate-visible
/// fixed_newtype!(Name, N);                              // private
/// fixed_newtype!(pub Name, N, "doc string");            // with custom doc
/// fixed_newtype!(pub Name, N, derive: [ConstantTimeEq]); // with opt-in impls
/// fixed_newtype!(pub Name, N, "doc", derive: [ConstantTimeEq]);
/// fixed_newtype!(pub Name, generic T);                  // reduced API, opted into
/// fixed_newtype!(pub Name, generic T, "doc string");
/// fixed_newtype!(pub Name, generic T, derive: [ConstantTimeEq]);
/// fixed_newtype!(pub Name, generic T, "doc", derive: [ConstantTimeEq]);
/// ```
///
/// Supported `derive:` options are `ConstantTimeEq`, `Deserialize`, `FromWrapper`, `IntoWrapper`, and `WrapperAccess` (= both directions). See
/// *Cloning and serialization* below for the two that are deliberately absent.
///
/// # Examples
///
/// All three visibility forms:
///
/// ```rust
/// use secure_gate::{fixed_newtype, SecretLen};
///
/// fixed_newtype!(pub EncKey, 32);          // public
/// fixed_newtype!(pub(crate) HmacKey, 32);  // crate-visible
/// fixed_newtype!(local_nonce, 12);         // private
///
/// let key = EncKey::new([42u8; 32]);
/// assert_eq!(key.len(), 32);
/// ```
///
/// Distinct roles do not mix — this is the point:
///
/// ```rust,compile_fail
/// use secure_gate::fixed_newtype;
///
/// fixed_newtype!(pub EncKey, 32);
/// fixed_newtype!(pub MacKey, 32);
///
/// fn seal(_enc: &EncKey, _mac: &MacKey) {}
///
/// let enc = EncKey::new([1u8; 32]);
/// let mac = MacKey::new([2u8; 32]);
/// seal(&mac, &enc); // E0308: roles swapped
/// ```
///
/// Zero-size is a **compile error**, raised where the type is declared rather
/// than where one is first built:
///
/// ```rust,compile_fail
/// use secure_gate::fixed_newtype;
/// fixed_newtype!(pub Bad, 0); // compile-time error: index out of bounds
/// ```
///
/// # Inner types other than bytes
///
/// The size-literal forms cover `Fixed<[u8; N]>`, the shape nearly every
/// secret takes. [`Fixed<T>`](crate::Fixed) holds more than that, and the
/// `generic` marker opts a newtype into it. The requirement is
/// `Zeroize + `[`SentinelValue`](crate::SentinelValue), checked at the
/// declaration — slightly narrower than `Fixed<T>` itself, which needs only
/// `Zeroize`, because the generated [`into_inner`](crate::RevealSecret::into_inner)
/// has to leave an inert value behind. Arrays of a `Default` element, `String`
/// and `Vec<T>` already satisfy both; a custom inner type needs its own
/// `impl SentinelValue`, which is why that trait is public:
///
/// ```rust
/// use secure_gate::{fixed_newtype, RevealSecret};
///
/// fixed_newtype!(pub Poly, generic [i16; 256]);
///
/// let poly = Poly::new([0i16; 256]);
/// assert_eq!(poly.with_secret(|coeffs| coeffs.len()), 256);
/// ```
///
/// The case this exists for is `no_std`. With no allocator there is no
/// [`Dynamic`](crate::Dynamic), so `Fixed` is the only wrapper, and a secret on
/// such a target is frequently not bytes: an ML-KEM secret polynomial
/// `[i16; 256]`, Ed25519 scalar limbs `[u64; 4]`, AES-256 expanded round keys
/// `[u32; 60]`. An inner type missing either bound is a compile error reported
/// from the expansion: `Zeroize` fails against `Fixed<T>`'s own bound, and
/// `SentinelValue` against the one the generated `RevealSecret` restates.
/// [`dynamic_newtype!`](crate::dynamic_newtype)'s `generic` arm carries the
/// same pair, for the same reason.
///
/// The `generic` form deliberately provides less: [`RevealSecret`](crate::RevealSecret),
/// [`RevealSecretMut`](crate::RevealSecretMut), redacted `Debug`, `Zeroize`,
/// `ZeroizeOnDrop`, and `new`. Absent are [`SecretLen`](crate::SecretLen), `From`
/// and `TryFrom`, the encoders and the RNG constructors, none of which has a
/// meaning for an arbitrary `T` — a length in elements is not the byte length
/// callers expect, and hex over a `Vec<u32>` has no defined byte order. Writing
/// the marker is how you say you know that. A zero-sized inner value is still
/// refused: there is no `N` for the macro to check, so
/// [`Fixed`](crate::Fixed) rejects it at construction instead.
///
/// **`new_with` is absent for a different reason, and it costs you something.**
/// Unlike the others it is perfectly meaningful for an arbitrary `T`; it simply
/// is not generated. So the arm has no in-place constructor, and `new` takes its
/// value by value — which is the construction the size-literal arms offer
/// `new_with` to avoid, because a by-value argument may leave a copy of the
/// secret on the caller's frame that nothing will wipe (see
/// [`Fixed::new_with`](crate::Fixed::new_with)). On this arm that mitigation is
/// unavailable: build the value as close to the call as you can, and prefer a
/// size-literal newtype when the secret is a byte array and residue matters.
///
/// # Cloning and serialization are not generated
///
/// There is no `derive: [Clone]` or `derive: [Serialize]`, by design. Neither
/// can be forwarded from the wrapper — `Fixed<[u8; N]>: Clone` requires
/// `[u8; N]: `[`CloneableSecret`](crate::CloneableSecret), which the orphan
/// rule makes permanently unimplementable downstream (deliberately so). A
/// generated impl would therefore have to route through `with_secret` and
/// rebuild, opting the secret into cloning with no marker impl anywhere — a
/// second door around the opt-in system, spelled in one word inside a macro
/// expansion. Asking for either is a compile error that says so.
///
/// The generated type is local to **your** crate, so write the impl by hand
/// when you mean it. The decision then lives in your code, where it is
/// visible, greppable, and reviewable:
///
/// ```rust
/// use secure_gate::{fixed_newtype, Fixed, RevealSecret};
///
/// fixed_newtype!(pub SessionKey, 32);
///
/// // Deliberate: each clone is an independent copy, zeroized on its own drop.
/// // Cloning widens the window for memory-extraction attacks — audit each use.
/// impl Clone for SessionKey {
///     fn clone(&self) -> Self {
///         Self::new(self.with_secret(|bytes| *bytes))
///     }
/// }
///
/// let key = SessionKey::new([7u8; 32]);
/// let copy = key.clone();
/// assert_eq!(copy.expose_secret()[0], 7);
/// ```
///
/// The same applies to `Serialize`, with a higher bar: serialization exposes
/// the full secret, so treat a hand-written impl as a security decision and
/// see [`SerializableSecret`](crate::SerializableSecret) for the risk notes.
///
/// # Implementation Notes
///
/// The generated type is `#[repr(transparent)]` over the wrapper, so
/// `size_of::<EncKey>() == N` and delegation is `#[inline]` throughout — the
/// newtype costs nothing at runtime.
///
/// Each size-literal expansion emits `const _: () = { let _ = [(); N][0]; };`,
/// a declaration-site courtesy: `N = 0` fails on the line that declares the
/// type, which is the line worth pointing at. It is not the only guard.
/// [`Fixed::new`](crate::Fixed::new) and
/// [`Fixed::new_with`](crate::Fixed::new_with) carry a `const` assertion
/// rejecting a zero-sized inner value at construction, which is what covers a
/// plain `type` alias and the `generic` arm; there the error falls at the first
/// concrete construction instead.
///
/// **Do not add your own `Drop` impl.** None is needed: the wrapped
/// [`Fixed`](crate::Fixed) still runs its own, so zeroization is unaffected.
/// Adding one makes the inner field unmovable (**E0509**) and silently costs
/// you [`into_inner`](crate::RevealSecret::into_inner).
///
/// # Security
///
/// Generated types inherit every [`Fixed`](crate::Fixed) guarantee: zeroize on
/// drop, `Debug` that always prints `[REDACTED]`, and access only through
/// [`RevealSecret`](crate::RevealSecret) /
/// [`RevealSecretMut`](crate::RevealSecretMut). There is no `Deref` — a
/// generated newtype is not coercible to its wrapper, which is what keeps the
/// nominal separation total rather than by-value-only.
///
/// **Nominal separation guards against mistakes, not intent** — but nothing is
/// generated that would undo it by accident. There is no `From<Wrapper>` and
/// no `Deref`, so a base-typed value cannot flow into a newtype through
/// `.into()`, and `&Newtype` never coerces to `&Wrapper` at a call site. By
/// default the only way material enters or leaves is the 3-tier access API —
/// a `with_secret` round trip — which is explicit and shows up in the audit
/// sweep. Base-wrapper access is opt-in, per newtype, and **split by
/// direction**: `derive: [FromWrapper]` adds `from_wrapper` (a base value
/// *enters* this role), `derive: [IntoWrapper]` adds `as_wrapper`,
/// `as_wrapper_mut`, and `into_wrapper` (material *leaves* this role toward
/// the base type), and `derive: [WrapperAccess]` is shorthand for both.
///
/// These cross a different wall from `into_inner`. A newtype has two:
///
/// | Wall | Going in | Going out |
/// |---|---|---|
/// | Contents (the wrapper's protection) | `new`, `From<[u8; N]>` | `with_secret`, `expose_secret`, `into_inner` |
/// | Role (the nominal label) | `from_wrapper` | `as_wrapper`, `as_wrapper_mut`, `into_wrapper` |
///
/// `into_inner` leaves the protection: it hands back the plain value, so the
/// contents are in the caller's hands (tier 3 of the access model, audited).
/// `into_wrapper` is a **label** drop; `into_inner` is a **protection** drop.
/// Confusing those two names is the main way this model gets misread. `into_wrapper` only removes the label: the
/// result is still a `Fixed`, still unreadable without `with_secret`. The
/// role row exists so that dropping a label never forces opening the
/// contents — without it, reaching base-typed code costs an `into_inner` plus
/// a rebuild, a reveal the job never needed.
///
/// **Which direction is safe depends on the pool.** In a mixed tree the base
/// type is not raw material: every plain `type` alias sharing it *is* that
/// type, so a directional token connects this role to all of them at once.
/// `FromWrapper` lets anything in the pool become this role — the source never
/// opts in, because the source is just the base type — so a type that guards
/// a boundary must never take it. `IntoWrapper` lets this role become anything
/// in the pool, which is safe only when the role is no more sensitive than
/// the least-sensitive alias sharing its base; on a secret role it is an
/// explicit, greppable downgrade, not a neutral operation. The default,
/// neither token, is sufficient more often than it looks. The exposure is
/// largest during a partial migration — the regime real consumers live in —
/// because while most aliases stay plain the base type is a universal donor.
/// Audit these methods the way you audit `expose_secret()`.
///
/// # See also
///
/// - [`dynamic_newtype!`](crate::dynamic_newtype) — heap-allocated counterpart
/// - a plain `type` alias — `pub type Aes256Key = Fixed<[u8; 32]>;` — when a
///   readable name rather than role separation is the goal, and the name should
///   stay interchangeable with its base. Two aliases over one shape are the
///   same type, so the compiler will not keep two roles apart; that is the
///   whole of the choice, and the crate's README argues it at length
#[macro_export]
macro_rules! fixed_newtype {
    // ---- explicit generic arms: caller opts in to the reduced API ----
    //
    // Placed first. They match the literal token `generic` in the inner-type
    // position, so they cannot shadow a size literal, and matching the marker
    // before any `:literal` or `:ty` fragment is parsed keeps the ordering
    // safe: `macro_rules!` does not backtrack once a fragment has been
    // consumed. The doc-literal forms get their own arms, exactly as
    // `dynamic_newtype!`'s generic form does, so that the third positional
    // argument means the same thing on both macros and on every arm of each.
    ($(#[$attr:meta])* $vis:vis $name:ident, generic $inner:ty
     $(, $doc:literal)? $(, derive: [$($opt:ident),* $(,)?])?) => {
        $crate::__sg_newtype_base!(
            $(#[$attr])* $(#[doc = $doc])* $vis $name($crate::Fixed<$inner>),
            derive: [$($($opt),*)?]
        );

        impl $name {
            /// Wraps a value in place. `const fn`, like `Fixed::new`.
            #[inline(always)]
            pub const fn new(value: $inner) -> Self {
                Self($crate::Fixed::new(value))
            }
        }
    };

    ($(#[$attr:meta])* $vis:vis $name:ident, $size:literal, $doc:literal, derive: [$($opt:ident),* $(,)?]) => {
        $crate::fixed_newtype!($(#[$attr])* #[doc = $doc] $vis $name, $size, derive: [$($opt),*]);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, $size:literal, $doc:literal) => {
        $crate::fixed_newtype!($(#[$attr])* #[doc = $doc] $vis $name, $size, derive: []);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, $size:literal) => {
        $crate::fixed_newtype!($(#[$attr])* $vis $name, $size, derive: []);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, $size:literal, derive: [$($opt:ident),* $(,)?]) => {
        const _: () = { let _ = [(); $size][0]; };

        $crate::__sg_newtype_base!(
            $(#[$attr])* $vis $name($crate::Fixed<[u8; $size]>), derive: [$($opt),*]
        );
        $crate::__sg_newtype_len!($name);

        impl $name {
            /// Wraps a fixed-size byte array. `const fn`, like `Fixed::new`.
            #[inline(always)]
            pub const fn new(value: [u8; $size]) -> Self {
                Self($crate::Fixed::new(value))
            }
            /// Scoped construction — writes directly into the wrapper's storage.
            #[inline(always)]
            pub fn new_with<F>(f: F) -> Self
            where F: ::core::ops::FnOnce(&mut [u8; $size]) {
                Self($crate::Fixed::new_with(f))
            }
        }

        impl ::core::convert::From<[u8; $size]> for $name {
            #[inline(always)]
            fn from(value: [u8; $size]) -> Self { Self($crate::Fixed::new(value)) }
        }

        impl ::core::convert::TryFrom<&[u8]> for $name {
            type Error = $crate::FromSliceError;
            #[inline]
            fn try_from(slice: &[u8]) -> ::core::result::Result<Self, Self::Error> {
                ::core::result::Result::Ok(Self(
                    <$crate::Fixed<[u8; $size]> as ::core::convert::TryFrom<&[u8]>>::try_from(slice)?
                ))
            }
        }

        $crate::__sg_if_rand! {
            impl $name {
                /// Generates the secret from the system RNG.
                #[inline]
                pub fn from_random() -> Self { Self($crate::Fixed::from_random()) }

                /// Generates the secret from a caller-supplied CSPRNG.
                #[inline]
                pub fn from_rng<R>(rng: &mut R) -> ::core::result::Result<Self, R::Error>
                where
                    R: $crate::__private::TryRng + $crate::__private::TryCryptoRng,
                {
                    ::core::result::Result::Ok(Self($crate::Fixed::from_rng(rng)?))
                }
            }
        }

        $crate::__sg_if_hex! {
            impl $name {
                /// Constant-time hex decode into this secret type.
                #[inline]
                pub fn try_from_hex(hex: &str) -> ::core::result::Result<Self, $crate::HexError> {
                    ::core::result::Result::Ok(Self($crate::Fixed::try_from_hex(hex)?))
                }
            }
            $crate::__sg_if_alloc! {
                impl $crate::ToHex for $name {
                    #[inline]
                    fn to_hex(&self) -> $crate::EncodedSecret {
                        $crate::ToHex::to_hex(&self.0)
                    }
                    #[inline]
                    fn to_hex_upper(&self) -> $crate::EncodedSecret {
                        $crate::ToHex::to_hex_upper(&self.0)
                    }
                }
            }
        }

        $crate::__sg_if_base32! {
            impl $name {
                /// Constant-time Base32 decode into this secret type.
                #[inline]
                pub fn try_from_base32(s: &str) -> ::core::result::Result<Self, $crate::Base32Error> {
                    ::core::result::Result::Ok(Self($crate::Fixed::try_from_base32(s)?))
                }
            }
            $crate::__sg_if_alloc! {
                impl $crate::ToBase32 for $name {
                    #[inline]
                    fn to_base32(&self) -> $crate::EncodedSecret {
                        $crate::ToBase32::to_base32(&self.0)
                    }
                }
            }
        }

        $crate::__sg_if_base64! {
            impl $name {
                /// Constant-time Base64url decode into this secret type.
                #[inline]
                pub fn try_from_base64url(s: &str) -> ::core::result::Result<Self, $crate::Base64Error> {
                    ::core::result::Result::Ok(Self($crate::Fixed::try_from_base64url(s)?))
                }
            }
            $crate::__sg_if_alloc! {
                impl $crate::ToBase64Url for $name {
                    #[inline]
                    fn to_base64url(&self) -> $crate::EncodedSecret {
                        $crate::ToBase64Url::to_base64url(&self.0)
                    }
                }
            }
        }

        $crate::__sg_if_bech32m! {
            impl $name {
                /// HRP-validated Bech32m decode into this secret type.
                #[inline]
                pub fn try_from_bech32m(s: &str, expected_hrp: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self($crate::Fixed::try_from_bech32m(s, expected_hrp)?))
                }
                /// Bech32m decode without HRP validation.
                #[inline]
                pub fn try_from_bech32m_unchecked(s: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self($crate::Fixed::try_from_bech32m_unchecked(s)?))
                }
                /// HRP-validated Bech32m decode accepting strings up to `C` characters.
                #[inline]
                pub fn try_from_bech32m_sized<const C: usize>(s: &str, expected_hrp: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self(
                        $crate::Fixed::try_from_bech32m_sized::<C>(s, expected_hrp)?,
                    ))
                }
                /// Bech32m decode without HRP validation, accepting strings up to `C` characters.
                #[inline]
                pub fn try_from_bech32m_unchecked_sized<const C: usize>(s: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self(
                        $crate::Fixed::try_from_bech32m_unchecked_sized::<C>(s)?,
                    ))
                }
            }
            $crate::__sg_if_alloc! {
                impl $crate::ToBech32m for $name {
                    #[inline]
                    fn try_to_bech32m(
                        &self,
                        hrp: &str,
                        case: $crate::Case,
                    ) -> ::core::result::Result<$crate::EncodedSecret, $crate::Bech32Error> {
                        $crate::ToBech32m::try_to_bech32m(&self.0, hrp, case)
                    }
                    #[inline]
                    fn try_to_bech32m_sized<const C: usize>(
                        &self,
                        hrp: &str,
                        case: $crate::Case,
                    ) -> ::core::result::Result<$crate::EncodedSecret, $crate::Bech32Error> {
                        $crate::ToBech32m::try_to_bech32m_sized::<C>(&self.0, hrp, case)
                    }
                }
            }
        }

        $crate::__sg_if_bech32! {
            $crate::__sg_if_alloc! {
                impl $crate::ToBech32 for $name {
                    #[inline]
                    fn try_to_bech32(
                        &self,
                        hrp: &str,
                        case: $crate::Case,
                    ) -> ::core::result::Result<$crate::EncodedSecret, $crate::Bech32Error> {
                        $crate::ToBech32::try_to_bech32(&self.0, hrp, case)
                    }
                    #[inline]
                    fn try_to_bech32_sized<const C: usize>(
                        &self,
                        hrp: &str,
                        case: $crate::Case,
                    ) -> ::core::result::Result<$crate::EncodedSecret, $crate::Bech32Error> {
                        $crate::ToBech32::try_to_bech32_sized::<C>(&self.0, hrp, case)
                    }
                }
            }
            impl $name {
                /// HRP-validated Bech32 decode into this secret type.
                #[inline]
                pub fn try_from_bech32(s: &str, expected_hrp: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self($crate::Fixed::try_from_bech32(s, expected_hrp)?))
                }
                /// Bech32 decode without HRP validation.
                #[inline]
                pub fn try_from_bech32_unchecked(s: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self($crate::Fixed::try_from_bech32_unchecked(s)?))
                }
                /// HRP-validated Bech32 decode accepting strings up to `C` characters.
                #[inline]
                pub fn try_from_bech32_sized<const C: usize>(s: &str, expected_hrp: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self(
                        $crate::Fixed::try_from_bech32_sized::<C>(s, expected_hrp)?,
                    ))
                }
                /// Bech32 decode without HRP validation, accepting strings up to `C` characters.
                #[inline]
                pub fn try_from_bech32_unchecked_sized<const C: usize>(s: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self(
                        $crate::Fixed::try_from_bech32_unchecked_sized::<C>(s)?,
                    ))
                }
            }
        }
    };

    // ---- catch-all: neither a byte size nor the `generic` marker ----
    //
    // Uses `$($rest:tt)+` rather than `$inner:ty` so it can never itself
    // hard-error on a malformed tail; the message names what was written.
    ($(#[$attr:meta])* $vis:vis $name:ident, $($rest:tt)+) => {
        ::core::compile_error!(::core::concat!(
            "fixed_newtype!: no form matches `",
            ::core::stringify!($($rest)+),
            "`. The accepted forms are `N`, `N, \"doc\"`, `N, derive: [..]` and \
             `N, \"doc\", derive: [..]`, where N is the length of the `[u8; N]` \
             array being wrapped; and the same four with `generic <type>` in place \
             of N, for an inner type that is not a byte array \
             (`fixed_newtype!(pub K, generic [i16; 256])`), which takes the reduced \
             API (RevealSecret, RevealSecretMut, Debug, Zeroize, and `new`) on \
             purpose. If the length or the marker looks right, the problem is in \
             what follows it: a `derive:` list needs brackets, and accepts only \
             ConstantTimeEq, Deserialize, FromWrapper, IntoWrapper and \
             WrapperAccess."
        ));
    };
}
