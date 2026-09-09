# `EncodedSecret`: why the output wrapper derefs

> **Status: decided, and implemented as described.** Ships in 0.9.0 alongside the
> encoder merge (every encoder returns `EncodedSecret`; the `*_zeroizing` variants
> are gone) and the deletion of `InnerSecret<T>`. Backported to the 0.8 line in
> 0.8.0-rc.12, where the same three changes landed together; the record otherwise
> describes `main`.
>
> This is a rejected-alternatives record. It exists because `EncodedSecret` is the
> one type in this crate that deliberately breaks the crate's own no-`Deref` rule,
> and a reader who has internalised that rule is owed the reason. Nothing here is a
> threat-model claim — `SECURITY.md` stays the threat model and the audit surface
> list, and does not repeat this argument.

## The rule this type breaks

`Fixed<T>` and `Dynamic<T>` implement neither `Deref` nor `AsRef`. That is the
crate's central accident-prevention claim: while a secret is held, there is no
implicit path to its bytes, so reaching them is always something you typed
(`with_secret`, `expose_secret`, `into_inner`) and always something an auditor can
grep for. `tests/compile-fail/fixed_no_deref.rs` pins it against the compiler
rather than leaving it asserted in prose.

`EncodedSecret` implements `Deref<Target = str>`.

## Why the exception is correct

`EncodedSecret` is an **output wrapper, not a secret wrapper**. It does not
implement `RevealSecret`, and it is not a tier of the access model. It holds a
copy the caller already asked for: `to_hex` and friends copy the secret into a
longer alphabet, and that second copy is still the whole secret, so it comes back
wrapped — `Zeroizing<String>`, `Debug` redacted, no `Display` — rather than as a
bare `String`.

The type's entire job is to hand that encoded copy to APIs that already speak
`&str`: `sqlx`, `serde_json`, `rusqlite`, any driver that binds text. Deref
coercion — `takes_str(&*encoded)` — *is* the product. A wrapper that made that
awkward would be a wrapper people route around, and the routing-around is the
actual risk.

## The alternative, stated fairly

`.to_string()` on an `EncodedSecret` is not a language hole. It exists precisely
because `Deref<Target = str>` puts every `str` method on the type. The fix is
available and it is small:

- drop `Deref`, add an inherent `as_str(&self) -> &str`
- `encoded.to_string()` stops compiling
- drivers wanting `&str` call `encoded.as_str()`
- generic bounds like `impl AsRef<str>` still work if `AsRef` is put back as a
  named door (it was removed this release — see below)

That is exactly the posture `Fixed`/`Dynamic` take, and it would close the last
quiet way to get an owned `String` out of the type.

## Why it was rejected anyway

Two reasons, in order of weight.

**The cost lands on the type's only job.** Every call site that feeds a driver
grows an `.as_str()`. The type becomes clumsy at the one thing it exists to do, to
close a hole that is not a confidentiality boundary — see below.

**`.to_string()` is not an extraction.** It is a *copy*. The distinction matters
and it is the reason this hole is smaller than it looks:

|                        | `.to_string()` / `.to_owned()`   | `into_inner()`                        |
|------------------------|----------------------------------|---------------------------------------|
| What happens           | Copies into a new `String`       | Moves *this* `String` out (`mem::take`) |
| The wrapper afterwards | Still held, still wiped on drop  | Consumed                              |
| Copies of the secret   | Two, until the wrapper drops     | One, and it is yours                  |
| In an audit sweep      | Noisy — a `str` method           | A named exit                          |

Neither result is protected. The difference is that `.to_string()` leaves the
protected buffer in place and still wiped, while `into_inner` ends protection for
the only copy that existed. Removing `into_inner` because `.to_string()` exists
would therefore be a mistake in the opposite direction: one moves, the other
copies, and the crate should keep offering the one that does not duplicate.

The remaining sting is real but narrow: `.to_string()` is *quieter* than
`into_inner()`. It reads as a `str` method, not as a named exit. The answer is to
sweep `.to_string()` / `.to_owned()` alongside the encoding audit, not to make the
type inconvenient.

That sweep is not a grep for `to_string` — these are ordinary `str` methods, reached
through the `Deref` above and not through anything this crate defines, and a
project-wide search for them is almost all noise. That is exactly why they are not in
the token list under **Audit Surfaces** in `SECURITY.md`. It is also why the problem
is specific to this type: on `Fixed`/`Dynamic` there is no `Deref`, so the same copy
must be spelled `expose_secret().to_string()`, and that already trips a listed token. It is a second pass over
the call sites that list already finds: for every encoder hit, look at what happens
to the returned `EncodedSecret`. And judge the deref site rather than the method
name — `String::from(&*enc)`, `(&*enc).into()`, and `format!("{}", &*enc)` are the
same event under different spellings, which is another reason a token list would
have been the wrong instrument. `SECURITY.md` carries that instruction directly
beneath the token list, and separately classifies the result of `enc.to_string()` as
untracked plaintext under "Where accident-prevention ends".

## What did get a compile error instead

Deref is kept, but the accidents that are *not* interop were each closed:

| Accident                    | Closed by                        | Pinned in                                            |
|-----------------------------|----------------------------------|------------------------------------------------------|
| `println!("{}", encoded)`   | no `Display`                     | `tests/compile-fail/encoded_secret_no_display.rs`     |
| Re-encoding encoded text    | `EncodableBytes` bound           | `tests/compile-fail/encoded_secret_no_reencode.rs`, `..._all_formats.rs` |
| `a == b` on secret material | no `PartialEq` (variable-time)   | `tests/compile-fail/encoded_secret_no_eq.rs`          |
| Four doors onto one room    | `AsRef<str>`/`AsRef<[u8]>` removed | (`Deref` reached everything they did)               |

`Display` was worth blocking because a caller who learned from `{:?}` that the
type is log-safe would otherwise be surprised by `{}`. Re-encode was worth
blocking because `str: AsRef<[u8]>` makes double-encoding type-check silently.
Neither is interop; both are mistakes. `to_string` is neither — it is a request,
correctly spelled.

The `AsRef` row is a different kind of decision and should not be read as a hazard
being closed. Those impls reached nothing `Deref` does not, so removing them cost
no interop; for a type whose purpose is making extraction visible, four doors onto
the same room was three too many. That is the same instinct as this whole note —
keep one obvious door — applied in the direction that happened not to cost
anything.

## What not to change

- Do not drop `Deref` on `EncodedSecret` to silence `to_string`. `as_str()` would
  work, and would make the type clumsy for its actual job.
- Do not add `Deref` or `AsRef` to `Fixed`/`Dynamic`. The exception is for output,
  and does not generalise.
- Do not drop `EncodedSecret::into_inner` because `to_string` exists. One moves,
  the other copies.
- Do not reintroduce `InnerSecret<T>`. It applied this same deref-with-wiping
  shape to *extraction*, where it read as protection continuing after the exit —
  and it did not: `{:?}` on `&*inner` printed the secret, and getting a genuinely
  owned value meant a clone, because `zeroize` will not move out of
  `Zeroizing<T>`.

The split the crate is selling is: compiler-enforced while held, honest named exit
when taken. Encoding as a separate output wrapper with `Deref` is the one place
that posture correctly switches, because by then the copy has already been made at
the caller's request.
