//! SG001 -- a `FixedStorage` assertion contradicted by the type's own fields.
//!
//! #201 put a `FixedStorage` bound on `Fixed::new`, which turns
//! `Fixed<Vec<u8>>`, `Fixed<String>` and `Fixed<[Vec<u8>; 2]>` into `cargo
//! check` errors. The bound is deliberately an assertion rather than an
//! enforcement -- `src/traits/fixed_storage.rs` says so, and says exactly what
//! it costs:
//!
//! > A type with a `Vec` field that implements `FixedStorage` anyway will
//! > compile and will leak, which is measured and deliberate: the alternative
//! > is a closed set of blessed types, and that would break the one thing the
//! > `generic` arm of `fixed_newtype!` exists for.
//!
//! That trade is the right one -- a closed set would be worse. It leaves one
//! hole, it is the hole a reader can check by eye, and checking it by eye does
//! not scale past a few types. This is that check, mechanised.
//!
//! # The predicate is heap ownership, not resizability
//!
//! `fe64ef8` changed what the marker asserts. It originally asked for a fixed
//! capacity, which blessed `Box<[T]>` -- a boxed slice cannot grow. Measured, a
//! `Fixed<Box<[u8]>>` holding a 1024-byte secret and assigned through
//! `with_secret_mut(|slot| *slot = other)` released the original block with
//! 1024 of 1024 bytes intact. Replacing the whole value abandons the allocation
//! without any capacity change at all, and the wrapper wipes what it holds at
//! drop rather than what it used to hold.
//!
//! So this check asks [`Storage::owns_heap`], not whether capacity can change.
//! Asking the other question is how an earlier version of this pass reported
//! `struct K { buf: Box<[u8]> }` as honest while `Fixed::new` refused it.
//!
//! The severity is `error` because the impl is a claim about the type, the
//! fields are the evidence, and they disagree. Nothing about intent enters into
//! it: `Fixed<T>` is documented as having no reallocation surface, and an impl
//! like this is what makes that sentence false for one `T`.

use crate::index::Index;
use crate::report::{Finding, Kind, Severity};
use crate::storage::Storage;

pub const RULE: &str = "SG001";

pub fn check(index: &Index) -> Vec<Finding> {
    let mut findings = Vec::new();

    for site in &index.fixed_storage_impls {
        // A blanket impl asserts a conditional -- `[T; N]` is `FixedStorage`
        // *when* `T` is -- and the bound on `T` is what discharges it. That is
        // the crate's own pattern and there is nothing here to contradict.
        if site.generic {
            continue;
        }

        let found = index.resolver.classify_named(&site.type_name, &site.args);

        if let Some((path, ty)) = found.owns_heap() {
            // Naming which of the two it is matters to the fix: a resizable
            // buffer can be pre-sized inside a `Dynamic`; an unresizable heap
            // allocation is simply not a thing `Fixed` can hold at all.
            let how = if found.capacity_can_change() {
                "a resizable buffer"
            } else {
                "a heap allocation"
            };
            findings.push(
                Finding::new(
                    RULE,
                    Kind::Assertion,
                    Severity::Error,
                    &site.file,
                    site.line,
                    format!(
                        "`{}` implements FixedStorage, but owns {how} at `{path}: {ty}`",
                        site.type_name
                    ),
                )
                .with_note(
                    "FixedStorage asserts that the type owns no heap allocation. An allocation \
                     can be abandoned unwiped either by a reallocation or by replacing the whole \
                     value -- measured at 1024 of 1024 bytes for a `Box<[u8]>` assigned through \
                     `with_secret_mut`, which is why the marker stopped accepting boxed slices \
                     in fe64ef8. Use `Dynamic<T>` for a heap-backed secret, or \
                     `Dynamic<[u8; N]>` for a heap-only secret of fixed size",
                ),
            );
        } else if let Storage::Unknown { path, ty } = &found {
            findings.push(
                Finding::new(
                    RULE,
                    Kind::Assertion,
                    Severity::Unresolved,
                    &site.file,
                    site.line,
                    format!(
                        "`{}` implements FixedStorage; the type at `{path}: {ty}` is not defined \
                         in the scanned files, so the assertion was not checked",
                        site.type_name
                    ),
                )
                .with_note(
                    "the assertion may well be correct; this is a report that it was not \
                     checked, not that it failed. Scan the crate defining that type, or review \
                     the impl by hand",
                ),
            );
        }
    }

    findings
}
