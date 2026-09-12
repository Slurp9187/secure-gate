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
//! The severity is `error` because the impl is a claim about the type, the
//! fields are the evidence, and they disagree. Nothing about intent enters into
//! it: `Fixed<T>` is documented as having no reallocation surface, and an impl
//! like this is what makes that sentence false for one `T`.

use crate::index::Index;
use crate::report::{Finding, Kind, Severity};
use crate::storage::{Storage, classify_named};

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

        match classify_named(&site.type_name, &index.locals) {
            Storage::Resizable { path, ty } => {
                findings.push(
                    Finding::new(
                        RULE,
                        Kind::Assertion,
                        Severity::Error,
                        &site.file,
                        site.line,
                        format!(
                            "`{}` implements FixedStorage, but owns a resizable buffer at `{}: {}`",
                            site.type_name, path, ty
                        ),
                    )
                    .with_note(
                        "FixedStorage asserts that no buffer the type owns can change capacity. \
                         Any capacity change abandons a buffer holding the secret, and \
                         `Fixed` has no `io::Write` growth path to wipe it -- \
                         SECURITY.md, \"Heap-reallocation residue\". Hold the resizable part in \
                         a `Dynamic` and pre-size it, or store it as `Box<[T]>`, whose length is \
                         fixed at construction",
                    ),
                );
            }
            Storage::Unknown { path, ty } => {
                findings.push(
                    Finding::new(
                        RULE,
                        Kind::Assertion,
                        Severity::Unresolved,
                        &site.file,
                        site.line,
                        format!(
                            "`{}` implements FixedStorage; the field at `{}: {}` is defined \
                             outside this crate and was not checked",
                            site.type_name, path, ty
                        ),
                    )
                    .with_note(
                        "the assertion may well be correct -- this pass cannot see the fields of \
                         a foreign type to confirm it",
                    ),
                );
            }
            Storage::Fixed => {}
        }
    }

    findings
}
