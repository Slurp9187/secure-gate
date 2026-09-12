//! Source-level audit checks for code that holds secrets in `secure-gate`.
//!
//! # Why a separate pass exists at all
//!
//! `secure-gate` moves everything it can into the type system, and #201 moved a
//! good deal more: `Fixed::new` now requires `FixedStorage`, so `Fixed<Vec<u8>>`
//! stopped compiling. What is left over is not an oversight, it is the residue
//! of two deliberate decisions, each documented where it was made:
//!
//! * `FixedStorage` is **an assertion, not an enforcement**. The alternative was
//!   a closed set of blessed inner types, which would have broken the `generic`
//!   arm that exists for holding an ML-KEM polynomial on a target with no
//!   allocator. So a wrong impl compiles. -> [`checks::fixed_storage`]
//! * `Dynamic::new_with` hands out an **empty** buffer, because the whole point
//!   is that the closure writes the secret into the allocation that will be
//!   protected. So a closure that fills it byte by byte abandons its own
//!   intermediates. -> [`checks::new_with`]
//!
//! Neither is a bug to be fixed upstream. Both are the kind of thing a reader
//! can check by eye on one type and cannot check by eye across a codebase.
//!
//! # What it does not claim
//!
//! Nothing here observes memory. The measurements this tool quotes come from
//! `tests/lifecycle_trace_heap.rs`, which installs a global allocator and counts
//! non-zero bytes in freed blocks; that is the instrument that can say whether a
//! buffer was abandoned. This pass reads source and recognises shapes that were
//! measured elsewhere. A clean run means no site matched a known shape -- see
//! [`report::Severity::Unresolved`] for the sites it could not read at all.

pub mod checks;
pub mod index;
pub mod report;
pub mod storage;

use std::path::{Path, PathBuf};

use index::{Collector, Index};
use report::Finding;
use syn::visit::Visit;

/// A parsed file, kept between the two passes.
struct Source {
    name: String,
    ast: syn::File,
}

/// Runs both checks over a set of already-read sources.
///
/// Two passes, because a `new_with` call can precede the declaration of the type
/// it is called on, and because declarations routinely live in another file.
pub fn analyze_sources(sources: &[(String, String)]) -> Result<Vec<Finding>, Error> {
    let mut parsed = Vec::new();
    for (name, text) in sources {
        let ast = syn::parse_file(text).map_err(|e| Error::Parse {
            file: name.clone(),
            message: e.to_string(),
        })?;
        parsed.push(Source {
            name: name.clone(),
            ast,
        });
    }

    let mut index = Index::default();
    for source in &parsed {
        let mut collector = Collector::new(&mut index, source.name.clone());
        collector.visit_file(&source.ast);
    }

    let mut findings = checks::fixed_storage::check(&index);
    for source in &parsed {
        findings.extend(checks::new_with::check(&index, &source.name, &source.ast));
    }

    findings.sort_by(|a, b| (&a.file, a.line, a.rule).cmp(&(&b.file, b.line, b.rule)));
    Ok(findings)
}

/// Reads every `.rs` file under `roots` and runs both checks over the set.
pub fn analyze_paths(roots: &[PathBuf]) -> Result<Vec<Finding>, Error> {
    let mut sources = Vec::new();
    for root in roots {
        for file in rust_files(root)? {
            let text = std::fs::read_to_string(&file).map_err(|e| Error::Io {
                file: file.display().to_string(),
                message: e.to_string(),
            })?;
            sources.push((file.display().to_string(), text));
        }
    }
    analyze_sources(&sources)
}

fn rust_files(root: &Path) -> Result<Vec<PathBuf>, Error> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root).into_iter().filter_entry(|e| {
        // `target/` is build output; scanning it finds generated copies of
        // the same code and reports each twice.
        e.file_name() != "target" && e.file_name() != ".git"
    }) {
        let entry = entry.map_err(|e| Error::Io {
            file: root.display().to_string(),
            message: e.to_string(),
        })?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|e| e == "rs") {
            out.push(entry.into_path());
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Debug)]
pub enum Error {
    Parse { file: String, message: String },
    Io { file: String, message: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse { file, message } => write!(f, "{file}: could not parse: {message}"),
            Error::Io { file, message } => write!(f, "{file}: {message}"),
        }
    }
}

impl std::error::Error for Error {}
