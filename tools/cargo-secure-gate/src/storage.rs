//! Answering one question about a type: can any buffer it owns change capacity?
//!
//! This is the question `FixedStorage` asks an implementor to answer by hand.
//! `src/traits/fixed_storage.rs` states the contract and then states its limit:
//! "the compiler checks that you wrote the impl, not that the claim is true. A
//! type with a `Vec` field that implements `FixedStorage` anyway will compile
//! and will leak." This module is the second opinion.
//!
//! The answer is three-valued on purpose. A pass that cannot see through a
//! foreign type has not proved the type safe, and saying so is the difference
//! between a finding and a silence that reads like one.

use std::collections::{HashMap, HashSet};

use quote::ToTokens;

/// What a type owns, as far as this pass can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Storage {
    /// Owns no buffer whose capacity can change.
    Fixed,
    /// Owns a resizable buffer. Carries the field path that reaches it, so a
    /// finding can name `Poly.inner.buf: Vec<u8>` rather than just `Poly`.
    Resizable { path: String, ty: String },
    /// Not resolvable here: a foreign type, a generic parameter, or a shape
    /// this pass does not model. Never reported as a violation.
    Unknown { path: String, ty: String },
}

impl Storage {
    pub fn is_resizable(&self) -> bool {
        matches!(self, Storage::Resizable { .. })
    }
}

/// Standard-library containers that reallocate. `SECURITY.md` frames the
/// property as *capacity-changing* rather than growing, which is what makes
/// `shrink_to_fit` and a bare `reserve` belong on the same list as `push`;
/// at the type level the same framing just means "owns a resizable buffer".
const RESIZABLE: &[&str] = &[
    "Vec",
    "VecDeque",
    "String",
    "HashMap",
    "HashSet",
    "BTreeMap",
    "BTreeSet",
    "BinaryHeap",
    "LinkedList",
    "PathBuf",
    "OsString",
];

/// Types that own nothing resizable and need no further resolution.
const PRIMITIVE: &[&str] = &[
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "f32",
    "f64",
    "bool",
    "char",
    "str",
    "NonZeroU8",
    "NonZeroU16",
    "NonZeroU32",
    "NonZeroU64",
    "NonZeroUsize",
];

/// Single-payload wrappers: transparent for this question, so recurse into the
/// first type argument. `Box<[T]>` lands here and resolves to its slice, which
/// is why a boxed slice comes back `Fixed` exactly as the crate's own impl says.
const TRANSPARENT: &[&str] = &[
    "Option",
    "Box",
    "ManuallyDrop",
    "Wrapping",
    "Reverse",
    "Cell",
    "RefCell",
    "UnsafeCell",
    "MaybeUninit",
];

/// Field lists for the structs and enums defined in the scanned crate.
pub type LocalTypes = HashMap<String, Vec<(String, syn::Type)>>;

/// Classifies `ty`, resolving local types through `locals`.
pub fn classify(ty: &syn::Type, locals: &LocalTypes) -> Storage {
    let mut seen = HashSet::new();
    walk(ty, locals, String::new(), &mut seen)
}

/// Classifies a named local type by its fields.
pub fn classify_named(name: &str, locals: &LocalTypes) -> Storage {
    let mut seen = HashSet::new();
    resolve_local(name, locals, name.to_string(), &mut seen)
}

fn walk(ty: &syn::Type, locals: &LocalTypes, path: String, seen: &mut HashSet<String>) -> Storage {
    match ty {
        // An array never reallocates whatever its length, so it is exactly as
        // fixed as its element type -- the crate's own `[T; N]` impl reasoning.
        syn::Type::Array(a) => walk(&a.elem, locals, format!("{path}[_]"), seen),
        syn::Type::Slice(s) => walk(&s.elem, locals, format!("{path}[_]"), seen),
        syn::Type::Paren(p) => walk(&p.elem, locals, path, seen),
        syn::Type::Group(g) => walk(&g.elem, locals, path, seen),

        // Borrowing a `Vec` is not owning one. The contract is about owned
        // storage, and a reference's capacity is someone else's problem.
        syn::Type::Reference(_)
        | syn::Type::Ptr(_)
        | syn::Type::BareFn(_)
        | syn::Type::Never(_) => Storage::Fixed,

        syn::Type::Tuple(t) => {
            for (i, elem) in t.elems.iter().enumerate() {
                let found = walk(elem, locals, format!("{path}.{i}"), seen);
                if !matches!(found, Storage::Fixed) {
                    return found;
                }
            }
            Storage::Fixed
        }

        syn::Type::Path(p) => walk_path(p, locals, path, seen),

        // `impl Trait`, `dyn Trait`, inferred and macro types: not resolvable.
        other => Storage::Unknown {
            path,
            ty: render(other),
        },
    }
}

fn walk_path(
    p: &syn::TypePath,
    locals: &LocalTypes,
    path: String,
    seen: &mut HashSet<String>,
) -> Storage {
    let Some(last) = p.path.segments.last() else {
        return Storage::Unknown {
            path,
            ty: render(p),
        };
    };
    let name = last.ident.to_string();

    if RESIZABLE.contains(&name.as_str()) {
        return Storage::Resizable {
            path,
            ty: render(p),
        };
    }
    if PRIMITIVE.contains(&name.as_str()) {
        return Storage::Fixed;
    }
    if TRANSPARENT.contains(&name.as_str()) {
        return match first_type_arg(last) {
            Some(inner) => walk(inner, locals, path, seen),
            // `Box` with no type argument is not a shape we can read.
            None => Storage::Unknown {
                path,
                ty: render(p),
            },
        };
    }
    if locals.contains_key(&name) {
        return resolve_local(&name, locals, path, seen);
    }

    // A single-uppercase-letter path with no arguments is almost always a
    // generic parameter. Naming it as such reads better in a report than
    // repeating the whole type expression.
    Storage::Unknown {
        path,
        ty: render(p),
    }
}

fn resolve_local(
    name: &str,
    locals: &LocalTypes,
    path: String,
    seen: &mut HashSet<String>,
) -> Storage {
    // A type that reaches itself is a cycle behind a pointer; the pointer was
    // already resolved on the way in, so stopping here loses nothing.
    if !seen.insert(name.to_string()) {
        return Storage::Fixed;
    }
    let Some(fields) = locals.get(name) else {
        return Storage::Unknown {
            path,
            ty: name.to_string(),
        };
    };

    let mut unknown = None;
    for (field, ty) in fields {
        let child = if path.is_empty() {
            format!("{name}.{field}")
        } else {
            format!("{path}.{field}")
        };
        match walk(ty, locals, child, seen) {
            Storage::Resizable { path, ty } => return Storage::Resizable { path, ty },
            // Keep looking: a resizable field elsewhere in the same type is the
            // stronger answer and should win over an unresolved one.
            Storage::Unknown { path, ty } => unknown.get_or_insert(Storage::Unknown { path, ty }),
            Storage::Fixed => continue,
        };
    }
    seen.remove(name);
    unknown.unwrap_or(Storage::Fixed)
}

fn first_type_arg(seg: &syn::PathSegment) -> Option<&syn::Type> {
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    args.args.iter().find_map(|a| match a {
        syn::GenericArgument::Type(t) => Some(t),
        _ => None,
    })
}

pub fn render<T: ToTokens>(t: &T) -> String {
    let s = t.to_token_stream().to_string();
    // `Vec < u8 >` is how a token stream prints; nobody writes it that way.
    s.replace(" < ", "<")
        .replace(" > ", ">")
        .replace(" >", ">")
        .replace(" ,", ",")
        .replace("< ", "<")
        .replace(" ::", "::")
        .replace(":: ", "::")
        .replace(" ;", ";")
}
