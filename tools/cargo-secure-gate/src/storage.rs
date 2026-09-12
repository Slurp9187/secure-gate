//! Answering one question about a type: can any buffer it owns change capacity?
//!
//! This is the question `FixedStorage` asks an implementor to answer by hand.
//! `src/traits/fixed_storage.rs` states the contract and then states its limit:
//! "the compiler checks that you wrote the impl, not that the claim is true. A
//! type with a `Vec` field that implements `FixedStorage` anyway will compile
//! and will leak." This module is the second opinion.
//!
//! # Three values, and why the third one is load-bearing
//!
//! A pass that cannot see through a type has not proved it safe. Reporting that
//! as silence is the one output a security auditor must never produce, so
//! [`Storage::Unknown`] is a result and not an absence.
//!
//! The corollary is that `Unknown` must be rare enough to read. Two shapes that
//! look unresolvable are not: a local `type Blob = Vec<u8>;` is one lookup away,
//! and `impl FixedStorage for Gen<Vec<u8>>` supplies the very argument its
//! struct is generic over. Both resolve here, so what is left in `Unknown` is
//! genuinely foreign.

use std::collections::{HashMap, HashSet};

use quote::ToTokens;

/// What a type owns, as far as this pass can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Storage {
    /// Owns no buffer whose capacity can change.
    Fixed,
    /// Owns a resizable buffer. Carries the field path that reaches it, so a
    /// finding can name `Outer.inner.scratch: String` rather than just `Outer`.
    Resizable { path: String, ty: String },
    /// Not resolvable here. Never reported as a violation, never as silence.
    Unknown { path: String, ty: String },
}

/// Standard-library containers that reallocate. `SECURITY.md` frames the
/// property as *capacity-changing* rather than growing, which is what puts
/// `shrink_to_fit` and a bare `reserve` alongside `push`; at the type level the
/// same framing just means "owns a resizable buffer".
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

/// A struct or enum defined in the scanned files.
#[derive(Debug, Clone, Default)]
pub struct TypeDef {
    /// Type-parameter names, in declaration order, for substitution.
    pub generics: Vec<String>,
    pub fields: Vec<(String, syn::Type)>,
}

/// Everything the scanned files say about their own type names.
#[derive(Debug, Default)]
pub struct Resolver {
    pub types: HashMap<String, TypeDef>,
    /// Every `type X = ...;`, so a local alias is not mistaken for a foreign type.
    pub aliases: HashMap<String, syn::Type>,
}

/// Type parameters bound to concrete arguments at an impl site.
type Bindings = HashMap<String, syn::Type>;

impl Resolver {
    /// Classifies a named local type, with `args` supplying its type parameters
    /// if the impl site named any (`impl FixedStorage for Gen<Vec<u8>>`).
    pub fn classify_named(&self, name: &str, args: &[syn::Type]) -> Storage {
        let bindings = match self.types.get(name) {
            Some(def) => def
                .generics
                .iter()
                .cloned()
                .zip(args.iter().cloned())
                .collect(),
            None => Bindings::new(),
        };
        let mut seen = HashSet::new();
        self.resolve_local(name, name.to_string(), &bindings, &mut seen)
    }

    fn walk(
        &self,
        ty: &syn::Type,
        path: String,
        bindings: &Bindings,
        seen: &mut HashSet<String>,
    ) -> Storage {
        match ty {
            // An array never reallocates whatever its length, so it is exactly
            // as fixed as its element type -- the crate's own `[T; N]` reasoning.
            syn::Type::Array(a) => self.walk(&a.elem, format!("{path}[_]"), bindings, seen),
            syn::Type::Slice(s) => self.walk(&s.elem, format!("{path}[_]"), bindings, seen),
            syn::Type::Paren(p) => self.walk(&p.elem, path, bindings, seen),
            syn::Type::Group(g) => self.walk(&g.elem, path, bindings, seen),

            // Borrowing a `Vec` is not owning one. The contract is about owned
            // storage; a reference's capacity is someone else's problem.
            syn::Type::Reference(_)
            | syn::Type::Ptr(_)
            | syn::Type::BareFn(_)
            | syn::Type::Never(_) => Storage::Fixed,

            syn::Type::Tuple(t) => {
                for (i, elem) in t.elems.iter().enumerate() {
                    let found = self.walk(elem, format!("{path}.{i}"), bindings, seen);
                    if !matches!(found, Storage::Fixed) {
                        return found;
                    }
                }
                Storage::Fixed
            }

            syn::Type::Path(p) => self.walk_path(p, path, bindings, seen),

            other => Storage::Unknown {
                path,
                ty: render(other),
            },
        }
    }

    fn walk_path(
        &self,
        p: &syn::TypePath,
        path: String,
        bindings: &Bindings,
        seen: &mut HashSet<String>,
    ) -> Storage {
        let Some(last) = p.path.segments.last() else {
            return Storage::Unknown {
                path,
                ty: render(p),
            };
        };
        let name = last.ident.to_string();

        // A type parameter the impl site bound to something concrete.
        if let Some(bound) = bindings.get(&name) {
            if p.path.segments.len() == 1 {
                let bound = bound.clone();
                return self.walk(&bound, path, &Bindings::new(), seen);
            }
        }

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
                Some(inner) => self.walk(inner, path, bindings, seen),
                None => Storage::Unknown {
                    path,
                    ty: render(p),
                },
            };
        }
        // A local `type Blob = Vec<u8>;` is one lookup away, and treating it as
        // foreign would put a resolvable answer in the unresolved pile.
        if let Some(target) = self.aliases.get(&name) {
            if seen.insert(format!("alias::{name}")) {
                let target = target.clone();
                return self.walk(&target, path, bindings, seen);
            }
        }
        if self.types.contains_key(&name) {
            let args = type_args(last);
            let nested = match self.types.get(&name) {
                Some(def) => def.generics.iter().cloned().zip(args).collect(),
                None => Bindings::new(),
            };
            return self.resolve_local(&name, path, &nested, seen);
        }

        Storage::Unknown {
            path,
            ty: render(p),
        }
    }

    fn resolve_local(
        &self,
        name: &str,
        path: String,
        bindings: &Bindings,
        seen: &mut HashSet<String>,
    ) -> Storage {
        // A type that reaches itself is a cycle behind a pointer, and the
        // pointer was resolved on the way in, so stopping here loses nothing.
        if !seen.insert(name.to_string()) {
            return Storage::Fixed;
        }
        let Some(def) = self.types.get(name) else {
            return Storage::Unknown {
                path,
                ty: name.to_string(),
            };
        };

        let mut unknown = None;
        for (field, ty) in &def.fields {
            let child = if path.is_empty() {
                format!("{name}.{field}")
            } else {
                format!("{path}.{field}")
            };
            match self.walk(ty, child, bindings, seen) {
                Storage::Resizable { path, ty } => return Storage::Resizable { path, ty },
                // Keep looking: a resizable field elsewhere in the same type is
                // the stronger answer and should win over an unresolved one.
                Storage::Unknown { path, ty } => {
                    if unknown.is_none() {
                        unknown = Some(Storage::Unknown { path, ty });
                    }
                }
                Storage::Fixed => {}
            }
        }
        seen.remove(name);
        unknown.unwrap_or(Storage::Fixed)
    }
}

fn first_type_arg(seg: &syn::PathSegment) -> Option<&syn::Type> {
    type_args_ref(seg).into_iter().next()
}

fn type_args(seg: &syn::PathSegment) -> Vec<syn::Type> {
    type_args_ref(seg).into_iter().cloned().collect()
}

fn type_args_ref(seg: &syn::PathSegment) -> Vec<&syn::Type> {
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return Vec::new();
    };
    args.args
        .iter()
        .filter_map(|a| match a {
            syn::GenericArgument::Type(t) => Some(t),
            _ => None,
        })
        .collect()
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
