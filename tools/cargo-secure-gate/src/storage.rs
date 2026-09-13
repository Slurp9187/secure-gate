//! What a type owns, as far as the source says.
//!
//! This module answers **two** questions, because the two checks ask different
//! ones and an earlier version of this file conflated them:
//!
//! * *Does it own a heap allocation?* -- what `FixedStorage` asserts, and what
//!   [`checks::fixed_storage`](crate::checks::fixed_storage) verifies.
//! * *Can a buffer it owns change capacity?* -- the reallocation question, and
//!   the vocabulary `SECURITY.md` uses for the growth routes.
//!
//! They came apart in `fe64ef8`. `FixedStorage` originally asked for a fixed
//! capacity and so blessed `Box<[T]>`, on the reasoning that a boxed slice
//! cannot be resized. Measured, a `Fixed<Box<[u8]>>` holding a 1024-byte secret
//! and assigned through `with_secret_mut(|slot| *slot = other)` released the
//! original block with **1024 of 1024** bytes intact: whole-value replacement
//! abandons an allocation just as well as a reallocation does, and the wrapper
//! wipes what it holds at drop, not what it used to hold. `Fixed<[u8; 1024]>`
//! assigned the same way frees nothing, because there is no allocation to
//! abandon. So the crate's predicate is now heap ownership, and `Box<[T]>` is
//! refused at any payload.
//!
//! Keeping one predicate for both checks is what let this pass bless a shape
//! the compiler rejects, so the two are separate values here.
//!
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
    /// Owns no heap allocation at all: the secret lives inline, wherever the
    /// wrapper does. This is the only shape `FixedStorage` may be asserted for.
    Inline,
    /// Owns a heap buffer whose capacity can change -- `Vec`, `String`. Both
    /// questions answer yes.
    Resizable { path: String, ty: String },
    /// Owns a heap allocation that cannot be resized -- `Box<[T]>`. Capacity
    /// cannot change and the allocation can still be abandoned by replacing the
    /// whole value, which is the distinction `fe64ef8` was made of.
    HeapFixed { path: String, ty: String },
    /// Not resolvable here. Never reported as a violation, never as silence.
    Unknown { path: String, ty: String },
}

impl Storage {
    /// The `FixedStorage` predicate: does the type own a heap allocation?
    pub fn owns_heap(&self) -> Option<(&str, &str)> {
        match self {
            Storage::Resizable { path, ty } | Storage::HeapFixed { path, ty } => Some((path, ty)),
            Storage::Inline | Storage::Unknown { .. } => None,
        }
    }

    /// The reallocation predicate: can a buffer it owns change capacity?
    /// Distinct from [`Storage::owns_heap`] since `fe64ef8`, and the reason the
    /// two checks no longer share one answer.
    pub fn capacity_can_change(&self) -> bool {
        matches!(self, Storage::Resizable { .. })
    }
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
/// Mirrors the crate's own impl list at `9eabeec`. All twelve `NonZero`
/// integers are there deliberately: a consumer cannot add the impl itself
/// (E0117), so the crate carries them, and a classifier that knew only five
/// would put the other seven in the unresolved pile.
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
    "NonZeroU128",
    "NonZeroUsize",
    "NonZeroI8",
    "NonZeroI16",
    "NonZeroI32",
    "NonZeroI64",
    "NonZeroI128",
    "NonZeroIsize",
];

/// Heap allocations that cannot be resized. The crate implemented `FixedStorage`
/// for `Box<[T]>` and then removed it: a boxed slice cannot grow, and replacing
/// the whole value still abandons its allocation unwiped, measured at 1024 of
/// 1024 bytes. `Rc` and `Arc` own a heap allocation on the same reasoning.
///
/// `Box<[u8; N]>` is disqualified here too, which is correct under the crate's
/// predicate and cannot arise anyway: `zeroize` does not implement `Zeroize` for
/// a `Box` of a sized type, so `Fixed` never accepts one.
const HEAP_FIXED: &[&str] = &["Box", "Rc", "Arc"];

/// Single-payload wrappers that are genuinely inline: no allocation of their
/// own, so recurse into the first type argument. `Box` is deliberately NOT here.
const TRANSPARENT: &[&str] = &[
    "Option",
    "ManuallyDrop",
    "Wrapping",
    "Reverse",
    "Cell",
    "RefCell",
    "UnsafeCell",
    "MaybeUninit",
    // `Zeroizing<T>` is `T`'s own storage with a drop impl, and the crate
    // blesses it conditionally -- `Zeroizing<Vec<u8>>` is still refused, which
    // falls out of recursing into the payload.
    "Zeroizing",
    // `Fixed<T>` nests, so a `Fixed` inside a custom inner type is as inline as
    // its own payload.
    "Fixed",
];

/// A struct or enum defined in the scanned files.
#[derive(Debug, Clone, Default)]
pub struct TypeDef {
    /// Type-parameter names, in declaration order, for substitution.
    pub generics: Vec<String>,
    pub fields: Vec<(String, syn::Type)>,
}

/// One definition of a name, and the file it came from.
#[derive(Debug, Clone)]
pub struct Def<T> {
    pub file: String,
    pub item: T,
}

/// Everything the scanned files say about their own type names.
///
/// Keyed by name **and** file. An earlier version used one flat map keyed by
/// bare name, so the last definition scanned won: adding an unrelated file that
/// happened to reuse a type name silently erased every finding about the real
/// one, a reversed argument order brought them back, and a name reused with a
/// growable field manufactured a finding against a type that had no impl at all.
/// Two `Key`s in one crate is not exotic, so the flat map was a correctness bug
/// rather than a simplification.
#[derive(Debug, Default)]
pub struct Resolver {
    types: HashMap<String, Vec<Def<TypeDef>>>,
    aliases: HashMap<String, Vec<Def<syn::Type>>>,
}

/// What a name resolved to, and whether it resolved at all.
enum Lookup<'a, T> {
    One(&'a Def<T>),
    /// Defined differently in more than one scanned file, with no way here to
    /// tell which one a reference means. Reported, never guessed at.
    Ambiguous(Vec<String>),
    None,
}

impl Resolver {
    pub fn add_type(&mut self, file: &str, name: String, item: TypeDef) {
        self.types.entry(name).or_default().push(Def {
            file: file.to_string(),
            item,
        });
    }

    pub fn add_alias(&mut self, file: &str, name: String, item: syn::Type) {
        self.aliases.entry(name).or_default().push(Def {
            file: file.to_string(),
            item,
        });
    }

    /// Resolves a name as referenced from `from_file`.
    ///
    /// A definition in the same file wins, which is the closest this pass gets
    /// to Rust's own scoping. Failing that, a single definition anywhere is
    /// used, and so are several that agree. Genuine disagreement is ambiguous.
    fn look_up<'a, T: Renderable>(
        map: &'a HashMap<String, Vec<Def<T>>>,
        name: &str,
        from_file: &str,
    ) -> Lookup<'a, T> {
        let Some(defs) = map.get(name) else {
            return Lookup::None;
        };
        if let Some(local) = defs.iter().find(|d| d.file == from_file) {
            return Lookup::One(local);
        }
        match defs.len() {
            0 => Lookup::None,
            1 => Lookup::One(&defs[0]),
            _ => {
                let first = defs[0].item.render_key();
                if defs.iter().all(|d| d.item.render_key() == first) {
                    Lookup::One(&defs[0])
                } else {
                    Lookup::Ambiguous(defs.iter().map(|d| d.file.clone()).collect())
                }
            }
        }
    }
}

/// Lets two definitions of a name be compared for "do these actually differ".
trait Renderable {
    fn render_key(&self) -> String;
}

impl Renderable for TypeDef {
    fn render_key(&self) -> String {
        self.fields
            .iter()
            .map(|(n, t)| format!("{n}:{}", render(t)))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl Renderable for syn::Type {
    fn render_key(&self) -> String {
        render(self)
    }
}

/// Type parameters bound to concrete arguments at an impl site.
type Bindings = HashMap<String, syn::Type>;

impl Resolver {
    /// Classifies a named local type as referenced from `from_file`, with
    /// `args` supplying its type parameters if the impl site named any
    /// (`impl FixedStorage for Gen<Vec<u8>>`).
    pub fn classify_named(&self, name: &str, args: &[syn::Type], from_file: &str) -> Storage {
        let bindings = match Self::look_up(&self.types, name, from_file) {
            Lookup::One(def) => def
                .item
                .generics
                .iter()
                .cloned()
                .zip(args.iter().cloned())
                .collect(),
            _ => Bindings::new(),
        };
        let mut seen = HashSet::new();
        self.resolve_local(name, name.to_string(), from_file, &bindings, &mut seen)
    }

    fn walk(
        &self,
        ty: &syn::Type,
        path: String,
        from_file: &str,
        bindings: &Bindings,
        seen: &mut HashSet<String>,
    ) -> Storage {
        match ty {
            // An array never reallocates whatever its length, so it is exactly
            // as fixed as its element type -- the crate's own `[T; N]` reasoning.
            syn::Type::Array(a) => {
                self.walk(&a.elem, format!("{path}[_]"), from_file, bindings, seen)
            }
            syn::Type::Slice(s) => {
                self.walk(&s.elem, format!("{path}[_]"), from_file, bindings, seen)
            }
            syn::Type::Paren(p) => self.walk(&p.elem, path, from_file, bindings, seen),
            syn::Type::Group(g) => self.walk(&g.elem, path, from_file, bindings, seen),

            // Borrowing a `Vec` is not owning one. The contract is about owned
            // storage; a reference's capacity is someone else's problem.
            syn::Type::Reference(_)
            | syn::Type::Ptr(_)
            | syn::Type::BareFn(_)
            | syn::Type::Never(_) => Storage::Inline,

            syn::Type::Tuple(t) => {
                for (i, elem) in t.elems.iter().enumerate() {
                    let found = self.walk(elem, format!("{path}.{i}"), from_file, bindings, seen);
                    if !matches!(found, Storage::Inline) {
                        return found;
                    }
                }
                Storage::Inline
            }

            syn::Type::Path(p) => self.walk_path(p, path, from_file, bindings, seen),

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
        from_file: &str,
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
        if p.path.segments.len() == 1 {
            if let Some(bound) = bindings.get(&name) {
                let bound = bound.clone();
                return self.walk(&bound, path, from_file, &Bindings::new(), seen);
            }
        }

        if RESIZABLE.contains(&name.as_str()) {
            return Storage::Resizable {
                path,
                ty: render(p),
            };
        }
        if HEAP_FIXED.contains(&name.as_str()) {
            return Storage::HeapFixed {
                path,
                ty: render(p),
            };
        }
        if PRIMITIVE.contains(&name.as_str()) {
            return Storage::Inline;
        }
        if TRANSPARENT.contains(&name.as_str()) {
            return match first_type_arg(last) {
                Some(inner) => self.walk(inner, path, from_file, bindings, seen),
                None => Storage::Unknown {
                    path,
                    ty: render(p),
                },
            };
        }
        // A local `type Blob = Vec<u8>;` is one lookup away, and treating it as
        // foreign would put a resolvable answer in the unresolved pile.
        match Self::look_up(&self.aliases, &name, from_file) {
            Lookup::One(def) => {
                if seen.insert(format!("alias::{name}")) {
                    let target = def.item.clone();
                    return self.walk(&target, path, &def.file.clone(), bindings, seen);
                }
            }
            Lookup::Ambiguous(files) => {
                return Storage::Unknown {
                    path,
                    ty: format!("{name} (alias defined differently in {})", files.join(", ")),
                };
            }
            Lookup::None => {}
        }
        match Self::look_up(&self.types, &name, from_file) {
            Lookup::One(def) => {
                let args = type_args(last);
                let nested = def.item.generics.iter().cloned().zip(args).collect();
                let file = def.file.clone();
                return self.resolve_local(&name, path, &file, &nested, seen);
            }
            Lookup::Ambiguous(files) => {
                return Storage::Unknown {
                    path,
                    ty: format!("{name} (defined differently in {})", files.join(", ")),
                };
            }
            Lookup::None => {}
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
        from_file: &str,
        bindings: &Bindings,
        seen: &mut HashSet<String>,
    ) -> Storage {
        // A type that reaches itself is a cycle behind a pointer, and the
        // pointer was resolved on the way in, so stopping here loses nothing.
        if !seen.insert(name.to_string()) {
            return Storage::Inline;
        }
        let def = match Self::look_up(&self.types, name, from_file) {
            Lookup::One(def) => def,
            Lookup::Ambiguous(files) => {
                return Storage::Unknown {
                    path,
                    ty: format!("{name} (defined differently in {})", files.join(", ")),
                };
            }
            Lookup::None => {
                return Storage::Unknown {
                    path,
                    ty: name.to_string(),
                };
            }
        };

        let mut unknown = None;
        let mut heap = None;
        // Fields resolve in the file that declares them, not the file that
        // referenced the type -- otherwise a nested type would be looked up in
        // the wrong scope and re-open the collision this keying exists to close.
        let owner = def.file.clone();
        for (field, ty) in &def.item.fields {
            let child = if path.is_empty() {
                format!("{name}.{field}")
            } else {
                format!("{path}.{field}")
            };
            match self.walk(ty, child, &owner, bindings, seen) {
                // A heap-owning field answers both questions, so it wins
                // outright; `Resizable` is reported ahead of `HeapFixed`
                // because it is the stronger statement about the same field.
                Storage::Resizable { path, ty } => return Storage::Resizable { path, ty },
                Storage::HeapFixed { path, ty } => {
                    if heap.is_none() {
                        heap = Some(Storage::HeapFixed { path, ty });
                    }
                }
                // Keep looking: an owning field elsewhere in the same type is
                // the stronger answer and should win over an unresolved one.
                Storage::Unknown { path, ty } => {
                    if unknown.is_none() {
                        unknown = Some(Storage::Unknown { path, ty });
                    }
                }
                Storage::Inline => {}
            }
        }
        seen.remove(name);
        heap.or(unknown).unwrap_or(Storage::Inline)
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
