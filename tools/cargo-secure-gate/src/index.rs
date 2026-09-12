//! A first pass that learns the crate's secure-gate vocabulary.
//!
//! Neither check can run off method names alone. `new_with` exists on both
//! wrappers, and on `Fixed` its closure receives a `&mut [u8; N]` that cannot
//! grow -- since #201, cannot even be a `Vec`. Flagging it would be noise. So
//! the pass first reads every declaration that names a wrapper:
//!
//! * `type Tok = Dynamic<Vec<u8>>;` -- the only alias form left after #201
//!   retired the four `*_alias!` macros, and easier to resolve than they were.
//! * `dynamic_newtype!(pub Tok, Vec<u8>, "...")` and the `fixed_newtype!` forms,
//!   including the `generic T` arm #201 added to `fixed_newtype!`.
//! * every local `struct` / `enum`, so a `FixedStorage` impl can be checked
//!   against real fields.
//!
//! What it cannot resolve, it records as unresolved rather than guessing.

use std::collections::HashMap;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::visit::Visit;

use crate::storage::{LocalTypes, render};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    /// Heap-backed, and so the one with a reallocation surface.
    Dynamic,
    /// Since #201 its inner type must be `FixedStorage`, so it has none.
    Fixed,
}

#[derive(Debug, Clone)]
pub struct WrapperType {
    pub wrapper: Wrapper,
    /// The inner type as written, for reporting.
    pub inner: String,
    /// How the name was introduced, for reporting.
    pub origin: &'static str,
}

#[derive(Debug, Clone)]
pub struct ImplSite {
    pub type_name: String,
    pub generic: bool,
    pub file: String,
    pub line: usize,
}

#[derive(Default)]
pub struct Index {
    /// Type name -> which wrapper it is. Covers aliases and newtype macros.
    pub wrappers: HashMap<String, WrapperType>,
    /// Struct / enum name -> (field name, field type).
    pub locals: LocalTypes,
    /// Every `impl FixedStorage for _`.
    pub fixed_storage_impls: Vec<ImplSite>,
}

impl Index {
    pub fn wrapper_of(&self, name: &str) -> Option<&WrapperType> {
        self.wrappers.get(name)
    }
}

pub struct Collector<'a> {
    pub index: &'a mut Index,
    pub file: String,
}

impl<'a> Collector<'a> {
    pub fn new(index: &'a mut Index, file: String) -> Self {
        Self { index, file }
    }
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if let Some((wrapper, inner)) = wrapper_from_type(&node.ty) {
            self.index.wrappers.insert(
                node.ident.to_string(),
                WrapperType {
                    wrapper,
                    inner,
                    origin: "type alias",
                },
            );
        }
        syn::visit::visit_item_type(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let fields = node
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let name = f
                    .ident
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| i.to_string());
                (name, f.ty.clone())
            })
            .collect();
        self.index.locals.insert(node.ident.to_string(), fields);
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        // Every variant's fields belong to the same type for this question:
        // any one of them can hold the resizable buffer.
        let mut fields = Vec::new();
        for variant in &node.variants {
            for (i, f) in variant.fields.iter().enumerate() {
                let name = f
                    .ident
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| i.to_string());
                fields.push((format!("{}::{name}", variant.ident), f.ty.clone()));
            }
        }
        self.index.locals.insert(node.ident.to_string(), fields);
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if let Some(seg) = fixed_storage_target(node) {
            self.index.fixed_storage_impls.push(ImplSite {
                type_name: seg.ident.to_string(),
                // A blanket impl (`impl<T: FixedStorage> FixedStorage for [T; N]`)
                // asserts a conditional claim this pass does not try to check.
                generic: !node.generics.params.is_empty(),
                file: self.file.clone(),
                line: line_of(&seg.ident),
            });
        }
        syn::visit::visit_item_impl(self, node);
    }

    /// Catches the newtype macros wherever they appear -- module scope, inside a
    /// function, inside another macro's expansion input. `visit_macro` sees all
    /// of those, which `visit_item_macro` alone would not.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let Some(seg) = node.path.segments.last() else {
            return;
        };
        let wrapper = match seg.ident.to_string().as_str() {
            "dynamic_newtype" => Wrapper::Dynamic,
            "fixed_newtype" => Wrapper::Fixed,
            _ => return,
        };
        if let Some((name, inner)) = parse_newtype(node.tokens.clone()) {
            self.index.wrappers.insert(
                name,
                WrapperType {
                    wrapper,
                    inner,
                    origin: "newtype macro",
                },
            );
        }
        syn::visit::visit_macro(self, node);
    }
}

/// The `Self` type of an `impl FixedStorage for _`, if that is what this is.
fn fixed_storage_target(node: &syn::ItemImpl) -> Option<&syn::PathSegment> {
    let (_, path, _) = node.trait_.as_ref()?;
    if path
        .segments
        .last()
        .is_none_or(|s| s.ident != "FixedStorage")
    {
        return None;
    }
    match &*node.self_ty {
        syn::Type::Path(p) => p.path.segments.last(),
        _ => None,
    }
}

/// Reads `Dynamic<Vec<u8>>` / `Fixed<[u8; 32]>` out of an alias's right-hand side.
fn wrapper_from_type(ty: &syn::Type) -> Option<(Wrapper, String)> {
    let syn::Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    let wrapper = match seg.ident.to_string().as_str() {
        "Dynamic" => Wrapper::Dynamic,
        "Fixed" => Wrapper::Fixed,
        _ => return None,
    };
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return Some((wrapper, String::new()));
    };
    let inner = args
        .args
        .iter()
        .find_map(|a| match a {
            syn::GenericArgument::Type(t) => Some(render(t)),
            _ => None,
        })
        .unwrap_or_default();
    Some((wrapper, inner))
}

/// Pulls the name and inner type out of a newtype macro invocation.
///
/// The grammar is fixed by `src/macros/`: attributes and a visibility, then the
/// name, then the inner spec -- `String`, `Vec<u8>`, a byte length for
/// `fixed_newtype!`, or `generic T` -- then an optional doc literal and an
/// optional `derive: [...]`.
fn parse_newtype(tokens: TokenStream) -> Option<(String, String)> {
    let groups = split_top_level_commas(tokens);
    let head = groups.first()?;

    // Attributes and `pub` / `pub(crate)` all precede the name, and none of them
    // ends in a bare identifier, so the last identifier in the group is it.
    let name = head
        .iter()
        .filter_map(|t| match t {
            TokenTree::Ident(id) => Some(id.to_string()),
            _ => None,
        })
        .next_back()?;
    if name == "pub" {
        return None;
    }

    let spec = groups.get(1)?;
    let mut inner: Vec<&TokenTree> = spec.iter().collect();
    if matches!(inner.first(), Some(TokenTree::Ident(id)) if *id == "generic") {
        inner.remove(0);
    }
    let rendered = inner
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    Some((name, render_str(&rendered)))
}

/// Splits a macro's tokens on commas that are not inside brackets or angles.
///
/// Angle brackets are not a delimiter in a token stream, so `BTreeMap<u8, u8>`
/// would otherwise split in the middle. Depth tracking on `<` and `>` keeps it
/// in one piece.
fn split_top_level_commas(tokens: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut groups = vec![Vec::new()];
    let mut angle = 0i32;
    for tt in tokens {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == '<' => {
                angle += 1;
                groups.last_mut().unwrap().push(tt);
            }
            TokenTree::Punct(p) if p.as_char() == '>' => {
                angle -= 1;
                groups.last_mut().unwrap().push(tt);
            }
            TokenTree::Punct(p) if p.as_char() == ',' && angle <= 0 => groups.push(Vec::new()),
            _ => groups.last_mut().unwrap().push(tt),
        }
    }
    groups.retain(|g| !g.is_empty());
    groups
}

/// True when a comma-group is the `derive: [...]` tail rather than a type.
pub fn is_derive_group(group: &[TokenTree]) -> bool {
    matches!(group.first(), Some(TokenTree::Ident(id)) if *id == "derive")
        && group
            .iter()
            .any(|t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Bracket))
}

fn render_str(s: &str) -> String {
    s.replace(" < ", "<")
        .replace(" > ", ">")
        .replace(" >", ">")
        .replace("< ", "<")
        .replace(" ;", ";")
        .replace(" ,", ",")
}

pub fn line_of<T: syn::spanned::Spanned>(t: &T) -> usize {
    t.span().start().line
}
