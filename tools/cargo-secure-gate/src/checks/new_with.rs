//! SG002 -- a `Dynamic::new_with` closure that fills an unsized buffer.
//!
//! `new_with` is the constructor `SECURITY.md` recommends precisely because the
//! secret is written once, into the buffer that will be protected. #201 adds the
//! measurement that makes the recommendation conditional:
//!
//! > `new_with` starts the closure with an empty `Vec`, so a closure that fills
//! > it byte by byte reallocates its way up and abandons its own intermediate
//! > buffers: measured at 1016 secret bytes across 7 abandoned blocks for a
//! > 1008-byte secret. Call `v.reserve_exact(len)` first, or build the value and
//! > use `Dynamic::new`, both of which measured 0.
//!
//! Seven abandoned buffers, from the constructor the documentation points at,
//! before the wrapper has finished being built. The fix is one line and the
//! difference between 1016 and 0 is the whole of it, which is what makes this
//! worth a lint rather than a paragraph.
//!
//! # Two ways to get this check wrong
//!
//! Both are avoided here, and both would have looked reasonable:
//!
//! * **Keying on growth.** `SECURITY.md` is explicit that the property is
//!   *capacity-changing*, not growing: `shrink_to_fit` abandons a buffer while
//!   the buffer only ever got smaller, and "a check keyed on 'bytes added' would
//!   miss it". That framing governs the mutation-site check; inside `new_with`
//!   the buffer starts empty, so growth is the only way its capacity changes,
//!   and a shrink of an empty buffer abandons nothing. The narrower vocabulary
//!   here is a consequence of the scope, not a disagreement with the document.
//! * **Treating `reserve` as a hazard everywhere.** It is one -- on a buffer
//!   that already holds a secret, `reserve` abandons it while writing no payload
//!   at all. On the empty buffer `new_with` hands over, the same call is the
//!   recommended fix. The op's meaning depends on what the buffer already holds,
//!   so a single shared list of "capacity-changing calls" would flag the
//!   mitigation as the weakness.
//!
//! # What it does not see
//!
//! A closure that hands its `&mut Vec<u8>` to a helper function. The growth then
//! happens in a body this pass never connects to this buffer. Those sites are
//! reported as unresolved rather than passed.

use syn::visit::Visit;

use crate::index::{Index, Wrapper, line_of};
use crate::report::{Finding, Severity};

pub const RULE: &str = "SG002";

/// Calls that give the buffer its capacity up front. Inside `new_with` these are
/// the fix, not the hazard -- see the module docs.
const PRESIZE: &[&str] = &[
    "reserve",
    "reserve_exact",
    "try_reserve",
    "try_reserve_exact",
];

/// Calls that add a known quantity, reserving once for it. On the empty buffer
/// `new_with` hands over, one of these allocates a buffer and abandons nothing --
/// there is no earlier buffer to abandon. Two of them in sequence is a different
/// matter, and so is one inside a loop.
const BULK: &[&str] = &[
    "push",
    "push_str",
    "extend_from_slice",
    "extend_from_within",
    "insert",
    "insert_str",
    "append",
    "resize",
];

/// Calls driven by an iterator, which reserve against a size hint this pass
/// cannot see. `repeat_n` reserves once; a filter chain reallocates its way up.
const INCREMENTAL: &[&str] = &["extend", "splice"];

/// Calls that hand the buffer to something this pass cannot follow.
const ESCAPE: &[&str] = &["as_mut", "as_mut_slice", "as_mut_vec", "by_ref"];

pub fn check(index: &Index, file: &str, ast: &syn::File) -> Vec<Finding> {
    let mut visitor = SiteVisitor {
        index,
        file,
        findings: Vec::new(),
        self_ty: None,
    };
    visitor.visit_file(ast);
    visitor.findings
}

struct SiteVisitor<'a> {
    index: &'a Index,
    file: &'a str,
    findings: Vec<Finding>,
    /// The name `Self` refers to at this point in the traversal.
    self_ty: Option<String>,
}

impl<'ast> Visit<'ast> for SiteVisitor<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(site) = self.classify_call(node) {
            self.findings.extend(site);
        }
        syn::visit::visit_expr_call(self, node);
    }

    /// `Self::new_with` is how a constructor calls its sibling, and it is the
    /// commonest receiver inside the library itself. Without this the whole of
    /// `src/fixed.rs` reports as unresolved, which is a report nobody reads.
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.self_ty.take();
        self.self_ty = match &*node.self_ty {
            syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        };
        syn::visit::visit_item_impl(self, node);
        self.self_ty = previous;
    }
}

impl SiteVisitor<'_> {
    fn classify_call(&self, node: &syn::ExprCall) -> Option<Vec<Finding>> {
        let syn::Expr::Path(path) = &*node.func else {
            return None;
        };
        let segments = &path.path.segments;
        if segments.len() < 2 || segments.last()?.ident != "new_with" {
            return None;
        }
        let mut receiver = segments[segments.len() - 2].ident.to_string();
        if receiver == "Self" {
            match &self.self_ty {
                Some(name) => receiver = name.clone(),
                // A `Self` outside any impl block is not something to guess at.
                None => return None,
            }
        }
        let line = line_of(&segments.last()?.ident);

        // `Fixed::new_with` hands the closure a `&mut [u8; N]`. It cannot change
        // capacity, and since #201's `FixedStorage` bound it cannot even be a
        // `Vec`, so there is nothing here to find.
        let kind = match receiver.as_str() {
            "Dynamic" => Wrapper::Dynamic,
            "Fixed" => return Some(Vec::new()),
            other => match self.index.wrapper_of(other) {
                Some(w) => w.wrapper,
                None => {
                    return Some(vec![
                        Finding::new(
                            RULE,
                            Severity::Unresolved,
                            self.file,
                            line,
                            format!(
                                "`{other}::new_with` -- `{other}` is not declared in the scanned \
                                 files, so this pass cannot tell a Dynamic buffer from a Fixed one"
                            ),
                        )
                        .with_note("scan the crate that declares it, or check this site by hand"),
                    ]);
                }
            },
        };
        if kind == Wrapper::Fixed {
            return Some(Vec::new());
        }

        let Some(syn::Expr::Closure(closure)) = node.args.first() else {
            return Some(vec![
                Finding::new(
                    RULE,
                    Severity::Unresolved,
                    self.file,
                    line,
                    format!("`{receiver}::new_with` is not called with a closure literal here"),
                )
                .with_note("the buffer is filled somewhere this pass cannot follow"),
            ]);
        };
        let target = closure_param(closure)?;

        let mut scan = ClosureScan {
            target: &target,
            presized: false,
            growth: Vec::new(),
            escaped: None,
            loop_depth: 0,
        };
        scan.visit_expr(&closure.body);

        if let Some(escape) = scan.escaped.as_deref().filter(|_| !scan.presized) {
            return Some(vec![
                Finding::new(
                    RULE,
                    Severity::Unresolved,
                    self.file,
                    line,
                    format!(
                        "`{receiver}::new_with` passes `{target}` to `{escape}` before sizing it; \
                         any growth there was not checked"
                    ),
                )
                .with_note(
                    "pre-size with `reserve_exact` in the closure and the question does not arise",
                ),
            ]);
        }

        let (growth, severity) = scan.verdict()?;

        let message = if severity == Severity::Error {
            format!(
                "`{receiver}::new_with` grows `{target}` repeatedly without sizing it (`{}`); the \
                 closure starts with an empty buffer, so every reallocation after the first \
                 abandons one holding the secret",
                growth.method
            )
        } else {
            format!(
                "`{receiver}::new_with` fills `{target}` with `{}` without sizing it; whether that \
                 reallocates depends on the iterator's size hint, which this pass cannot see",
                growth.method
            )
        };

        Some(vec![
            Finding::new(RULE, severity, self.file, growth.line, message).with_note(format!(
                "add `{target}.reserve_exact(len)` as the first statement, or build the value and \
                 use `{receiver}::new`. Measured: 1016 secret bytes across 7 abandoned blocks for \
                 a 1008-byte secret, against 0 for either fix -- SECURITY.md, \"Heap-reallocation \
                 residue\""
            )),
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// One reservation for a known quantity.
    Bulk,
    /// Iterator-driven: one call, an unknown number of reallocations.
    Incremental,
}

struct Growth {
    method: String,
    line: usize,
    shape: Shape,
    /// Inside a `for` / `while` / `loop`, so it runs an unknown number of times.
    repeated: bool,
}

/// Walks the closure body in source order, so a `reserve_exact` counts only when
/// it actually precedes the growth it is meant to cover.
struct ClosureScan<'a> {
    target: &'a str,
    presized: bool,
    growth: Vec<Growth>,
    escaped: Option<String>,
    loop_depth: usize,
}

impl ClosureScan<'_> {
    fn record(&mut self, method: String, line: usize, shape: Shape) {
        let repeated = self.loop_depth > 0;
        self.growth.push(Growth {
            method,
            line,
            shape,
            repeated,
        });
    }

    /// The verdict, and why.
    ///
    /// A single bulk fill of an empty buffer allocates once and abandons
    /// nothing, which is what the crate's own `dynamic_vec_new_with_fills_correctly`
    /// does; calling that a leak would be wrong and would cost the tool its
    /// welcome. What `SECURITY.md` measured at 1016 bytes across 7 blocks is a
    /// closure that "fills it byte by byte" -- growth that repeats.
    fn verdict(&self) -> Option<(&Growth, Severity)> {
        if self.presized {
            return None;
        }
        if let Some(g) = self.growth.iter().find(|g| g.repeated) {
            return Some((g, Severity::Error));
        }
        if self.growth.len() > 1 {
            return Some((&self.growth[1], Severity::Error));
        }
        match self.growth.first() {
            Some(g) if g.shape == Shape::Incremental => Some((g, Severity::Warning)),
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for ClosureScan<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if base_ident(&node.receiver).as_deref() == Some(self.target) {
            let method = node.method.to_string();
            let line = line_of(&node.method);
            if PRESIZE.contains(&method.as_str()) {
                self.presized = true;
            } else if BULK.contains(&method.as_str()) {
                self.record(method, line, Shape::Bulk);
            } else if INCREMENTAL.contains(&method.as_str()) {
                self.record(method, line, Shape::Incremental);
            } else if ESCAPE.contains(&method.as_str()) && self.escaped.is_none() {
                self.escaped = Some(method);
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    /// `*v = Vec::with_capacity(n)` and `*v = already_built` both replace the
    /// empty buffer wholesale rather than growing it, which abandons nothing.
    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if base_ident(&node.left).as_deref() == Some(self.target) {
            self.presized = true;
        }
        syn::visit::visit_expr_assign(self, node);
    }

    /// `*s += "..."` is `push_str` spelled as an operator.
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::AddAssign(_))
            && base_ident(&node.left).as_deref() == Some(self.target)
        {
            let line = line_of(&node.left);
            self.record("+=".to_string(), line, Shape::Bulk);
        }
        syn::visit::visit_expr_binary(self, node);
    }

    /// `write!(v, ...)` grows a `Vec<u8>` through `io::Write`, and `writeln!`
    /// into a `String` through `fmt::Write`. Both reallocate the same way.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let is_write = node
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "write" || s.ident == "writeln");
        if is_write {
            if let Some(proc_macro2::TokenTree::Ident(id)) = node.tokens.clone().into_iter().next()
            {
                if id == self.target {
                    let line = id.span().start().line;
                    self.record("write!".to_string(), line, Shape::Bulk);
                }
            }
        }
        syn::visit::visit_macro(self, node);
    }

    /// A growth call that runs once is not the shape that was measured; the same
    /// call in a loop is exactly it -- "fills it byte by byte", seven buffers
    /// deep. These three overrides are what tells the two apart.
    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.loop_depth += 1;
        syn::visit::visit_expr_for_loop(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.loop_depth += 1;
        syn::visit::visit_expr_while(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.loop_depth += 1;
        syn::visit::visit_expr_loop(self, node);
        self.loop_depth -= 1;
    }

    /// A helper call that takes the buffer is growth this pass cannot see.
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        for arg in &node.args {
            if base_ident(arg).as_deref() == Some(self.target) && self.escaped.is_none() {
                self.escaped = Some(crate::storage::render(&*node.func));
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn closure_param(closure: &syn::ExprClosure) -> Option<String> {
    let pat = closure.inputs.first()?;
    pat_ident(pat)
}

fn pat_ident(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(id) => Some(id.ident.to_string()),
        syn::Pat::Type(t) => pat_ident(&t.pat),
        _ => None,
    }
}

/// The binding an expression ultimately names, looking through the borrows and
/// derefs that a `&mut` buffer collects at a call site.
fn base_ident(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => base_ident(&u.expr),
        syn::Expr::Reference(r) => base_ident(&r.expr),
        syn::Expr::Paren(p) => base_ident(&p.expr),
        syn::Expr::Group(g) => base_ident(&g.expr),
        _ => None,
    }
}
