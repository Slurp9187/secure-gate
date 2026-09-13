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
//! # Naming the buffer
//!
//! An independent adversarial pass found field access to be the shape most
//! often missed, and it is the most idiomatic one in the language: for a
//! `Dynamic<Session>`, the growth is `s.token.push(b)` and the buffer is never
//! named on its own. So the scan tracks *access paths* rather than bindings --
//! `s`, `s.token`, `alias` after a `let` -- which also keeps `s.token.reserve_exact`
//! from excusing a growth of `s.other`.
//!
//! # What it does not see
//!
//! A closure that hands its `&mut Vec<u8>` to a helper function. The growth then
//! happens in a body this pass never connects to this buffer. Those sites are
//! reported as unresolved rather than passed.

use std::collections::{HashMap, HashSet};

use syn::visit::Visit;

use crate::index::{Index, Wrapper, line_of};
use crate::report::{Finding, Kind, Severity};

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
    // Whole-value replacement of an already-filled buffer, and a one-shot fill
    // of an empty one. Measured as a 1008/1008 leak at a mutation site.
    "clone_from",
    // `io::Write` on a `&mut Vec<u8>`, and the `bytes::BufMut` family. Naming
    // them is worth doing and is not a fix for the underlying problem: the
    // vocabulary is closed, and UNKNOWN_OP below is what covers the rest.
    "write_all",
    "put",
    "put_slice",
    "put_u8",
];

/// Calls that read the buffer without touching its allocation. Anything on the
/// buffer that is in none of these lists is reported as unresolved rather than
/// ignored -- an author naming their own extension method is otherwise a hole
/// straight through a closed vocabulary, and silence is the wrong answer to
/// "I do not know what this call does".
const READS: &[&str] = &[
    "len",
    "is_empty",
    "capacity",
    "iter",
    "iter_mut",
    "as_slice",
    "as_str",
    "as_ptr",
    "as_bytes",
    "first",
    "last",
    "get",
    "get_mut",
    "contains",
    "starts_with",
    "ends_with",
    "chars",
    "bytes",
    "to_vec",
    "clone",
    "sort",
    "sort_unstable",
    "reverse",
    "fill",
    "copy_from_slice",
    "clone_from_slice",
    "swap",
    // Shrink the length, never the allocation, so nothing is abandoned.
    "truncate",
    "clear",
    "pop",
    "remove",
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
                            Kind::Route,
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
                    Kind::Route,
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
            aliases: HashSet::from([target.clone()]),
            presized: HashSet::new(),
            growth: Vec::new(),
            unknown_op: None,
            escaped: None,
            loop_depth: 0,
            arm: None,
            conditionals: 0,
        };
        scan.visit_expr(&closure.body);

        if let Some(escape) = scan.escaped.as_deref().filter(|_| scan.presized.is_empty()) {
            return Some(vec![
                Finding::new(
                    RULE,
                    Kind::Route,
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

        if scan.verdict().is_none() {
            if let Some((path, method, line)) = &scan.unknown_op {
                return Some(vec![
                    Finding::new(
                        RULE,
                        Kind::Route,
                        Severity::Unresolved,
                        self.file,
                        *line,
                        format!(
                            "`{receiver}::new_with` calls `{path}.{method}(..)`, which is not a \
                             call this pass knows; whether it grows the buffer was not checked"
                        ),
                    )
                    .with_note(
                        "the op vocabulary is a closed list, so a trait method or an extension \
                         method on the buffer reads as unknown rather than safe. Pre-size with \
                         `reserve_exact` and the question does not arise",
                    ),
                ]);
            }
        }
        let (growth, severity) = scan.verdict()?;

        let message = if severity == Severity::Error {
            format!(
                "`{receiver}::new_with` grows `{}` repeatedly without sizing it (`{}`); the \
                 closure starts with an empty buffer, so each growth past capacity can abandon \
                 one holding the secret",
                growth.path, growth.method
            )
        } else {
            format!(
                "`{receiver}::new_with` fills `{}` with `{}` without sizing it; whether that \
                 reallocates depends on the iterator's size hint, which this pass cannot see",
                growth.path, growth.method
            )
        };

        Some(vec![
            Finding::new(RULE, Kind::Route, severity, self.file, growth.line, message).with_note(
                format!(
                    "add `{}.reserve_exact(len)` as the first statement, or build the value and \
                 use `{receiver}::new`. Measured: 1016 secret bytes across 7 abandoned blocks for \
                 a 1008-byte secret, against 0 for either fix -- SECURITY.md, \"Heap-reallocation \
                 residue\"",
                    growth.path
                ),
            ),
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
    /// The access path grown, e.g. `s.token`.
    path: String,
    /// The innermost conditional arm this sits in, as (conditional, arm). Two
    /// growths in different arms of the same conditional cannot both run, so
    /// they must not be counted as two.
    arm: Option<(usize, usize)>,
    /// Inside a `for` / `while` / `loop`, so it runs an unknown number of times.
    repeated: bool,
}

/// Walks the closure body in source order, so a `reserve_exact` counts only when
/// it actually precedes the growth it is meant to cover.
struct ClosureScan {
    /// Every root name that reaches the buffer. `let alias = v;` is one
    /// statement and it used to defeat this check silently, which is the worst
    /// way to fail: a miss that reads exactly like a pass.
    aliases: HashSet<String>,
    /// Access paths already given their capacity, e.g. `v` or `s.token`. Keyed
    /// by path so that sizing one field does not excuse growing another.
    presized: HashSet<String>,
    growth: Vec<Growth>,
    /// A call on the buffer that is in none of the known lists.
    unknown_op: Option<(String, String, usize)>,
    escaped: Option<String>,
    loop_depth: usize,
    /// Innermost enclosing conditional arm, and a counter giving each
    /// conditional a distinct identity.
    arm: Option<(usize, usize)>,
    conditionals: usize,
}

impl ClosureScan {
    /// The access path an expression names, if it reaches the buffer at all.
    fn refers_to(&self, expr: &syn::Expr) -> Option<String> {
        let path = access_path(expr)?;
        let root = path.split('.').next()?;
        self.aliases.contains(root).then_some(path)
    }

    fn record(&mut self, path: String, method: String, line: usize, shape: Shape) {
        // Sizing has to precede the growth it covers, which the source-order
        // traversal gives for free: a path reserved later is not in the set yet.
        if self.presized.contains(&path) {
            return;
        }
        let repeated = self.loop_depth > 0;
        let arm = self.arm;
        self.growth.push(Growth {
            method,
            line,
            shape,
            path,
            arm,
            repeated,
        });
    }

    /// How many growths of `path` can actually run in one execution.
    ///
    /// Growths in different arms of the same conditional are mutually
    /// exclusive, so the worst case within a conditional is its heaviest arm,
    /// not the sum of them. Counting the sum reported
    /// `if hex { v.extend_from_slice(m) } else { v.extend_from_slice(&m[..1]) }`
    /// -- one bulk fill of an empty buffer on either path, the shape this check
    /// deliberately calls clean -- as repeated growth.
    fn reachable_count(&self, path: &str) -> usize {
        let mine: Vec<&Growth> = self.growth.iter().filter(|g| g.path == path).collect();
        let top = mine.iter().filter(|g| g.arm.is_none()).count();
        let mut per_conditional: HashMap<usize, HashMap<usize, usize>> = HashMap::new();
        for g in mine.iter().filter_map(|g| g.arm.map(|a| (a, *g))) {
            let ((cond, arm), _) = g;
            *per_conditional
                .entry(cond)
                .or_default()
                .entry(arm)
                .or_default() += 1;
        }
        top + per_conditional
            .values()
            .map(|arms| arms.values().copied().max().unwrap_or(0))
            .sum::<usize>()
    }

    /// The verdict, and why.
    ///
    /// A single bulk fill of an empty buffer allocates once and abandons
    /// nothing, which is what the crate's own `dynamic_vec_new_with_fills_correctly`
    /// does; calling that a leak would be wrong and would cost the tool its
    /// welcome. What `SECURITY.md` measured at 1016 bytes across 7 blocks is a
    /// closure that "fills it byte by byte" -- growth that repeats.
    fn verdict(&self) -> Option<(&Growth, Severity)> {
        if let Some(g) = self.growth.iter().find(|g| g.repeated) {
            return Some((g, Severity::Error));
        }
        // Per access path, not globally: `|s| { s.a.extend_from_slice(x);
        // s.b.extend_from_slice(y); }` is one bulk fill of each of two empty
        // fields, and counting them together reported `s.b` as grown repeatedly.
        if let Some(g) = self
            .growth
            .iter()
            .find(|g| self.reachable_count(&g.path) > 1)
        {
            return Some((g, Severity::Error));
        }
        match self.growth.first() {
            Some(g) if g.shape == Shape::Incremental => Some((g, Severity::Warning)),
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for ClosureScan {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if let Some(path) = self.refers_to(&node.receiver) {
            let method = node.method.to_string();
            let line = line_of(&node.method);
            if PRESIZE.contains(&method.as_str()) {
                self.presized.insert(path);
            } else if BULK.contains(&method.as_str()) {
                self.record(path, method, line, Shape::Bulk);
            } else if INCREMENTAL.contains(&method.as_str()) {
                self.record(path, method, line, Shape::Incremental);
            } else if ESCAPE.contains(&method.as_str()) && self.escaped.is_none() {
                self.escaped = Some(method);
            } else if !READS.contains(&method.as_str()) && self.unknown_op.is_none() {
                // Resolving the receiver used to make this case quieter than
                // failing to resolve it, which is backwards for a "not checked"
                // tier: more information must never buy less signal.
                self.unknown_op = Some((path, method, line));
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    /// `*v = Vec::with_capacity(n)` and `*v = already_built` both replace the
    /// empty buffer wholesale rather than growing it, which abandons nothing.
    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(path) = self.refers_to(&node.left) {
            self.presized.insert(path);
        }
        syn::visit::visit_expr_assign(self, node);
    }

    /// `*s += "..."` is `push_str` spelled as an operator.
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::AddAssign(_)) {
            if let Some(path) = self.refers_to(&node.left) {
                let line = line_of(&node.left);
                self.record(path, "+=".to_string(), line, Shape::Bulk);
            }
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
            // The destination is everything up to the first comma, so reading a
            // single token saw `s` in `write!(s.token, ..)` -- which then missed
            // the `s.token.reserve_exact(..)` sitting right above it, and
            // suggested `s.reserve_exact(len)`, which would not compile.
            if let Some(dest) = macro_first_arg(&node.tokens) {
                if let Some(path) = self.refers_to(&dest) {
                    let line = line_of(&dest);
                    self.record(path, "write!".to_string(), line, Shape::Bulk);
                }
            }
        }
        syn::visit::visit_macro(self, node);
    }

    /// A growth call that runs once is not the shape that was measured; the same
    /// call in a loop is exactly it -- "fills it byte by byte", seven buffers
    /// deep. These three overrides are what tells the two apart.
    /// Each conditional gets an identity and each of its arms an index, so
    /// `reachable_count` can tell "twice" from "once, one way or the other".
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.conditionals += 1;
        let id = self.conditionals;
        let outer = self.arm;
        // The condition itself always runs.
        self.visit_expr(&node.cond);
        self.arm = Some((id, 0));
        self.visit_block(&node.then_branch);
        if let Some((_, else_branch)) = &node.else_branch {
            self.arm = Some((id, 1));
            self.visit_expr(else_branch);
        }
        self.arm = outer;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.conditionals += 1;
        let id = self.conditionals;
        let outer = self.arm;
        self.visit_expr(&node.expr);
        for (i, arm) in node.arms.iter().enumerate() {
            self.arm = Some((id, i));
            self.visit_expr(&arm.body);
        }
        self.arm = outer;
    }

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

    /// `let alias = v;` gives the same buffer a second name. Following it is
    /// one line here and the difference between a miss and a silent miss.
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(init) = &node.init {
            if let Some(path) = self.refers_to(&init.expr) {
                match pat_ident(&node.pat) {
                    Some(name) => {
                        // A rebinding of an already-sized path inherits its
                        // sizing; otherwise `v.reserve_exact(n); let a = v;`
                        // would report the growth it already covered.
                        if self.presized.contains(&path) {
                            self.presized.insert(name.clone());
                        }
                        self.aliases.insert(name);
                    }
                    // Destructured into a shape this pass does not model.
                    None => {
                        if self.escaped.is_none() {
                            self.escaped = Some("a destructuring `let`".to_string());
                        }
                    }
                }
            }
        }
        syn::visit::visit_local(self, node);
    }

    /// A helper call that takes the buffer is growth this pass cannot see.
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        for arg in &node.args {
            if self.refers_to(arg).is_some() && self.escaped.is_none() {
                self.escaped = Some(crate::storage::render(&*node.func));
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// The first macro argument, parsed as an expression -- `write!(s.token, ..)`
/// hands back `s.token` rather than the bare token `s`.
fn macro_first_arg(tokens: &proc_macro2::TokenStream) -> Option<syn::Expr> {
    let mut head = proc_macro2::TokenStream::new();
    for tt in tokens.clone() {
        if matches!(&tt, proc_macro2::TokenTree::Punct(p) if p.as_char() == ',') {
            break;
        }
        head.extend(std::iter::once(tt));
    }
    syn::parse2(head).ok()
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

/// The access path an expression names -- `v`, `s.token`, `s.inner.0` --
/// looking through the borrows and derefs a `&mut` buffer collects at a call
/// site. Field access is what makes this a path rather than a name: for a
/// `Dynamic<Session>` the growth is `s.token.push(b)` and the buffer itself is
/// never named alone.
fn access_path(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        syn::Expr::Field(f) => {
            let base = access_path(&f.base)?;
            let member = match &f.member {
                syn::Member::Named(id) => id.to_string(),
                syn::Member::Unnamed(i) => i.index.to_string(),
            };
            Some(format!("{base}.{member}"))
        }
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => access_path(&u.expr),
        syn::Expr::Reference(r) => access_path(&r.expr),
        syn::Expr::Paren(p) => access_path(&p.expr),
        syn::Expr::Group(g) => access_path(&g.expr),
        _ => None,
    }
}
