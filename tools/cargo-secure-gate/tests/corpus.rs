//! The checks, pinned against the shapes the crate has already measured.
//!
//! `tests/lifecycle_trace_heap.rs` installs a global allocator and counts
//! non-zero bytes in freed blocks, which makes it the thing that can actually
//! say whether a buffer was abandoned and how much of the secret was in it. Its
//! scenarios come with signed verdicts: `check_new_with_keeps_the_closures_buffer`
//! measured 0, `check_growth_orphan_retains_secret_vec` measured every byte.
//!
//! Rather than invent a notion of what these checks ought to flag, each fixture
//! is one of those scenarios and each expectation is that scenario's measured
//! result. Where a shape is documented but not in the corpus -- the unsized
//! `new_with`, measured at 1016 bytes across 7 blocks in `SECURITY.md` -- the
//! fixture says so.
//!
//! The negative cases carry as much weight as the positive ones. A tool that
//! flags `Fixed::new_with`, or the capacity-stable mutation `SECURITY.md`
//! recommends, teaches its users to ignore it.

use cargo_secure_gate::analyze_sources;
use cargo_secure_gate::report::{Kind, Severity};

fn run(fixture: &str) -> Vec<(String, Severity, usize)> {
    let path = format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("fixture is readable");
    analyze_sources(&[(fixture.to_string(), text)])
        .expect("fixture parses")
        .into_iter()
        .map(|f| (f.rule.to_string(), f.severity, f.line))
        .collect()
}

fn rules(fixture: &str, severity: Severity) -> Vec<String> {
    run(fixture)
        .into_iter()
        .filter(|(_, s, _)| *s == severity)
        .map(|(r, _, _)| r)
        .collect()
}

// ---------------------------------------------------------------------------
// SG002 -- construction
// ---------------------------------------------------------------------------

#[test]
fn presized_new_with_is_clean() {
    // check_new_with_keeps_the_closures_buffer: measured 0 surviving bytes.
    assert_eq!(run("presized_new_with.rs"), vec![]);
}

#[test]
fn unsized_new_with_is_one_finding_per_call_site() {
    // SECURITY.md: 1016 secret bytes across 7 abandoned blocks, from a closure
    // that "fills it byte by byte". Two loops, two errors -- not one per `push`.
    assert_eq!(
        rules("unsized_new_with.rs", Severity::Error),
        vec!["SG002", "SG002"]
    );
    // And the iterator fill, whose reallocation count lives in a size hint this
    // pass cannot read, is a warning rather than a claim.
    assert_eq!(
        rules("unsized_new_with.rs", Severity::Warning),
        vec!["SG002"]
    );
}

#[test]
fn a_single_bulk_fill_of_an_empty_buffer_is_clean() {
    // The distinction the first draft of this check got wrong, and running it
    // over the crate's own tests is what surfaced it: one `extend_from_slice`
    // into an empty buffer allocates once and abandons nothing. Flagging it
    // would have put three findings on `tests/core_tests.rs` that were not there.
    let findings = run("single_bulk_fill.rs");
    assert_eq!(
        findings
            .iter()
            .filter(|(_, s, _)| *s != Severity::Error)
            .count(),
        0
    );
    // The two-fill function in the same fixture is the one real finding.
    assert_eq!(rules("single_bulk_fill.rs", Severity::Error), vec!["SG002"]);
}

#[test]
fn the_growth_is_reported_where_it_happens() {
    // The useful line is the `push`, not the `new_with` that opened the closure.
    let findings = run("unsized_new_with.rs");
    let first = findings
        .iter()
        .find(|(r, s, _)| r == "SG002" && *s == Severity::Error)
        .expect("the first site is flagged");
    assert_eq!(first.2, 12, "expected the line holding `v.push(*byte)`");
}

#[test]
fn fixed_new_with_is_not_a_dynamic_new_with() {
    // Shared method name, and no capacity to change. Flagging it would be noise.
    assert_eq!(run("fixed_new_with.rs"), vec![]);
}

#[test]
fn capacity_stable_mutation_is_clean() {
    // check_capacity_stable_mutation_stays_in_one_buffer: 0 allocations.
    // This is the pattern SECURITY.md recommends; flagging it would be worse
    // than saying nothing.
    assert_eq!(run("capacity_stable_mutation.rs"), vec![]);
}

#[test]
fn a_buffer_handed_to_a_helper_is_unresolved_not_clean() {
    let findings = run("escaping_helper.rs");
    assert_eq!(
        findings
            .iter()
            .map(|(r, s, _)| (r.as_str(), *s))
            .collect::<Vec<_>>(),
        vec![("SG002", Severity::Unresolved)],
    );
    assert!(
        rules("escaping_helper.rs", Severity::Error).is_empty(),
        "an unchecked site must not be reported as a confirmed one"
    );
}

// ---------------------------------------------------------------------------
// SG001 -- the assertion FixedStorage cannot check
// ---------------------------------------------------------------------------

#[test]
fn an_honest_fixed_storage_impl_is_clean() {
    // The `Poly([i16; 256])` impl from the FixedStorage module docs, plus the
    // array, tuple and Option shapes the crate implements for you.
    assert_eq!(run("fixed_storage_honest.rs"), vec![]);
}

#[test]
fn heap_ownership_is_the_predicate_not_resizability() {
    // The crate's marker originally asked for a fixed capacity and so accepted
    // `Box<[T]>`. Measured, a `Fixed<Box<[u8]>>` assigned through
    // `with_secret_mut` released its original block with 1024 of 1024 bytes
    // intact -- whole-value replacement abandons an allocation with no capacity
    // change at all -- and `fe64ef8` dropped the impl. This pass treated `Box`
    // as transparent and reported every one of these as honest, which is a false
    // negative in the one check whose whole value is catching a false assertion.
    let errors = rules("heap_owning_not_resizable.rs", Severity::Error);
    assert_eq!(
        errors,
        vec!["SG001", "SG001", "SG001", "SG001"],
        "Box<[u8]>, Option<Box<[u8]>>, [Box<[u8]>; 2] and Arc<[u8]> all own heap"
    );
    // The inline contrast from the same measurement must stay clean.
    assert_eq!(run("heap_owning_not_resizable.rs").len(), 4);
}

#[test]
fn the_two_checks_ask_two_different_questions() {
    // Conflating them is the root cause rather than the `Box` entry itself: a
    // boxed slice owns heap (so SG001 must flag it) and cannot change capacity
    // (so the reallocation vocabulary must not claim it can).
    use cargo_secure_gate::storage::{Resolver, Storage, TypeDef};
    let mut resolver = Resolver::default();
    resolver.types.insert(
        "B".to_string(),
        TypeDef {
            generics: vec![],
            fields: vec![(
                "buf".to_string(),
                syn::parse_str::<syn::Type>("Box<[u8]>").unwrap(),
            )],
        },
    );
    let found = resolver.classify_named("B", &[]);
    assert!(matches!(found, Storage::HeapFixed { .. }));
    assert!(found.owns_heap().is_some(), "FixedStorage must reject it");
    assert!(
        !found.capacity_can_change(),
        "a boxed slice cannot be resized, and saying it can would be the mirror error"
    );
}

#[test]
fn a_contradicted_fixed_storage_impl_is_an_error() {
    // Direct Vec field, one level down, inside an array, and in one enum
    // variant -- four impls, four errors.
    let errors = rules("fixed_storage_contradicted.rs", Severity::Error);
    assert_eq!(errors, vec!["SG001", "SG001", "SG001", "SG001"]);
}

#[test]
fn a_foreign_field_is_unresolved_not_clean() {
    let findings = run("fixed_storage_foreign.rs");
    assert_eq!(
        findings
            .iter()
            .map(|(r, s, _)| (r.as_str(), *s))
            .collect::<Vec<_>>(),
        vec![("SG001", Severity::Unresolved)],
    );
}

// ---------------------------------------------------------------------------
// Cross-file resolution
// ---------------------------------------------------------------------------

#[test]
fn a_newtype_declared_in_another_file_still_resolves() {
    // Real crates declare the newtype in one module and construct it in
    // another. A single-file pass would report this as unresolved.
    let declaration = (
        "secrets.rs".to_string(),
        "dynamic_newtype!(pub Tok, Vec<u8>, \"token\");".to_string(),
    );
    let use_site = (
        "build.rs".to_string(),
        "fn f(m: &[u8]) -> Tok { Tok::new_with(|v| { for b in m { v.push(*b); } }) }".to_string(),
    );
    let findings = analyze_sources(&[use_site, declaration]).expect("parses");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Error);
    assert_eq!(findings[0].rule, "SG002");
}

#[test]
fn an_undeclared_receiver_is_unresolved() {
    let findings = analyze_sources(&[(
        "lone.rs".to_string(),
        "fn f(m: &[u8]) -> Tok { Tok::new_with(|v| { for b in m { v.push(*b); } }) }".to_string(),
    )])
    .expect("parses");
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].severity,
        Severity::Unresolved,
        "an unknown receiver must not be guessed at in either direction"
    );
}

#[test]
fn the_generic_arm_resolves_like_the_named_ones() {
    // #201 gave `fixed_newtype!` a `generic T` arm; `dynamic_newtype!` had one.
    // The inner type is arbitrary tokens, so the parser has to read it as a type
    // rather than match on `String` / `Vec<u8>`.
    let findings = analyze_sources(&[(
        "generic.rs".to_string(),
        "dynamic_newtype!(pub Wide, generic Vec<u32>, \"wide\");\n\
         fn f() -> Wide { Wide::new_with(|v| { for i in 0..4u32 { v.push(i); } }) }"
            .to_string(),
    )])
    .expect("parses");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Error);
}

#[test]
fn a_comma_inside_generics_does_not_split_the_inner_type() {
    // Angle brackets are not a delimiter in a token stream, so a naive split on
    // commas reads `BTreeMap<u8` as the whole inner type and loses the name.
    let findings = analyze_sources(&[(
        "map.rs".to_string(),
        "dynamic_newtype!(pub Table, generic BTreeMap<u8, u8>, \"table\");\n\
         fn f() -> Table { Table::new_with(|m| { for i in 0..4u8 { m.insert(i, i); } }) }"
            .to_string(),
    )])
    .expect("parses");
    assert_eq!(findings.len(), 1, "the newtype name failed to resolve");
    assert_eq!(findings[0].severity, Severity::Error);
}

// ---------------------------------------------------------------------------
// Shapes a text-based matcher misses, and bait it falls for
//
// These come from a peer sweep of this crate that measured ~23% recall for a
// regex prototype against a deliberately evasive corpus, with the misses
// systematic rather than random: anything that rebinds the exposed reference.
// Two of the three below were verified against this pass directly; the aliasing
// one failed, silently, and is fixed.
// ---------------------------------------------------------------------------

#[test]
fn an_aliased_buffer_is_still_the_buffer() {
    // `let alias = v;` used to defeat this check without leaving a trace.
    let errors = rules("aliased_buffer.rs", Severity::Error);
    assert_eq!(errors, vec!["SG002", "SG002"], "one per aliased call site");
    assert!(
        run("aliased_buffer.rs").len() == 2,
        "the third function pre-sizes and binds a capacity, which is not the buffer"
    );
}

#[test]
fn comments_string_literals_and_unrelated_vecs_are_not_findings() {
    // The bait a text matcher takes. Parsing makes this free, which is most of
    // the argument for parsing.
    assert_eq!(run("lexical_bait.rs"), vec![]);
}

#[test]
fn a_non_ascii_type_name_does_not_evade_the_check() {
    // Rust identifiers are XID. A one-character rename defeats `[A-Za-z_]`.
    let errors = rules("non_ascii_idents.rs", Severity::Error);
    assert_eq!(errors, vec!["SG001", "SG001"]);
}

// ---------------------------------------------------------------------------
// The two kinds of claim
// ---------------------------------------------------------------------------

#[test]
fn an_assertion_and_a_route_are_not_the_same_kind_of_claim() {
    // SG001 is decidable from the source: the impl contradicts the type whether
    // or not a secret ever flows through it. SG002 names a place a
    // reallocation can happen -- whether it does depends on capacity and on
    // whether the allocator extends in place, which SECURITY.md measures
    // happening. Reporting them in one severity list invites the reader to
    // treat a route as an observed leak.
    let assertion = analyze_sources(&[(
        "a.rs".to_string(),
        "struct S { v: Vec<u8> }\nimpl FixedStorage for S {}".to_string(),
    )])
    .expect("parses");
    assert_eq!(assertion[0].kind, Kind::Assertion);

    let route = analyze_sources(&[(
        "b.rs".to_string(),
        "fn f(m: &[u8]) -> Dynamic<Vec<u8>> { Dynamic::new_with(|v| { for b in m { v.push(*b); } }) }"
            .to_string(),
    )])
    .expect("parses");
    assert_eq!(route[0].kind, Kind::Route);
}

// ---------------------------------------------------------------------------
// Failure modes reported by an independent adversarial pass
//
// That pass was run against a regex implementation of the same two rules and
// inverted: pointed at one file with 11 measured leaks and one with none, it
// put all ten of its findings on the clean file. The shapes below are the ones
// that transfer to any implementation, tested here against this one.
// ---------------------------------------------------------------------------

#[test]
fn a_local_alias_and_a_bound_type_parameter_are_resolvable_not_foreign() {
    // Reported as silent in the regex pass. They must be errors, not
    // unresolved: both are one lookup from an answer.
    assert_eq!(
        rules("resolvable_not_foreign.rs", Severity::Error),
        vec!["SG001", "SG001"]
    );
    assert!(
        rules("resolvable_not_foreign.rs", Severity::Unresolved).is_empty(),
        "a resolvable answer must not land in the unresolved pile"
    );
}

#[test]
fn growth_through_a_field_is_growth() {
    // "The miss that matters most", and the most idiomatic shape in the
    // language: for a `Dynamic<Session>` the buffer is never named alone.
    let findings = run("field_access.rs");
    let errors: Vec<_> = findings
        .iter()
        .filter(|(_, s, _)| *s == Severity::Error)
        .collect();
    assert_eq!(
        errors.len(),
        2,
        "one per call site, including the half-sized one"
    );
}

#[test]
fn sizing_one_field_does_not_excuse_growing_another() {
    // Tracking paths rather than bindings is what buys this. Keyed on the
    // binding alone, `s.token.reserve_exact(..)` would cover `s.label.push(..)`.
    let findings = analyze_sources(&[(
        "f.rs".to_string(),
        "struct S { a: Vec<u8>, b: String }\n\
         fn f(m: &[u8]) -> Dynamic<S> { Dynamic::new_with(|s| { \
           s.a.reserve_exact(m.len()); for x in m { s.a.push(*x); } \
           for c in \"xy\".chars() { s.b.push(c); } }) }"
            .to_string(),
    )])
    .expect("parses");
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].message.contains("s.b"),
        "the sized field was reported instead of the unsized one: {}",
        findings[0].message
    );
}

#[test]
fn a_doc_comment_is_not_evidence() {
    // The regex pass quoted a developer's own safety comment back at them as
    // the reason for its highest-severity finding. Parsing makes this free.
    assert_eq!(run("doc_comment_evidence.rs"), vec![]);
}

#[test]
fn an_unparseable_file_is_reported_and_does_not_abort_the_run() {
    // One bad file used to return Err and scan nothing. Scanning less than was
    // asked for, silently, is the failure mode this pass exists to avoid.
    let findings = analyze_sources(&[
        ("broken.rs".to_string(), "fn f( {{{".to_string()),
        (
            "good.rs".to_string(),
            "struct S { v: Vec<u8> }\nimpl FixedStorage for S {}".to_string(),
        ),
    ])
    .expect("a bad file is a finding, not an error");
    assert!(
        findings
            .iter()
            .any(|f| f.rule == "SG000" && f.severity == Severity::Unresolved),
        "the unparseable file was not reported"
    );
    assert!(
        findings.iter().any(|f| f.rule == "SG001"),
        "the good file was not scanned"
    );
}
