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
use cargo_secure_gate::report::Severity;

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
    // Box<[u8]>, array, tuple and Option shapes the crate implements for you.
    assert_eq!(run("fixed_storage_honest.rs"), vec![]);
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
