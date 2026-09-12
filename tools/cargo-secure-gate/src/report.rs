//! Findings, and the two ways they are printed.
//!
//! The report carries unresolved sites alongside findings by design. A pass that
//! quietly skipped what it could not resolve would read, to someone scanning its
//! output, exactly like a pass that found nothing -- and `SECURITY.md` is at
//! pains not to let a green result be mistaken for a proof. `Unresolved` is how
//! this tool says "not checked" out loud.

use serde::Serialize;

/// What kind of claim a finding is making. The two are not comparable, and
/// putting them in one severity list invites the reader to treat them alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A marker trait asserts something about a type, and the type's own
    /// definition contradicts it. Decidable from the source, no runtime
    /// involved: the impl is wrong whether or not any secret ever flows
    /// through it.
    Assertion,
    /// A place where a buffer holding a secret can be reallocated. Whether it
    /// *is* reallocated at any particular execution depends on the capacity at
    /// that moment and on whether the allocator can extend the block in place
    /// -- `SECURITY.md` measures a 1008-byte buffer growing by 96 and extending
    /// in place, abandoning nothing. So this is a route, never an observation.
    Route,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A documented weakness, present in the source as written.
    Error,
    /// Worth a look; may be intended.
    Warning,
    /// Something the pass could not resolve. Never a claim about the code.
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub kind: Kind,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub message: String,
    /// Where the claim comes from: a SECURITY.md section, a measured test.
    pub note: Option<String>,
}

impl Finding {
    pub fn new(
        rule: &'static str,
        kind: Kind,
        severity: Severity,
        file: impl Into<String>,
        line: usize,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule,
            kind,
            severity,
            file: file.into(),
            line,
            message: message.into(),
            note: None,
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

pub fn print_human(findings: &[Finding]) {
    let assertions: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == Kind::Assertion && f.severity != Severity::Unresolved)
        .collect();
    let routes: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == Kind::Route && f.severity != Severity::Unresolved)
        .collect();
    let unresolved: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Unresolved)
        .collect();

    section(
        "ASSERTIONS CONTRADICTED BY THE TYPE",
        "A marker trait asserts something the type's own fields deny. Decidable \
         from the source: the impl is wrong whether or not a secret ever flows \
         through it. Review each by hand.",
        &assertions,
    );
    section(
        "GROWTH ROUTES",
        "Places where a buffer holding a secret can be reallocated. Whether any \
         one of them does reallocate depends on capacity and on whether the \
         allocator can extend in place, so this is an inventory of routes and \
         not a record of leaks.",
        &routes,
    );
    section(
        "NOT CHECKED",
        "Sites this pass could not resolve. Neither passed nor failed.",
        &unresolved,
    );

    println!(
        "{} assertion(s), {} growth route(s), {} not checked",
        assertions.len(),
        routes.len(),
        unresolved.len()
    );
    // Never "clean", never "no leaks". At an unmeasured recall against code
    // that is not trying to be read, the only defensible statement is about
    // what was looked for.
    println!("no other known shape was found in the scanned text; that is not a proof of absence");
}

fn section(title: &str, preamble: &str, findings: &[&Finding]) {
    if findings.is_empty() {
        return;
    }
    println!("== {title} ==");
    println!("{preamble}\n");
    for f in findings {
        println!("[{}] {}:{}\n    {}", f.rule, f.file, f.line, f.message);
        if let Some(note) = &f.note {
            println!("    note: {note}");
        }
        println!();
    }
}

pub fn print_json(findings: &[Finding]) -> serde_json::Result<()> {
    println!("{}", serde_json::to_string_pretty(findings)?);
    Ok(())
}
