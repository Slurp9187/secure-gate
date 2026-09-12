//! Findings, and the two ways they are printed.
//!
//! The report carries unresolved sites alongside findings by design. A pass that
//! quietly skipped what it could not resolve would read, to someone scanning its
//! output, exactly like a pass that found nothing -- and `SECURITY.md` is at
//! pains not to let a green result be mistaken for a proof. `Unresolved` is how
//! this tool says "not checked" out loud.

use serde::Serialize;

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

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Unresolved => "unresolved",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule: &'static str,
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
        severity: Severity,
        file: impl Into<String>,
        line: usize,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule,
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
    for f in findings {
        println!(
            "{}: [{}] {}:{}\n    {}",
            f.severity.label(),
            f.rule,
            f.file,
            f.line,
            f.message
        );
        if let Some(note) = &f.note {
            println!("    note: {note}");
        }
        println!();
    }

    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let unresolved = findings
        .iter()
        .filter(|f| f.severity == Severity::Unresolved)
        .count();

    println!("{errors} error(s), {warnings} warning(s), {unresolved} unresolved");
    if unresolved > 0 {
        println!(
            "unresolved sites were not checked; a clean run is not a proof that none of them leak"
        );
    }
}

pub fn print_json(findings: &[Finding]) -> serde_json::Result<()> {
    println!("{}", serde_json::to_string_pretty(findings)?);
    Ok(())
}
