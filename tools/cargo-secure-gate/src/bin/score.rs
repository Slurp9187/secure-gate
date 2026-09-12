//! Scores the audit pass against a corpus whose answers are known.
//!
//! Precision has been measurable all along -- run the pass over code believed
//! correct and count what it says. Recall has not, and the difference matters:
//! a peer's regex implementation of the same two rules measured 0 of 11 against
//! an independent corpus, and pointed at one leaking file and one clean file it
//! put all ten of its findings on the clean one. Its own author's corpus had
//! reported ~23%, because a corpus written by the same hand as the tool shares
//! its blind spots. The number only means something when someone else wrote the
//! cases, which is why this harness exists separately from the tool's own tests.
//!
//! # Marking a case
//!
//! A leak is marked next to the line that should be reported, using the
//! `compiletest` convention this repository already knows from `trybuild`:
//!
//! ```text
//! for b in material { s.token.push(*b); }   //~ LEAK
//! //~^ LEAK                                   (marks the line above instead)
//! ```
//!
//! Unmarked corpora still score: the run reports what it found and where, and
//! leaves the reconciling to a reader. That fallback is deliberate -- a corpus
//! is worth having before it is worth annotating, and requiring markers first
//! would be a reason not to hand one over.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;

use cargo_secure_gate::analyze_paths;
use cargo_secure_gate::report::{Finding, Severity};

const USAGE: &str = "\
score -- measure this pass against a corpus with known answers

usage:
    score --leaking <path>... [--clean <path>...]

    --leaking   files whose leaks are the cases to find. Lines carrying a
                `//~ LEAK` marker (or `//~^ LEAK` for the line above) are the
                expected findings; without markers the run reports raw counts.
    --clean     files believed correct. Any finding here is a false positive.
";

type Marker = (String, usize);

fn main() -> ExitCode {
    let mut leaking: Vec<PathBuf> = Vec::new();
    let mut clean: Vec<PathBuf> = Vec::new();
    let mut target = None;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--leaking" => target = Some(0),
            "--clean" => target = Some(1),
            other => match target {
                Some(0) => leaking.push(PathBuf::from(other)),
                Some(1) => clean.push(PathBuf::from(other)),
                _ => {
                    eprintln!("unexpected argument `{other}`");
                    return ExitCode::from(2);
                }
            },
        }
    }
    if leaking.is_empty() {
        print!("{USAGE}");
        return ExitCode::from(2);
    }

    let found = match analyze_paths(&leaking) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let markers = match collect_markers(&leaking) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let reported: BTreeSet<Marker> = found
        .iter()
        .filter(|f| f.severity != Severity::Unresolved)
        .map(|f| (f.file.clone(), f.line))
        .collect();
    let hits = markers.iter().filter(|m| reported.contains(*m)).count();

    println!("== RECALL ==");
    if markers.is_empty() {
        // No annotations: say what was found and let a reader reconcile it,
        // rather than inventing a denominator.
        println!("no `//~ LEAK` markers found, so there is no denominator here.");
        println!("{} finding(s) reported:", found.len());
        for f in &found {
            println!("  {}:{}  [{}]", f.file, f.line, f.rule);
        }
        println!("reconcile these against the corpus by hand, or add markers and re-run.\n");
    } else {
        println!("marked cases: {}", markers.len());
        println!("found:        {hits}");
        println!("missed:       {}", markers.len() - hits);
        for (file, line) in markers.iter().filter(|m| !reported.contains(*m)) {
            match nearest(&found, file, *line) {
                // A site reported as unresolved is better than silence and is
                // still not a catch, so it scores as a miss and says why.
                Some(f) if f.line == *line && f.severity == Severity::Unresolved => {
                    println!("  MISS {file}:{line}  (reported as not checked, which is not a find)")
                }
                Some(f) => println!("  MISS {file}:{line}  (nearest finding: line {})", f.line),
                None => println!("  MISS {file}:{line}  (nothing reported in this file)"),
            }
        }
        // A finding away from every marker is not automatically wrong -- one
        // function can carry two routes -- so it is listed, never scored.
        let extra: Vec<_> = found
            .iter()
            .filter(|f| f.severity != Severity::Unresolved)
            .filter(|f| !markers.contains(&(f.file.clone(), f.line)))
            .collect();
        if !extra.is_empty() {
            println!("unmarked findings in the leaking corpus ({}):", extra.len());
            for f in &extra {
                println!("  {}:{}  [{}]", f.file, f.line, f.rule);
            }
        }
        println!("recall: {hits}/{}\n", markers.len());
    }

    let unresolved: Vec<_> = found
        .iter()
        .filter(|f| f.severity == Severity::Unresolved)
        .collect();
    if !unresolved.is_empty() {
        println!("not checked in the leaking corpus ({}):", unresolved.len());
        for f in &unresolved {
            println!("  {}:{}  {}", f.file, f.line, f.message);
        }
        println!();
    }

    let mut false_positives = 0usize;
    if !clean.is_empty() {
        println!("== PRECISION ==");
        match analyze_paths(&clean) {
            Ok(findings) => {
                let fp: Vec<_> = findings
                    .iter()
                    .filter(|f| f.severity != Severity::Unresolved)
                    .collect();
                false_positives = fp.len();
                println!("findings on code believed correct: {}", fp.len());
                for f in &fp {
                    println!("  {}:{}  [{}] {}", f.file, f.line, f.rule, f.message);
                }
                println!();
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    }

    println!("== SUMMARY ==");
    if markers.is_empty() {
        println!("recall: unmeasured (no markers)");
    } else {
        println!("recall: {hits}/{}", markers.len());
    }
    println!("false positives on clean code: {false_positives}");
    ExitCode::SUCCESS
}

/// Every `(file, line)` a `//~ LEAK` marker says should be reported.
fn collect_markers(roots: &[PathBuf]) -> Result<BTreeSet<Marker>, String> {
    let mut markers = BTreeSet::new();
    for root in roots {
        let files: Vec<PathBuf> = if root.is_file() {
            vec![root.clone()]
        } else {
            walkdir::WalkDir::new(root)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file())
                .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
                .map(|e| e.into_path())
                .collect()
        };
        for file in files {
            let text =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            for (i, line) in text.lines().enumerate() {
                let Some(at) = line.find("//~") else { continue };
                let rest = &line[at + 3..];
                if !rest.to_ascii_uppercase().contains("LEAK") {
                    continue;
                }
                // `//~^` points at the line above, as in compiletest.
                let up = rest.chars().take_while(|c| *c == '^').count();
                let target = (i + 1).saturating_sub(up).max(1);
                markers.insert((file.display().to_string(), target));
            }
        }
    }
    Ok(markers)
}

/// The closest finding to a missed marker, which usually says whether the shape
/// was missed outright or merely attributed to a different line.
fn nearest<'a>(found: &'a [Finding], file: &str, line: usize) -> Option<&'a Finding> {
    found
        .iter()
        .filter(|f| f.file == file)
        .min_by_key(|f| f.line.abs_diff(line))
}
