//! `cargo secure-gate <path>...` -- run the audit checks over a source tree.

use std::path::PathBuf;
use std::process::ExitCode;

use cargo_secure_gate::analyze_paths;
use cargo_secure_gate::report::{Kind, Severity, print_human, print_json};

const USAGE: &str = "\
cargo secure-gate -- source-level audit checks for secure-gate consumers

usage:
    cargo secure-gate [--format human|json] [--deny-routes] <path>...

checks:
    SG001  a FixedStorage impl on a type that owns a resizable buffer
    SG002  a Dynamic::new_with closure that fills a buffer it never sized

exit code is 1 when a contradicted assertion is reported. Growth routes are an
inventory, not findings; pass --deny-routes to fail on them too.
";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1).peekable();
    // Invoked as `cargo secure-gate`, cargo passes the subcommand name through.
    if args.peek().map(String::as_str) == Some("secure-gate") {
        args.next();
    }

    let mut json = false;
    let mut deny_routes = false;
    let mut roots: Vec<PathBuf> = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--format" => match args.next().as_deref() {
                Some("json") => json = true,
                Some("human") | None => {}
                Some(other) => {
                    eprintln!("unknown format `{other}`");
                    return ExitCode::from(2);
                }
            },
            "--deny-routes" => deny_routes = true,
            other => roots.push(PathBuf::from(other)),
        }
    }

    if roots.is_empty() {
        print!("{USAGE}");
        return ExitCode::from(2);
    }

    let findings = match analyze_paths(&roots) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    // An assertion contradicted by its own type is a defect in the source and
    // fails the run. A growth route is an inventory entry -- reported, and not
    // treated as a finding unless the caller says to, because failing on it
    // would undo the distinction the report just drew.
    let failed = findings.iter().any(|f| {
        f.severity == Severity::Error
            && (f.kind == Kind::Assertion || (deny_routes && f.kind == Kind::Route))
    });
    if json {
        if let Err(e) = print_json(&findings) {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    } else {
        print_human(&findings);
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
