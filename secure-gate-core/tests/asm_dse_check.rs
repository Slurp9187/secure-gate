//! Assembly-level verification that LLVM dead-store elimination (DSE) does not
//! remove the volatile zero-store instructions emitted by `Fixed<T>`'s drop glue.
//!
//! # Strategy
//!
//! Compiles `src/bin/asm_check.rs` in release mode with `--emit=asm`, locates
//! the `make_and_drop_fixed` symbol (which is `#[no_mangle]`d, so no demangling
//! is required), extracts that function's body, and asserts that store-to-zero
//! instructions are present.
//!
//! # Platform
//!
//! Assertion patterns are x86_64-specific. The test is gated to that arch and
//! skipped silently on anything else.
//!
//! # Running
//!
//! ```text
//! cargo test -p secure-gate --release --test asm_dse_check -- --nocapture
//! ```
//!
//! The test triggers a full release build of the binary (~30 s first run) so it
//! is marked `#[ignore]` to keep `cargo test` fast by default. Run explicitly:
//!
//! ```text
//! cargo test -p secure-gate --release --test asm_dse_check -- --ignored --nocapture
//! ```

#![cfg(target_arch = "x86_64")]
#![cfg(not(miri))] // test shells out to cargo; Miri cannot handle that

use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "triggers a full release build; run with --ignored in CI or manually"]
fn fixed_drop_emits_volatile_zero_stores() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Use `cargo rustc` so `--emit=asm` only applies to the final crate (the
    // binary), not to every dependency. This avoids cluttering the deps dir
    // with unrelated .s files and prevents unnecessary recompilation of deps.
    let status = Command::new(env!("CARGO"))
        .current_dir(&manifest_dir)
        .args([
            "rustc",
            "--release",
            "--bin",
            "asm_check",
            "--",
            "--emit=asm",
        ])
        .status()
        .expect("failed to invoke cargo");

    assert!(
        status.success(),
        "cargo rustc --release --bin asm_check failed"
    );

    // The .s file lands in target/release/deps/ named asm_check-<hash>.s.
    let deps_dir = manifest_dir
        .parent() // workspace root
        .expect("manifest_dir has no parent")
        .join("target")
        .join("release")
        .join("deps");

    let asm_path = find_asm_file(&deps_dir, "asm_check").unwrap_or_else(|| {
        panic!(
            "could not find asm_check*.s in {}\n\
             Ensure the crate compiled successfully and --emit=asm was honoured.",
            deps_dir.display()
        )
    });

    let asm = std::fs::read_to_string(&asm_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", asm_path.display()));

    // Extract just the make_and_drop_fixed function body so we don't match
    // unrelated zeroing code elsewhere in the binary.
    let body = extract_function_body(&asm, "make_and_drop_fixed").unwrap_or_else(|| {
        panic!(
            "could not find 'make_and_drop_fixed' label in {}\n\
             First 40 lines of assembly:\n{}",
            asm_path.display(),
            asm.lines().take(40).collect::<Vec<_>>().join("\n")
        )
    });

    // Assert that at least one zero-store pattern is present.
    //
    // LLVM may codegen 32 volatile byte-writes as any of:
    //
    //   (a) SSE:  xorps/pxor to zero xmm0, then movaps/movups/movdqa/movdqu x2
    //   (b) AVX:  vxorps/vpxor + vmovaps/vmovups x2
    //   (c) Scalar 8-byte: mov QWORD PTR [...], 0  x4
    //   (d) Scalar 1-byte: mov BYTE PTR  [...], 0  x32
    //   (e) Rep string:    xor eax,eax / rep stosb
    //
    // The assertion is deliberately broad: any of these confirms the stores
    // survived. The failure mode we guard against is *none* being present.
    let has_sse_zero = (body.contains("xorps")
        || body.contains("xorpd")
        || body.contains("pxor")
        || body.contains("vxorps")
        || body.contains("vpxor"))
        && (body.contains("movaps")
            || body.contains("movups")
            || body.contains("movdqa")
            || body.contains("movdqu")
            || body.contains("vmovaps")
            || body.contains("vmovups")
            || body.contains("vmovdqa")
            || body.contains("vmovdqu"));

    let has_scalar_zero = has_mov_zero_pattern(&body);

    let has_rep_stos = body.contains("rep") && body.contains("stos");

    assert!(
        has_sse_zero || has_scalar_zero || has_rep_stos,
        "ZEROIZATION REGRESSION DETECTED\n\n\
         No volatile zero-store instructions were found in make_and_drop_fixed.\n\
         LLVM may have eliminated the zeroization writes via dead-store elimination.\n\n\
         Assembly file : {}\n\n\
         Extracted function body:\n\
         ─────────────────────────────────────────────\n\
         {body}\n\
         ─────────────────────────────────────────────",
        asm_path.display()
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the first `.s` file in `dir` whose name starts with `prefix`.
fn find_asm_file(dir: &Path, prefix: &str) -> Option<PathBuf> {
    std::fs::read_dir(dir).ok()?.flatten().find_map(|e| {
        let p = e.path();
        let name = p.file_name()?.to_str()?;
        if name.starts_with(prefix) && name.ends_with(".s") {
            Some(p)
        } else {
            None
        }
    })
}

/// Extracts the lines of `name:` up to (but not including) `.cfi_endproc`,
/// `.size`, or the next non-local, non-directive label.
fn extract_function_body(asm: &str, name: &str) -> Option<String> {
    let label = format!("{name}:");
    let mut in_func = false;
    let mut lines: Vec<&str> = Vec::new();

    for line in asm.lines() {
        let trimmed = line.trim();
        if !in_func {
            if trimmed == label || trimmed.starts_with(&format!("{label} ")) {
                in_func = true;
                lines.push(line);
            }
        } else {
            // End of function markers (Linux: .cfi_endproc / Windows SEH: .seh_endproc)
            if trimmed.starts_with(".cfi_endproc")
                || trimmed.starts_with(".seh_endproc")
                || trimmed.starts_with(".size")
            {
                break;
            }
            // Another non-local label (not a local numeric/dot label and not our own)
            if trimmed.ends_with(':')
                && !trimmed.starts_with('.')
                && !trimmed.starts_with(name)
                && !trimmed.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                break;
            }
            lines.push(line);
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

/// Returns `true` if `body` contains a `mov` instruction storing an immediate
/// zero to memory. Handles both syntaxes emitted by rustc:
///
/// - Intel: `mov BYTE PTR [rsp+8], 0`  (used on some targets)
/// - AT&T:  `movb $0, 8(%rsp)`         (used on Windows/Linux x86-64)
fn has_mov_zero_pattern(body: &str) -> bool {
    body.lines().any(|line| {
        let t = line.trim();
        if t.starts_with("movs") {
            return false; // movs* are string-move instructions, not what we want
        }
        if t.starts_with("mov") {
            // Intel syntax: `mov {size} PTR [...], 0`
            let intel = (t.contains("PTR") || t.contains("ptr"))
                && (t.ends_with(", 0") || t.ends_with(",0"));
            // AT&T syntax: `movb $0, ...` / `movl $0, ...` / `movq $0, ...`
            let att = t.contains("$0,") || t.contains("$0 ,") || t.ends_with("$0");
            return intel || att;
        }
        false
    })
}
