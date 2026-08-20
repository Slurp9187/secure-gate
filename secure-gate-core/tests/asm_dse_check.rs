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
//! The assembly is emitted to an explicit path (`--emit=asm=<path>` under the
//! target directory) and that path is deleted before the build. Cargo's
//! intermediate-artifact layout is not a stable interface — nightly moved these
//! artifacts out of `target/release/deps/` — and searching for the `.s` file
//! risks reading a stale one from an earlier build, which would make this guard
//! assert against the wrong compilation.
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
//! The test shells out to Cargo and rebuilds the binary every run (~10 s) so it
//! is marked `#[ignore]` to keep `cargo test` fast by default. Run explicitly:
//!
//! ```text
//! cargo test -p secure-gate --release --test asm_dse_check -- --ignored --nocapture
//! ```

#![cfg(target_arch = "x86_64")]
#![cfg(not(miri))] // test shells out to cargo; Miri cannot handle that

use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "triggers a full release build; run with --ignored in CI or manually"]
fn fixed_drop_emits_volatile_zero_stores() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Emit the assembly to a path we choose rather than guessing where Cargo
    // put it.
    //
    // Cargo's intermediate-artifact layout is not a stable interface. This test
    // used to glob `target/release/deps/asm_check*.s`, which broke when nightly
    // moved intermediate artifacts to `target/release/build/<pkg>/<hash>/out/`.
    // The silent-failure mode was worse than the loud one: when an earlier build
    // had left a `.s` behind in `deps/`, the glob found that *stale* file and the
    // test happily asserted against assembly from a different compilation.
    //
    // `--emit=asm=<path>` is a stable rustc CLI form and accumulates with the
    // `--emit` flags Cargo passes itself, so this works under either layout.
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest_dir
                .parent() // workspace root
                .expect("manifest_dir has no parent")
                .join("target")
        });
    std::fs::create_dir_all(&target_dir)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", target_dir.display()));
    let asm_path = target_dir.join("dse_check_asm_check.s");

    // Build into an isolated, wiped target directory.
    //
    // Without this the build is not guaranteed to happen at all: if Cargo
    // considers `asm_check` fresh (identical flags since the last run, or a
    // warm CI cache) it skips the compile, no assembly is emitted, and the
    // result depends on whatever happens to be on disk. Wiping a dedicated
    // tree makes the emission unconditional and independent of cache state.
    //
    // This is also *cheaper* than sharing the main target dir: only
    // `asm_check`'s real dependencies get built here, not the dev-dependencies
    // (criterion, proptest, trybuild) that dominate a workspace release build.
    let build_dir = target_dir.join("dse-check");
    match std::fs::remove_dir_all(&build_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("failed to clear {}: {e}", build_dir.display()),
    }
    let build_dir = build_dir
        .to_str()
        .expect("build dir path is not valid UTF-8")
        .to_owned();

    // Remove any previous emission too, so a leftover file from an earlier run
    // (or an earlier toolchain) cannot be mistaken for this build's output.
    match std::fs::remove_file(&asm_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("failed to clear {}: {e}", asm_path.display()),
    }

    // Use `cargo rustc` so `--emit=asm` only applies to the final crate (the
    // binary) rather than to every dependency, which would emit a `.s` per
    // crate and force all of them to recompile.
    let status = Command::new(env!("CARGO"))
        .current_dir(&manifest_dir)
        .args([
            "rustc",
            "--release",
            "--bin",
            "asm_check",
            // The binary declares required-features = ["std"] so it is skipped
            // in no_std target builds; enable the feature explicitly here.
            "--features",
            "std",
            "--target-dir",
            &build_dir,
            "--",
            &format!("--emit=asm={}", asm_path.display()),
        ])
        .status()
        .expect("failed to invoke cargo");

    assert!(
        status.success(),
        "cargo rustc --release --bin asm_check failed"
    );

    assert!(
        asm_path.is_file(),
        "cargo reported success but no assembly was emitted at {}\n\
         The `--emit=asm=<path>` form may no longer be honoured by rustc.",
        asm_path.display()
    );

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
