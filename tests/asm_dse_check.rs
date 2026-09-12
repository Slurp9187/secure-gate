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
//! The stores do not have to be in that body. LLVM decides whether to inline the
//! drop glue, and it changes its mind: under zeroize 1.9 the glue carries an
//! `asm!` barrier per element and stays out of line, so the wrapper is reduced to
//! a `callq core::ptr::drop_glue::<Fixed<[u8; 32]>>`. The assertion therefore
//! walks the drop path — the symbol, then any drop glue it calls — and passes at
//! the first body that still has its stores. What is being guarded is that the
//! volatile writes survive optimization, not where they land.
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

/// How far the drop-path walk follows calls to drop glue.
///
/// Whether the glue is inlined into the caller is LLVM's choice and it has
/// already flipped once: zeroize 1.9 replaced the per-element
/// `compiler_fence(SeqCst)` with an `asm!` barrier, and a body carrying 32
/// inline-asm blocks is no longer cheap enough to inline, so the stores moved
/// from `make_and_drop_fixed` into an out-of-line
/// `core::ptr::drop_glue::<Fixed<[u8; 32]>>`.
///
/// Following the call is not a weakening of the guard. What this test proves is
/// that the volatile stores still exist somewhere the drop reaches — DSE
/// deleting them is the regression, an inlining decision is not. The walk only
/// ever steps into symbols whose names identify them as drop glue, so it cannot
/// wander off and credit an unrelated function's stores.
///
/// One hop is what today's codegen needs; the headroom covers glue that defers
/// to a nested field's glue.
const MAX_GLUE_HOPS: usize = 4;

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

    // Both symbols must keep their stores: the plain wrapper, and the
    // `fixed_newtype!`-generated newtype over it. The newtype is
    // `#[repr(transparent)]` and adds no `Drop` of its own, so an extra
    // nominal layer must not cost the zeroization guarantee.
    for symbol in [
        "make_and_drop_fixed",
        "make_and_drop_newtype",
        "make_and_drop_generic_newtype",
    ] {
        assert_zero_stores_present(&asm, &asm_path, symbol);
    }
}

/// Asserts that the zero-store instructions survive somewhere on `symbol`'s
/// drop path.
///
/// Two indirections are followed before the assertion gives up:
///
/// **Identical-code folding.** If the symbol was folded into another — LLVM
/// emits `.set <symbol>, <target>` — the walk starts at the fold target. For the
/// newtype that outcome is the *strongest* possible result: it proves the
/// generated wrapper compiles to byte-identical code, not merely to equivalent
/// code.
///
/// **Out-of-line drop glue.** If a body holds no stores but calls drop glue, the
/// walk continues into the glue. See the note on [`MAX_GLUE_HOPS`] for why that
/// is not a weakening of the guard.
fn assert_zero_stores_present(asm: &str, asm_path: &std::path::Path, symbol: &str) {
    let entry = resolve_symbol_alias(asm, symbol);
    if entry != symbol {
        println!(
            "note: `{symbol}` was folded into `{entry}` (identical codegen) — \
             asserting against the fold target"
        );
    }

    // Breadth-first over {entry symbol} ∪ {drop glue it reaches}, stopping at the
    // first body that still has its stores.
    let mut inspected: Vec<(String, String)> = Vec::new();
    let mut undefined: Vec<String> = Vec::new();
    let mut frontier = vec![entry.clone()];

    for _hop in 0..=MAX_GLUE_HOPS {
        if frontier.is_empty() {
            break;
        }
        let mut next: Vec<String> = Vec::new();
        for name in frontier.drain(..) {
            if inspected.iter().any(|(seen, _)| *seen == name) {
                continue;
            }
            let Some(body) = extract_function_body(asm, &name) else {
                // The entry symbol is `#[no_mangle]`d and defined in the crate
                // under compilation, so its absence is a harness failure, not a
                // zeroization verdict. A callee's absence is reported below.
                assert!(
                    name != entry,
                    "could not find '{name}' label in {}\n\
                     First 40 lines of assembly:\n{}",
                    asm_path.display(),
                    asm.lines().take(40).collect::<Vec<_>>().join("\n")
                );
                undefined.push(name);
                continue;
            };
            if has_zero_store(&body) {
                if name != entry {
                    println!(
                        "note: `{entry}` calls out to `{name}` for its drop glue — \
                         asserting the zero-stores there"
                    );
                }
                return;
            }
            for callee in drop_glue_callees(&body) {
                next.push(resolve_symbol_alias(asm, &callee));
            }
            inspected.push((name, body));
        }
        frontier = next;
    }

    let mut report = String::new();
    for (name, body) in &inspected {
        report.push_str(&format!(
            "\n{name}:\n\
             ─────────────────────────────────────────────\n\
             {body}\n\
             ─────────────────────────────────────────────\n"
        ));
    }
    if !undefined.is_empty() {
        report.push_str(&format!(
            "\nDrop glue called but not defined in this assembly, so its body could \
             not be checked (this is a limitation of the guard, not itself a \
             regression):\n  {}\n",
            undefined.join("\n  ")
        ));
    }

    panic!(
        "ZEROIZATION REGRESSION DETECTED\n\n\
         No volatile zero-store instructions were found on the drop path of \
         {symbol}.\n\
         LLVM may have eliminated the zeroization writes via dead-store elimination.\n\n\
         Assembly file : {}\n\n\
         Inspected {} function bod{}:\n{report}",
        asm_path.display(),
        inspected.len(),
        if inspected.len() == 1 { "y" } else { "ies" },
    );
}

/// Returns `true` if `body` contains a recognizable store-to-zero.
///
/// LLVM may codegen 32 volatile byte-writes as any of:
///
///   (a) SSE:  xorps/pxor to zero xmm0, then movaps/movups/movdqa/movdqu x2
///   (b) AVX:  vxorps/vpxor + vmovaps/vmovups x2
///   (c) Scalar 8-byte: mov QWORD PTR [...], 0  x4
///   (d) Scalar 1-byte: mov BYTE PTR  [...], 0  x32
///   (e) Rep string:    xor eax,eax / rep stosb
///
/// The check is deliberately broad: any of these confirms the stores survived.
/// The failure mode guarded against is *none* being present.
fn has_zero_store(body: &str) -> bool {
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

    let has_scalar_zero = has_mov_zero_pattern(body);

    let has_rep_stos = body.contains("rep") && body.contains("stos");

    has_sse_zero || has_scalar_zero || has_rep_stos
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Direct `call`/`jmp` targets of `body` that name drop glue.
///
/// rustc emits AT&T syntax on every x86_64 target this test runs on —
/// `*-pc-windows-msvc` included — so the operand is the bare symbol. Indirect
/// targets (`callq *%rax`) are skipped: there is no symbol to follow.
///
/// Both mangling schemes spell the function recognizably: v0 renders
/// `core::ptr::drop_glue` as `...9drop_glue...`, legacy renders
/// `core::ptr::drop_in_place` as `...drop_in_place...`.
fn drop_glue_callees(body: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for line in body.lines() {
        let mut tokens = line.split_whitespace();
        let Some(mnemonic) = tokens.next() else {
            continue;
        };
        if !matches!(mnemonic, "call" | "callq" | "jmp" | "jmpq") {
            continue;
        }
        let Some(target) = tokens.next() else {
            continue;
        };
        if target.starts_with('*') {
            continue; // indirect call through a register or memory operand
        }
        if (target.contains("drop_glue") || target.contains("drop_in_place"))
            && !targets.iter().any(|seen| seen == target)
        {
            targets.push(target.to_owned());
        }
    }
    targets
}

/// Follows an assembler alias for `symbol`, if present.
///
/// LLVM's identical-code folding emits one when two functions compile to the
/// same machine code — which is exactly what happens for a
/// `#[repr(transparent)]` newtype that adds no `Drop` of its own. The directive
/// has two spellings, and the toolchain picks one:
///
/// - `.set <symbol>, <target>` — rustc 1.85 and earlier LLVMs, on ELF and COFF
/// - `<symbol> = <target>`      — rustc 1.98 (LLVM 22), on ELF and COFF alike
///
/// Both are followed. Missing either one makes the fold look like a missing
/// symbol, which is how the 1.98 upgrade first showed up: every DSE job failed
/// with "could not find 'make_and_drop_newtype' label".
fn resolve_symbol_alias(asm: &str, symbol: &str) -> String {
    let set_form = format!(".set {symbol},");
    let eq_form = format!("{symbol} =");
    for line in asm.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(&set_form) {
            return rest.trim().to_string();
        }
        if let Some(rest) = line.strip_prefix(&eq_form) {
            return rest.trim().to_string();
        }
    }
    symbol.to_string()
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
