#!/bin/sh

# =============================================================================
# test_all.sh — full feature-matrix test runner for secure-gate
#
# Mirrors the GitHub CI matrix from .github/workflows/ci.yml (as of 2026-03)
# Run this locally to reproduce CI coverage before pushing.
# =============================================================================

set -euo pipefail  # fail fast on errors / undefined vars

# Function to run tests for a given configuration
run_tests() {
  local name="$1"
  local features="$2"
  local status=0

  printf "\n%s\n" "═══════════════════════════════════════════════════════════════"
  printf "CONFIG: %s\n" "$name"
  if [ -n "$features" ]; then
    printf "  flags: %s\n" "$features"
  else
    printf "  flags: (default)\n"
  fi
  printf "%s\n\n" "═══════════════════════════════════════════════════════════════"

  # ── Clippy ───────────────────────────────────────────────────────────────
  printf "\033[1;36m[CLIPPY]\033[0m "
  if cargo clippy --tests --benches $features -- -D warnings >/dev/null 2>&1; then
    printf "\033[1;32mPASS\033[0m\n"
  else
    printf "\033[1;31mFAIL\033[0m\n"
    cargo clippy --tests --benches $features -- -D warnings
    status=1
  fi

  # ── Tests ────────────────────────────────────────────────────────────────
  printf "\033[1;36m[TESTS]\033[0m  "
  if cargo test --tests $features >/dev/null 2>&1; then
    printf "\033[1;32mPASS\033[0m\n"
  else
    printf "\033[1;31mFAIL\033[0m\n"
    cargo test --tests $features
    status=1
  fi

  # ── Doctests ─────────────────────────────────────────────────────────────
  printf "\033[1;36m[DOCTESTS]\033[0m "
  if cargo test --doc $features >/dev/null 2>&1; then
    printf "\033[1;32mPASS\033[0m\n"
  else
    printf "\033[1;31mFAIL\033[0m\n"
    cargo test --doc $features
    status=1
  fi

  # Final per-config verdict
  if [ $status -eq 0 ]; then
    printf "\n\033[1;32m✓ SUCCESS: %s passed (clippy + tests + doctests)\033[0m\n" "$name"
  else
    printf "\n\033[1;31m✗ FAILURE in %s\033[0m\n" "$name"
  fi

  return $status
}

echo "Starting local feature matrix test run..."
echo "Date: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo

# ── Baseline ────────────────────────────────────────────────────────────────
run_tests "Default features"               ""
run_tests "No features (Fixed-only)"       "--no-default-features"

# ── Alloc / std ─────────────────────────────────────────────────────────────
run_tests "alloc explicit"                 "--no-default-features --features=alloc"
run_tests "std explicit"                   "--no-default-features --features=std"

# ── Rand ────────────────────────────────────────────────────────────────────
# (rand always pulls alloc transitively)
run_tests "rand (includes alloc)"          "--no-default-features --features=rand"
run_tests "alloc + rand"                   "--no-default-features --features=alloc,rand"

# ── Constant-time equality ──────────────────────────────────────────────────
# (alloc needed for Dynamic<T> ct-eq tests)
run_tests "ct-eq + alloc"                  "--no-default-features --features=ct-eq,alloc"
run_tests "ct-eq-hash + alloc (unkeyed)"   "--no-default-features --features=ct-eq-hash,alloc"
run_tests "ct-eq-hash + alloc + rand (keyed)" "--no-default-features --features=ct-eq-hash,alloc,rand"

# ── Encoding ────────────────────────────────────────────────────────────────
run_tests "encoding (all formats)"         "--no-default-features --features=encoding"
run_tests "encoding-hex only"              "--no-default-features --features=encoding-hex"
run_tests "encoding-base64 only"           "--no-default-features --features=encoding-base64"
run_tests "encoding-bech32 only"           "--no-default-features --features=encoding-bech32"
run_tests "encoding-bech32m only"          "--no-default-features --features=encoding-bech32m"
run_tests "encoding-bech32 + bech32m"      "--no-default-features --features=encoding-bech32,encoding-bech32m"

# ── Serde ───────────────────────────────────────────────────────────────────
run_tests "serde (serialize + deserialize)" "--no-default-features --features=serde"
run_tests "serde-serialize only"           "--no-default-features --features=serde-serialize"
run_tests "serde-deserialize only"         "--no-default-features --features=serde-deserialize"

# ── Cloneable ───────────────────────────────────────────────────────────────
run_tests "alloc + cloneable"              "--no-default-features --features=alloc,cloneable"

# ── Full batteries-included ─────────────────────────────────────────────────
run_tests "full"                           "--features=full"

echo
echo "───────────────────────────────────────────────"
echo "All matrix configurations completed successfully."
echo "Local run matches current GitHub CI coverage."
