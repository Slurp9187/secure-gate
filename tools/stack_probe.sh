#!/usr/bin/env bash
# Runs the sealed stack-residue probe (docs/design/receipts/sealed-stack-residue/) and
# fails if it finds the sealing key or the plaintext on the stack after a sealed access.
#
# It changes the working tree: it applies the probe hooks and copies the probes into
# tests/. Run it in a CI checkout or a scratch copy, never in a tree you work in.
#
# Two runs per profile (debug, release):
#   1. "scrub off": scrub_stack() emptied. If the probe finds no key here, it cannot see
#      where the cipher leaves it in that profile on this target, and the clean result
#      below shows nothing. That profile is reported as inconclusive (a warning), not
#      as a pass. On Linux ARM64 the release build leaves no key in reach even then.
#   2. As shipped: every key and plaintext "hits=" count must be 0.
#
# Fails if a key or plaintext copy is found as shipped, or if neither profile is in reach
# (the probe would then show nothing at all on this target).
#
# Usage: tools/stack_probe.sh   (from the repository root)
set -euo pipefail

# The probe hooks and the emptied scrub leave unused items, and CI sets RUSTFLAGS to
# `-D warnings`. A warning here is not a finding, so it must not stop the build.
export RUSTFLAGS=""

R=docs/design/receipts/sealed-stack-residue
git apply "$R/probe_hooks.patch"
cp "$R"/probe_*.rs tests/

run() { # $1 = label, rest = cargo test profile flags. Prints the probe's "hits=" lines.
  local label=$1; shift
  local log
  log=$(mktemp)
  echo "== $label" >&2
  if ! cargo test -q "$@" --features sealed --test probe_stack --test probe_panic \
    -- --nocapture --test-threads=1 >"$log" 2>&1; then
    cat "$log" >&2
    echo "::error::$label: the probe did not build or run (full output above)" >&2
    rm -f "$log"
    return 1
  fi
  grep -E 'hits=' "$log" | tee /dev/stderr
  rm -f "$log"
}

PY=$(command -v python3 || command -v python)
fail=0
reached=0
for profile in debug release; do
  flags=()
  [ "$profile" = release ] && flags=(--release)

  cp src/sealed/prekey.rs /tmp/prekey.rs.shipped
  # Empty scrub_stack's body. The match is exact so a rename fails loudly here.
  "$PY" - <<'EOF'
p = "src/sealed/prekey.rs"
s = open(p).read()
body = """    let mut area = [0u64; SCRUB_LEN / 8];
    area.zeroize();
    core::hint::black_box(&area);"""
if s.count(body) != 1:
    raise SystemExit("stack_probe: scrub_stack body not found; update this script")
open(p, "w").write(s.replace(body, "    // stack_probe: scrub disabled"))
EOF
  off=$(run "scrub off, $profile" "${flags[@]}")
  cp /tmp/prekey.rs.shipped src/sealed/prekey.rs

  reach=$(printf '%s\n' "$off" | grep -E '^with_secret: ' | sed -E 's/.*key hits=([0-9]+).*/\1/')
  if [ -z "$reach" ] || [ "$reach" -eq 0 ]; then
    echo "::warning::$profile: inconclusive. With scrub_stack disabled the probe found no key copy, so it cannot see where the cipher leaves one in this profile on this target"
  else
    reached=$((reached + 1))
  fi

  on=$(run "as shipped, $profile" "${flags[@]}")
  # The control line counts a pattern the probe leaves on purpose; it is not a residue.
  if printf '%s\n' "$on" | grep -v '^control ' | grep -qE 'hits=[1-9]'; then
    echo "::error::$profile: sealing key or plaintext found on the stack after a sealed access"
    fail=1
  fi
done

if [ "$reached" -eq 0 ]; then
  echo "::error::neither profile is in reach on this target, so the probe shows nothing here"
  fail=1
fi

exit "$fail"
