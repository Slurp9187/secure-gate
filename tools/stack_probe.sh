#!/usr/bin/env bash
# Runs the sealed stack-residue probe (docs/design/receipts/sealed-stack-residue/) and
# fails if it finds the sealing key or the plaintext on the stack after a sealed access.
#
# It changes the working tree: it applies the probe hooks and copies the probes into
# tests/. Run it in a CI checkout or a scratch copy, never in a tree you work in.
#
# Two runs per profile (debug, release):
#   1. "scrub off": scrub_stack() emptied. The probe must find the key at least once, or
#      it is not looking where the cipher leaves it on this target, and a clean result
#      below would mean nothing.
#   2. As shipped: every key and plaintext "hits=" count must be 0.
#
# Usage: tools/stack_probe.sh   (from the repository root)
set -euo pipefail

R=docs/design/receipts/sealed-stack-residue
git apply "$R/probe_hooks.patch"
cp "$R"/probe_*.rs tests/

run() { # $1 = label, rest = cargo test profile flags
  local label=$1; shift
  echo "== $label" >&2
  cargo test -q "$@" --features sealed --test probe_stack --test probe_panic \
    -- --nocapture --test-threads=1 2>&1 | grep -E 'hits=' | tee /dev/stderr
}

PY=$(command -v python3 || command -v python)
fail=0
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
    echo "::error::$profile: with scrub_stack disabled the probe found no key copy, so it cannot see the region on this target (reach check failed)"
    fail=1
  fi

  on=$(run "as shipped, $profile" "${flags[@]}")
  # The control line counts a pattern the probe leaves on purpose; it is not a residue.
  if printf '%s\n' "$on" | grep -v '^control ' | grep -qE 'hits=[1-9]'; then
    echo "::error::$profile: sealing key or plaintext found on the stack after a sealed access"
    fail=1
  fi
done

exit "$fail"
