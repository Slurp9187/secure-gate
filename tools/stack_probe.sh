#!/usr/bin/env bash
# Runs the sealed stack-residue probe (docs/design/receipts/sealed-stack-residue/) and
# fails if it finds the sealing key or the plaintext on the stack after a sealed access.
#
# It changes the working tree: it applies the probe hooks and copies the probes into
# tests/. Run it in a CI checkout or a scratch copy, never in a tree you work in.
#
# Two runs per profile:
#   1. "scrub off": scrub_stack() emptied. The probe must find the key copy the cipher
#      leaves, or it cannot see the stack region in that profile on this target, and a
#      clean result as shipped would show nothing. That fails the run.
#   2. As shipped: every key and plaintext "hits=" count must be 0, with one exception
#      below.
#
# The profiles come from STACK_PROBE_PROFILES (default "debug release"). The workflow
# drops a profile only where it is known to be out of reach (Linux ARM64 release).
#
# The one count not gated: the plaintext count on the "unseal, result dropped" line.
# SealedFixed::unseal returns an ordinary Fixed by value, and a by-value return can
# leave a stack copy in the caller's frames, which the sealed scrub does not reach and
# SECURITY.md lists as not covered. The line is still printed; its key count is gated.
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
  # Printed to stderr for the log and to stdout for the caller. Not `tee /dev/stderr`:
  # the Windows runner's bash has no /dev/stderr, and the log then shows no counts.
  local hits
  hits=$( (grep -E 'hits=' "$log" || true) | tr -d '\r')
  rm -f "$log"
  printf '%s\n' "$hits" >&2
  printf '%s\n' "$hits"
}

# The key count of the probe's one `with_secret:` line, or nothing if there is not
# exactly one such line holding exactly one integer.
key_hits() {
  local lines
  lines=$(printf '%s\n' "$1" | grep -E '^with_secret: ' || true)
  [ "$(printf '%s' "$lines" | grep -c '')" -eq 1 ] || return 0
  printf '%s\n' "$lines" | sed -nE 's/^with_secret: key hits=([0-9]+) plaintext hits=[0-9]+$/\1/p'
}

PY=$(command -v python3 || command -v python)
fail=0
for profile in ${STACK_PROBE_PROFILES:-debug release}; do
  case $profile in
    debug) flags=() ;;
    release) flags=(--release) ;;
    *) echo "::error::unknown profile '$profile' in STACK_PROBE_PROFILES"; exit 1 ;;
  esac

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

  reach=$(key_hits "$off")
  if [ -z "$reach" ] || [ "$reach" -eq 0 ]; then
    echo "::error::$profile: out of reach. With scrub_stack disabled the probe found no key copy (or no single count), so it cannot see where the cipher leaves one in this profile on this target"
    fail=1
  fi

  on=$(run "as shipped, $profile" "${flags[@]}")
  if [ -z "$(key_hits "$on")" ]; then
    echo "::error::$profile: as shipped, the probe printed no single with_secret count, so this run shows nothing"
    fail=1
  fi
  # The control line counts a pattern the probe leaves on purpose; it is not a residue.
  # The unseal line's plaintext count is the by-value return described above.
  if printf '%s\n' "$on" | grep -v '^control ' |
    sed -E '/unseal, result dropped:/s/ plaintext hits=[0-9]+//' | grep -qE 'hits=[1-9]'; then
    echo "::error::$profile: sealing key or plaintext found on the stack after a sealed access"
    fail=1
  fi
done

exit "$fail"
