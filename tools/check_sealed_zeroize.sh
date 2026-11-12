#!/usr/bin/env bash
# Fails if a dependency of the `sealed` feature that holds key, keystream, MAC or hash state
# is built without its `zeroize` feature.
#
# The Cargo.toml comment above the `sealed` dependencies records the audit (rc.17): `zeroize`
# must be on for chacha20poly1305, chacha20, sha2, digest, block-buffer and poly1305, and is
# deliberately off for cipher, crypto-common and hybrid-array. Feature unification can change
# under a dependency update without any line here changing, so this script checks the
# resolved graph rather than the manifest:
#
#   1. every crate in REQUIRED is in the graph and has `zeroize` enabled;
#   2. every other crate in the graph that offers a `zeroize` feature has it enabled, or is
#      in ALLOWED_OFF. A new dependency with the flag off fails here until someone decides.
#
# Run from the repository root. Needs cargo and jq.
set -euo pipefail

REQUIRED=(chacha20poly1305 chacha20 sha2 digest block-buffer poly1305)
ALLOWED_OFF=(cipher crypto-common hybrid-array)

# Normal (non-dev) dependency graph of `sealed` alone, for every target, as "name version|features".
graph=$(cargo tree -p secure-gate -e normal --no-default-features --features sealed \
  --target all --prefix none --format '{p}|{f}' | sed 's/ (\*)$//; s/ ([^)]*)|/|/' | sort -u)

# "name version" of every package that declares a `zeroize` feature.
offers=$(cargo metadata --format-version 1 --no-default-features --features sealed |
  jq -r '.packages[] | select(.features | has("zeroize")) | "\(.name) v\(.version)"' | sort -u)

has_zeroize() { # $1 = "name version"
  local feats
  feats=$(printf '%s\n' "$graph" | awk -F'|' -v p="$1" '$1 == p { print $2 }')
  [[ ",$feats," == *",zeroize,"* ]]
}

fail=0
for name in "${REQUIRED[@]}"; do
  pkgs=$(printf '%s\n' "$graph" | awk -F'|' -v n="$name" 'split($1, a, " ") && a[1] == n { print $1 }')
  if [[ -z "$pkgs" ]]; then
    echo "::error::$name is no longer in the sealed dependency graph; review REQUIRED in $0 and the audit comment in Cargo.toml."
    fail=1
    continue
  fi
  while IFS= read -r pkg; do
    if has_zeroize "$pkg"; then
      echo "ok    $pkg: zeroize on"
    else
      echo "::error::$pkg is built without its zeroize feature."
      fail=1
    fi
  done <<< "$pkgs"
done

while IFS='|' read -r pkg _; do
  name=${pkg%% *}
  [[ " ${REQUIRED[*]} " == *" $name "* ]] && continue
  grep -qxF "$pkg" <<< "$offers" || continue
  if has_zeroize "$pkg"; then
    echo "ok    $pkg: zeroize on"
  elif [[ " ${ALLOWED_OFF[*]} " == *" $name "* ]]; then
    echo "off   $pkg: zeroize off, allowed (see Cargo.toml)"
  else
    echo "::error::$pkg offers a zeroize feature that the sealed graph leaves off. Turn it on, or add it to ALLOWED_OFF with the reason in Cargo.toml."
    fail=1
  fi
done <<< "$graph"

exit "$fail"
