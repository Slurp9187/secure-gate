#!/usr/bin/env python3
"""Generate the oversized fuzz/robustness cases for the sweep-tool handover.

These four shapes were originally checked in as large generated files. They are
reproduced here byte-for-byte by a tiny stdlib-only script so the published set
stays small. Output goes to stdout; redirect into the matching filename.

Usage:
    python3 gen_cases.py big50                 > big50.rs       # 50 MB throughput
    python3 gen_cases.py backtrack             > backtrack.rs   # regex backtracking
    python3 gen_cases.py nest                  > nest.rs        # 20000 nested delimiters
    python3 gen_cases.py quad <N>              > quadN.rs       # N repeated bindings
                                                                # (375, 750, 1500, 3000)

Each shape is deterministic and has no randomness, so regenerated output is
identical to the originals (verify with `cmp`/`sha256sum`).
"""
import sys


def big50(out):
    # 50 MB of "lots of simple, correct code": one harmless call per line.
    out.write("fn f() {\n")
    line = "    d.with_secret_mut(|v| v.len());\n"
    for _ in range(1456356):
        out.write(line)
    out.write("}\n")


def backtrack(out):
    # 20 functions, each a single 200000-char identifier -> forces the scanner's
    # per-line regex to chew through a huge token (regex-backtracking case).
    for i in range(20):
        out.write("fn g%d() { let x = %s }\n" % (i, "a" * 200000))


def nest(out):
    # 20000 levels of nested vec![ ... ] delimiters on one line.
    out.write("fn h() { let v = ")
    out.write("vec![" * 20000)
    out.write("0u8")
    out.write("]" * 20000)
    out.write("; }\n")


def quad(out, n):
    # N bindings that each expose a secret -> drives the quadratic-runtime test.
    out.write("fn f(s: &mut Dynamic<Vec<u8>>) {\n")
    for i in range(n):
        out.write("    let v%d = s.expose_secret_mut();\n" % i)
    out.write("}\n")


def main(argv):
    if len(argv) < 2:
        sys.exit("usage: gen_cases.py {big50|backtrack|nest|quad N}")
    kind = argv[1]
    out = sys.stdout
    if kind == "big50":
        big50(out)
    elif kind == "backtrack":
        backtrack(out)
    elif kind == "nest":
        nest(out)
    elif kind == "quad":
        if len(argv) < 3:
            sys.exit("quad needs a count, e.g. gen_cases.py quad 375")
        quad(out, int(argv[2]))
    else:
        sys.exit("unknown kind: %s" % kind)


if __name__ == "__main__":
    main(sys.argv)
