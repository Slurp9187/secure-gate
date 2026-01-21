#!/usr/bin/env python3
"""
package_it.py – FINAL BULLETPROOF VERSION (2025)
Safe, beautiful, sortable code packages – will never nuke your .git again.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# ========================== CONFIGURATION ==========================
PROJECT_TITLE = "secure-gate"
OUTPUT_DIR = "code_packages"
ENCODING = "utf-8"
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
OUTPUT_TIMESTAMP_FORMAT = "%Y%m%d_%H%M%S"

# ========================== SAFETY FIRST ==========================


def die(msg: str):
    print(f"FATAL: {msg}", file=sys.stderr, flush=False)
    sys.exit(1)


# Block any attempt to write into .git (even via symlinks)
output_path = Path.cwd().resolve() / OUTPUT_DIR
git_path = Path.cwd().resolve() / ".git"
try:
    if output_path.resolve().is_relative_to(git_path):
        die("Refusing to run: output directory would land inside .git!")
except Exception:
    pass  # Windows sometimes throws on broken symlinks

# =================================================================


def find_project_root(start: Optional[Path] = None) -> Path:
    cur = Path(start or __file__).resolve().parent
    while cur != cur.parent:
        if (cur / "Cargo.toml").exists():
            return cur
        cur = cur.parent
    die("Could not find project root (no Cargo.toml in parent directories)")


PROJECT_ROOT = find_project_root()

# =================================================================
PACKAGES = [
    {
        "suffix": "docs",
        "root_files": [
            "CHANGELOG.md",
            "README.md",
            "ROADMAP.md",
            "SECURITY.md",
        ],
        "include_dirs": [],
        "file_pattern": "*.md",
        "description": "Full documentation source",
    },
    {
        "suffix": "src",
        "root_files": [
            "Cargo.toml",
            # "CHANGELOG.md",
            # "README.md",
            # "ROADMAP.md",
            # "SECURITY.md",
        ],
        "include_dirs": ["src"],
        "file_pattern": "*.rs",
        "description": "Full library source + Cargo.toml",
    },
    {
        "suffix": "tests",
        "root_files": [],
        "include_dirs": ["tests"],
        "file_pattern": "*.rs",
        "description": "All integration tests",
    },
    {
        "suffix": "fuzz",
        "root_files": [
            "fuzz/Cargo.toml",
            ".github/workflows/fuzz-miri.yml",
            ".github/workflows/fuzz-nightly.yml",
            ".github/workflows/fuzz-quick.yml",
        ],
        "include_dirs": ["fuzz/fuzz_targets"],
        "file_pattern": "*.rs",
        "description": "Fuzzing targets",
    },
    # {
    #     "suffix": "mod",
    #     "root_files": [],
    #     "include_dirs": ["src", "tests"],
    #     "file_pattern": "mod.rs",
    #     "description": "Only mod.rs files from src/ and tests/ (module structure overview)",
    # },
    {
        "suffix": "benches",
        "root_files": [],
        "include_dirs": ["benches"],
        "file_pattern": "*.rs",
        "description": "benches (benchmarking)",
    },
]

# =================================================================


def format_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime(TIMESTAMP_FORMAT)[:-3]


def format_output_timestamp() -> str:
    return datetime.now().strftime(OUTPUT_TIMESTAMP_FORMAT)


def add_file(contents: list[str], toc: list[str], file_path: Path, root: Path) -> None:
    rel_path = file_path.relative_to(root).as_posix()
    content = file_path.read_text(encoding=ENCODING)
    ctime = format_timestamp(file_path.stat().st_ctime)
    mtime = format_timestamp(file_path.stat().st_mtime)
    idx = len(toc) + 1

    header = (
        f"\n\n\n================================================================================\n"
        f"// SECTION {idx:03d}: {rel_path}\n"
        f"// Created:  {ctime}\n"
        f"// Modified: {mtime}\n"
        f"================================================================================\n"
    )
    contents.append(header + content.rstrip() + "\n")
    toc.append(rel_path)


def create_package(pkg_def: dict, root: Path, timestamp: str) -> None:
    suffix = pkg_def["suffix"]
    description = pkg_def["description"]
    pattern = pkg_def["file_pattern"]

    out_dir = root / OUTPUT_DIR
    out_dir.mkdir(exist_ok=True)

    output_filename = f"{timestamp}_{PROJECT_TITLE}_{suffix}.txt"
    output_path = out_dir / output_filename

    file_contents: list[str] = []
    toc_entries: list[str] = []
    seen_paths = set()

    # Root files
    for f in pkg_def["root_files"]:
        p = root / f
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            if rel not in seen_paths:
                add_file(file_contents, toc_entries, p, root)
                seen_paths.add(rel)

    # Recursive file collection
    for base_dir_name in pkg_def["include_dirs"]:
        base_dir = root / base_dir_name
        if not base_dir.exists():
            print(f"  Warning: Directory not found: {base_dir}")
            continue
        for rs_file in sorted(
            base_dir.rglob(pattern),
            key=lambda p: p.relative_to(root).as_posix().lower(),
        ):
            rel = rs_file.relative_to(root).as_posix()
            if rel not in seen_paths:
                add_file(file_contents, toc_entries, rs_file, root)
                seen_paths.add(rel)

    # Build TOC
    toc_lines = [
        "// ============================================================================\n",
        "// TABLE OF CONTENTS\n",
        "// ============================================================================\n",
    ]
    for i, entry in enumerate(toc_entries, 1):
        toc_lines.append(f"// {i:03d}. {entry}\n")
    if not toc_entries:
        toc_lines.append("// (no files included)\n")
    toc_lines.append(
        "// ============================================================================\n\n"
    )

    # Write final file
    with output_path.open("w", encoding=ENCODING) as f:
        header_time = format_timestamp(datetime.now().timestamp())
        f.write(
            "// ============================================================================\n"
        )
        f.write(f"// {PROJECT_TITLE} – {description}\n")
        f.write(f"// Generated by: {Path(__file__).name}\n")
        f.write(f"// Generated at: {header_time}\n")
        f.write(
            "// ============================================================================\n\n"
        )
        f.writelines(toc_lines)
        f.writelines(file_contents)

    print(f"  → {output_filename}  ({len(file_contents)} sections)")


def package_all(root: Path = PROJECT_ROOT) -> None:
    root = root.resolve()
    timestamp = format_output_timestamp()
    print(f"Project root: {root}")
    print(f"Timestamp prefix: {timestamp}\n")

    for pkg in PACKAGES:
        print(f"Creating {PROJECT_TITLE}_{pkg['suffix']} package...")
        create_package(pkg, root, timestamp)

    print(f"\nAll packages created in ./{OUTPUT_DIR}/\n")
    print("Done – your code is now beautifully archived and safe!")


# =================================================================
if __name__ == "__main__":
    override_root: Optional[Path] = None
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if not arg.startswith("--"):
            override_root = Path(arg).resolve()
            if not override_root.exists():
                die(f"Override root does not exist: {override_root}")

    effective_root = override_root or PROJECT_ROOT
    if override_root:
        print(f"Using override root: {override_root}\n")

    if not (effective_root / "Cargo.toml").exists():
        die(f"No Cargo.toml found in {effective_root} – are you in the right project?")

    package_all(effective_root)
