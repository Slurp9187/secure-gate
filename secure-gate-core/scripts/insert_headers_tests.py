# insert_header_tests.py   ← save this anywhere in your repo (even in scripts/)
import pathlib


def make_header(rel_path: str) -> str:
    border = "// " + "=" * 74
    return f"{border}\n// {rel_path}\n{border}\n\n"


def main():
    # Find the repo root (the folder that contains the "tests" directory)
    current = pathlib.Path(__file__).resolve().parent

    # Walk upwards until we find the folder that has a "tests" subfolder
    root = None
    for parent in [current, *current.parents]:
        if (parent / "tests").exists() and (parent / "tests").is_dir():
            root = parent
            break

    if root is None:
        print("Error: Could not find a 'tests' directory in this project!")
        return

    tests = root / "tests"
    print(f"Found project root: {root}\nAdding headers in {tests} ...\n")

    for file in tests.rglob("*.rs"):
        rel_path = file.relative_to(root).as_posix()
        desired_header = make_header(rel_path)

        content = file.read_text(encoding="utf-8")

        if content.startswith(desired_header):
            print(f"Already perfect → {rel_path}")
            continue

        # Be tolerant of tiny formatting differences
        stripped = content.lstrip()
        if stripped.startswith(f"// {'='*74}\n// {rel_path}\n// {'='*74}"):
            print(f"Already good (minor diff) → {rel_path}")
            continue

        file.write_text(desired_header + content, encoding="utf-8")
        print(f"Added header    → {rel_path}")


if __name__ == "__main__":
    main()
    print("\nAll done — every .rs file now has a beautiful header!")
