#!/usr/bin/env python3
"""
Release script for cpd-sec.

Usage:
    python scripts/release.py 0.10.2
    python scripts/release.py 0.11.0 --dry-run
"""
import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=ROOT, check=check, capture_output=True, text=True)


def current_version() -> str:
    text = PYPROJECT.read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        sys.exit("ERROR: version not found in pyproject.toml")
    return m.group(1)


def set_version(new: str) -> None:
    text = PYPROJECT.read_text()
    updated = re.sub(
        r'^(version\s*=\s*")[^"]+"',
        rf'\g<1>{new}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    PYPROJECT.write_text(updated)


def unreleased_section(changelog: str) -> str:
    """Extract content between [Unreleased] and the next ## header."""
    m = re.search(
        r"## \[Unreleased\]\n(.*?)(?=\n## \[|\Z)",
        changelog,
        re.DOTALL,
    )
    if not m:
        return ""
    return m.group(1).strip()


def update_changelog(new: str) -> None:
    text = CHANGELOG.read_text()
    today = date.today().isoformat()

    unreleased = unreleased_section(text)
    if not unreleased:
        print("  WARNING: [Unreleased] section is empty — release entry will have no notes.")

    # Locate the whole Unreleased block: header, body, up to the next release
    # header (or EOF). Rewriting it in one shot moves the body into the new
    # release entry and leaves Unreleased empty.
    m = re.search(r"## \[Unreleased\]\n(.*?)(?=\n## \[|\Z)", text, re.DOTALL)
    if not m:
        sys.exit("ERROR: [Unreleased] section not found in CHANGELOG.md")

    new_entry = f"## [{new}] - {today}\n"
    if unreleased:
        new_entry += f"\n{unreleased}\n"

    updated = text[: m.start()] + f"## [Unreleased]\n\n{new_entry}" + text[m.end() :]

    CHANGELOG.write_text(updated)


def git_clean() -> bool:
    r = run(["git", "status", "--porcelain"], check=False)
    # Lines starting with "??" are untracked files — irrelevant for a release.
    dirty = [l for l in r.stdout.splitlines() if not l.startswith("??")]
    return len(dirty) == 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Release cpd-sec to a new version.")
    parser.add_argument("version", help="New version, e.g. 0.10.2")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without making changes.")
    args = parser.parse_args()

    new_ver = args.version.lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", new_ver):
        sys.exit(f"ERROR: version must be X.Y.Z, got '{new_ver}'")

    old_ver = current_version()
    tag = f"v{new_ver}"

    print(f"\ncpd-sec release: {old_ver} → {new_ver}")
    print(f"Tag: {tag}\n")

    # Guard: check working tree has no staged/modified tracked files
    if not git_clean():
        result = run(["git", "status", "--porcelain"], check=False)
        dirty = [l for l in result.stdout.splitlines() if not l.startswith("??")]
        print("\n".join(dirty))
        if not args.dry_run:
            sys.exit("ERROR: tracked files have uncommitted changes. Commit or stash first.")
        print("  (dry-run: would abort here)\n")

    # Guard: tag must not already exist
    tags = run(["git", "tag"], check=False).stdout.splitlines()
    if tag in tags:
        sys.exit(f"ERROR: tag {tag} already exists.")

    if args.dry_run:
        print("[dry-run] Would update pyproject.toml version")
        print("[dry-run] Would update CHANGELOG.md")
        print(f"[dry-run] Would commit: 'Release {tag}'")
        print(f"[dry-run] Would tag: {tag}")
        print("[dry-run] Would push branch + tag")
        return

    print("1. Updating pyproject.toml ...")
    set_version(new_ver)

    print("2. Updating CHANGELOG.md ...")
    update_changelog(new_ver)

    print("3. Staging files ...")
    run(["git", "add", "pyproject.toml", "CHANGELOG.md"])

    print(f"4. Committing ...")
    run(["git", "commit", "-m", f"Release {tag}"])

    print(f"5. Creating annotated tag {tag} ...")
    run(["git", "tag", "-a", tag, "-m", f"Release {tag}"])

    print("6. Pushing branch ...")
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    run(["git", "push", "origin", f"{branch}:master"])

    print(f"7. Pushing tag {tag} ...")
    run(["git", "push", "origin", tag])

    print(f"\nDone. Released {tag}.")


if __name__ == "__main__":
    main()
