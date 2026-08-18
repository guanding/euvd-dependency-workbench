#!/usr/bin/env python3
"""Build a public-source candidate from an explicit allowlist.

This file is intentionally dependency-free and fail-closed. It never copies a
working directory wholesale, includes only allowlisted tracked/non-ignored
files, blocks common private runtime formats, and writes an exact SHA-256
manifest. ``--strict`` additionally enforces the public-source license,
rights, and clean-worktree gates. It does not approve binary artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = Path(__file__).with_name("public_files.txt")
BLOCKED_ANY_PART = {
    ".git",
    ".serena",
    ".venv",
    ".cache",
    "__pycache__",
}
BLOCKED_TOP_LEVEL = {
    "backups",
    "data",
    "evidence",
    "outputs",
    "runtime",
    "self-test",
}
BLOCKED_SUFFIXES = {
    ".db",
    ".dump",
    ".key",
    ".p12",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".xls",
    ".xlsm",
    ".xlsx",
}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".cmd",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
LOCAL_MARKERS = (
    "/" + "Users/",
    "C:" + "\\Users\\",
    "@oai/" + "artifact-tool",
)
SECRET_PATTERNS = (
    re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[opsu]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
APACHE_2_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
EXPECTED_COPYRIGHT_NOTICE = "Copyright 2026 Ding Guan"


def _git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=REPO_ROOT, text=True, encoding="utf-8"
    ).strip()


def _candidate_paths() -> list[PurePosixPath]:
    raw = subprocess.check_output(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        cwd=REPO_ROOT,
    )
    return sorted(
        (PurePosixPath(item.decode("utf-8")) for item in raw.split(b"\0") if item),
        key=str,
    )


def _load_rules() -> tuple[tuple[str, ...], tuple[str, ...]]:
    includes: list[str] = []
    excludes: list[str] = []
    for raw in RULES_PATH.read_text(encoding="utf-8").splitlines():
        rule = raw.strip()
        if not rule or rule.startswith("#"):
            continue
        if rule.startswith("!"):
            excludes.append(rule[1:])
        else:
            includes.append(rule)
    if not includes:
        raise RuntimeError("public allowlist is empty")
    return tuple(includes), tuple(excludes)


def _matches(path: str, rule: str) -> bool:
    return path.startswith(rule) if rule.endswith("/") else path == rule


def _selected_paths() -> list[PurePosixPath]:
    includes, excludes = _load_rules()
    selected: list[PurePosixPath] = []
    for rel in _candidate_paths():
        value = rel.as_posix()
        if not any(_matches(value, rule) for rule in includes):
            continue
        if any(_matches(value, rule) for rule in excludes):
            continue
        if any(part in BLOCKED_ANY_PART for part in rel.parts) or (
            rel.parts and rel.parts[0] in BLOCKED_TOP_LEVEL
        ):
            raise RuntimeError(f"blocked path entered public set: {value}")
        if rel.suffix.lower() in BLOCKED_SUFFIXES:
            raise RuntimeError(f"blocked file type entered public set: {value}")
        source = REPO_ROOT / rel
        if source.is_symlink():
            raise RuntimeError(f"symlink is not allowed in public set: {value}")
        if source.is_file():
            selected.append(rel)
    return selected


def _scan_text(rel: PurePosixPath) -> list[str]:
    if rel.suffix.lower() not in TEXT_SUFFIXES:
        return []
    content = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
    findings: list[str] = []
    for marker in LOCAL_MARKERS:
        if marker in content:
            findings.append(f"local/private marker {marker!r}")
    for pattern in SECRET_PATTERNS:
        if pattern.search(content):
            findings.append(f"high-signal secret pattern {pattern.pattern!r}")
    return findings


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rights_pending(output: Path) -> bool:
    notices = output / "THIRD_PARTY_NOTICES.md"
    rights_review = output / "release" / "rights_review.json"
    if not notices.is_file() or not rights_review.is_file():
        return True
    try:
        review = json.loads(rights_review.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return True
    if review.get("overall_status") not in {"APPROVED", "APPROVED_WITH_EXCLUSIONS"}:
        return True
    approved = {"APPROVED", "NOT_APPLICABLE"}
    return any(
        item.get("included") is True and item.get("status") not in approved
        for item in review.get("items", [])
    )


def _license_gate(output: Path) -> tuple[bool, str | None]:
    license_path = output / "LICENSE"
    notice_path = output / "NOTICE"
    if not license_path.is_file():
        return False, "LICENSE_MISSING"
    if _sha256(license_path) != APACHE_2_LICENSE_SHA256:
        return False, "LICENSE_CONTENT_MISMATCH"
    if not notice_path.is_file():
        return False, "NOTICE_MISSING"
    try:
        notice = notice_path.read_text(encoding="utf-8")
    except OSError:
        return False, "NOTICE_UNREADABLE"
    if EXPECTED_COPYRIGHT_NOTICE not in notice.splitlines():
        return False, "NOTICE_COPYRIGHT_MISMATCH"
    return True, None


def build(output: Path, strict: bool) -> int:
    output = output.resolve()
    try:
        output.relative_to(REPO_ROOT)
    except ValueError:
        pass
    else:
        raise RuntimeError("output must be outside the source repository")
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")

    selected = _selected_paths()
    if not selected:
        raise RuntimeError("public candidate would be empty")
    scan_findings = {
        rel.as_posix(): findings
        for rel in selected
        if (findings := _scan_text(rel))
    }
    if scan_findings:
        detail = json.dumps(scan_findings, ensure_ascii=False, indent=2)
        raise RuntimeError(f"public text scan failed:\n{detail}")

    output.mkdir(parents=True)
    for rel in selected:
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel, target)

    license_present = (output / "LICENSE").is_file()
    license_consistent, license_blocking_reason = _license_gate(output)
    source_rights_pending = _rights_pending(output)
    source_worktree_dirty = bool(_git("status", "--porcelain"))
    source_eligible = (
        license_consistent and not source_rights_pending and not source_worktree_dirty
    )
    source_blocking_reasons = []
    if license_blocking_reason is not None:
        source_blocking_reasons.append(license_blocking_reason)
    if source_rights_pending:
        source_blocking_reasons.append("SOURCE_RIGHTS_PENDING")
    if source_worktree_dirty:
        source_blocking_reasons.append("SOURCE_WORKTREE_DIRTY")
    status = {
        "candidate_status": (
            "SOURCE_REPOSITORY_PUBLICATION_ELIGIBLE"
            if source_eligible
            else "SOURCE_REPOSITORY_PUBLICATION_BLOCKED"
        ),
        "source_repository_publication_eligible": source_eligible,
        "source_repository_publication_blocking_reasons": source_blocking_reasons,
        "github_release_eligible": False,
        "python_artifact_distribution_eligible": False,
        "container_distribution_eligible": False,
        "windows_portable_distribution_eligible": False,
        "artifact_distribution_blocking_reasons": [
            "ARTIFACT_LICENSE_AND_NOTICE_REVIEW_PENDING",
            "CONTAINER_VULNERABILITY_REVIEW_PENDING",
            "SIGNED_PROVENANCE_PENDING",
            "SUPPORTED_PLATFORM_RELEASE_VALIDATION_PENDING",
        ],
        "source_head": _git("rev-parse", "HEAD"),
        "source_worktree_dirty": source_worktree_dirty,
        "file_count_before_generated_metadata": len(selected),
        "license_present": license_present,
        "license_consistent": license_consistent,
        "license_expression": "Apache-2.0" if license_consistent else None,
        "copyright_notice": EXPECTED_COPYRIGHT_NOTICE if license_consistent else None,
        "source_rights_pending": source_rights_pending,
        "review_model": "SOLE_MAINTAINER_SELF_REVIEW",
        "boundary": (
            "SOURCE_ONLY_NO_GITHUB_RELEASE_NO_BINARY_OR_CONTAINER_DISTRIBUTION_"
            "NOT_CUSTOMER_EVIDENCE_NOT_CONFORMITY"
        ),
    }
    status_path = output / "PUBLIC_RELEASE_STATUS.json"
    status_path.write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    manifest_lines: list[str] = []
    for path in sorted((item for item in output.rglob("*") if item.is_file()), key=str):
        rel = path.relative_to(output).as_posix()
        if rel == "PUBLIC_RELEASE_MANIFEST.sha256":
            continue
        manifest_lines.append(f"{_sha256(path)}  {rel}")
    (output / "PUBLIC_RELEASE_MANIFEST.sha256").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8"
    )

    print(json.dumps(status, ensure_ascii=False, indent=2))
    if strict and not source_eligible:
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero until public-source license, rights, and clean-tree gates are closed",
    )
    args = parser.parse_args()
    try:
        return build(args.output, args.strict)
    except (FileExistsError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"PUBLIC_CANDIDATE_BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
