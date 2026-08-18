#!/usr/bin/env python3
"""Reconcile source, image, and portable internal candidate SBOM identities."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from generate_sbom import directory_entries


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.split("[", 1)[0].strip().casefold())


def parse_requirements(path: Path) -> dict[str, str]:
    requirements: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise ValueError(f"unlocked requirement cannot be reconciled: {line}")
        name, version = line.split("==", 1)
        requirements[normalize_name(name)] = version.strip()
    return requirements


def current_directory_manifest(root: Path, kind: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for entry in directory_entries(root, kind):
        line = (
            json.dumps(
                entry,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        digest.update(line)
        count += 1
    return digest.hexdigest(), count


def load_profile(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("bomFormat") != "CycloneDX":
        raise ValueError(f"not a CycloneDX document: {path}")
    components = payload.get("components")
    if not isinstance(components, list):
        raise ValueError(f"CycloneDX document has no components array: {path}")
    package_versions: dict[str, set[str]] = defaultdict(set)
    package_identities: set[str] = set()
    type_counts: Counter[str] = Counter()
    for component in components:
        if not isinstance(component, dict):
            continue
        component_type = str(component.get("type") or "unknown")
        type_counts[component_type] += 1
        if component_type == "file":
            continue
        name = normalize_name(str(component.get("name") or ""))
        version = str(component.get("version") or "")
        if not name:
            continue
        package_versions[name].add(version)
        package_identities.add(f"{name}@{version}")
    dependencies = payload.get("dependencies")
    return {
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "spec_version": str(payload.get("specVersion") or ""),
        "serial_number": str(payload.get("serialNumber") or ""),
        "bom_version": payload.get("version"),
        "component_count": len(components),
        "component_type_counts": dict(sorted(type_counts.items())),
        "dependency_entry_count": len(dependencies) if isinstance(dependencies, list) else 0,
        "package_versions": package_versions,
        "package_identities": package_identities,
    }


def generation_path_for(cyclonedx_path: Path) -> Path:
    suffix = ".cdx.json"
    if not cyclonedx_path.name.endswith(suffix):
        raise ValueError(
            f"CycloneDX filename must end with {suffix}: {cyclonedx_path}"
        )
    return cyclonedx_path.with_name(
        cyclonedx_path.name[: -len(suffix)] + ".generation.json"
    )


def validate_generation_binding(
    profile_name: str,
    cyclonedx_path: Path,
) -> dict[str, Any]:
    expected_kind = {
        "source": "source",
        "image": "docker-archive",
        "portable": "portable",
    }[profile_name]
    generation_path = generation_path_for(cyclonedx_path)
    if not generation_path.is_file():
        raise ValueError(f"missing generation evidence: {generation_path}")
    payload = json.loads(generation_path.read_text(encoding="utf-8"))
    if payload.get("evidence_type") != "INTERNAL_SBOM_GENERATION_CANDIDATE":
        raise ValueError(f"invalid generation evidence type: {generation_path}")
    if payload.get("source_kind") != expected_kind:
        raise ValueError(
            f"generation source kind mismatch for {profile_name}: "
            f"{payload.get('source_kind')}"
        )
    if payload.get("customer_evidence") is not False:
        raise ValueError("generation evidence must remain internal/customer_evidence=false")
    if payload.get("conformity_decision") is not False:
        raise ValueError("generation evidence must not contain a conformity decision")
    source_identity = payload.get("source_identity") or {}
    if profile_name == "image":
        if source_identity.get("image_id_matches_expected") is not True:
            raise ValueError("docker archive was not bound to its expected image ID")
        if source_identity.get("derived_image_id") != source_identity.get(
            "expected_image_id"
        ):
            raise ValueError("docker archive derived/expected image IDs differ")
        if source_identity.get("archive_sha256") != sha256_file(
            Path(str(source_identity.get("input_path") or ""))
        ):
            raise ValueError("docker archive no longer matches generation identity")

    outputs = payload.get("outputs") or {}
    cdx = outputs.get("cyclonedx") or {}
    actual_cdx_hash = sha256_file(cyclonedx_path)
    if cdx.get("file") != cyclonedx_path.name or cdx.get("sha256") != actual_cdx_hash:
        raise ValueError(
            f"CycloneDX output is not bound to generation evidence: {cyclonedx_path}"
        )
    syft = outputs.get("syft_json") or {}
    syft_path = generation_path.parent / str(syft.get("file") or "")
    if not syft_path.is_file() or sha256_file(syft_path) != syft.get("sha256"):
        raise ValueError(f"Syft JSON is missing or hash-mismatched: {syft_path}")

    manifest = payload.get("input_manifest") or {}
    manifest_path = generation_path.parent / str(manifest.get("file") or "")
    if (
        not manifest_path.is_file()
        or sha256_file(manifest_path) != manifest.get("sha256")
    ):
        raise ValueError(
            f"input manifest is missing or hash-mismatched: {manifest_path}"
        )
    input_path = Path(str(source_identity.get("input_path") or ""))
    if profile_name in {"source", "portable"}:
        if not input_path.is_dir():
            raise ValueError(f"generation input directory is unavailable: {input_path}")
        current_manifest_sha256, current_entry_count = current_directory_manifest(
            input_path, expected_kind
        )
        if current_manifest_sha256 != manifest.get("sha256"):
            raise ValueError(
                f"current {profile_name} tree drifted from its input manifest"
            )
        if current_entry_count != int(manifest.get("entry_count") or -1):
            raise ValueError(
                f"current {profile_name} exact file set differs from generation"
            )

    control = payload.get("scanner_control") or {}
    control_path = generation_path.parent / str(control.get("file") or "")
    if not control_path.is_file() or sha256_file(control_path) != control.get("sha256"):
        raise ValueError(
            f"scanner control is missing or hash-mismatched: {control_path}"
        )
    control_payload = json.loads(control_path.read_text(encoding="utf-8"))
    if control.get("all_controls_passed") is not True:
        raise ValueError(f"generation evidence did not pass scanner controls: {generation_path}")
    if control_payload.get("all_controls_passed") is not True:
        raise ValueError(f"scanner control artifact is not PASS: {control_path}")
    if control_payload.get("scanner_image_reference") != (
        "anchore/syft:v1.50.0@"
        "sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026"
    ):
        raise ValueError(f"scanner digest drift in control artifact: {control_path}")

    return {
        "generation_file": generation_path.name,
        "generation_sha256": sha256_file(generation_path),
        "identity": str(payload.get("identity") or ""),
        "source_kind": expected_kind,
        "source_version": str(payload.get("source_version") or ""),
        "input_manifest_file": manifest_path.name,
        "input_manifest_sha256": str(manifest.get("sha256") or ""),
        "input_manifest_entry_count": int(manifest.get("entry_count") or 0),
        "current_tree_manifest_recalculated": profile_name in {"source", "portable"},
        "scanner_control_file": control_path.name,
        "scanner_control_sha256": str(control.get("sha256") or ""),
        "scanner_container_id": str(control.get("container_id") or ""),
        "scanner_image_id": str(control.get("image_id") or ""),
        "source_identity": source_identity,
        "binding_validated": True,
    }


def public_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in profile.items()
        if key not in {"package_versions", "package_identities"}
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--portable", required=True, type=Path)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    profile_paths = {
        "source": args.source.resolve(),
        "image": args.image.resolve(),
        "portable": args.portable.resolve(),
    }
    profiles: dict[str, dict[str, Any]] = {}
    for profile_name, profile_path in profile_paths.items():
        profile = load_profile(profile_path)
        profile["generation_binding"] = validate_generation_binding(
            profile_name, profile_path
        )
        profiles[profile_name] = profile
    requirements = parse_requirements(args.requirements.resolve())
    direct_matrix: list[dict[str, Any]] = []
    review_reasons: list[str] = []
    for name, expected in sorted(requirements.items()):
        observations: dict[str, Any] = {}
        for profile_name, profile in profiles.items():
            observed = sorted(profile["package_versions"].get(name, set()))
            exact_present = expected in observed
            additional = [version for version in observed if version != expected]
            observations[profile_name] = {
                "observed_versions": observed,
                "expected_version_present": exact_present,
                "additional_versions": additional,
            }
            if not exact_present:
                review_reasons.append(
                    f"{profile_name} 缺少锁定直接依赖 {name}=={expected}"
                )
            if additional:
                review_reasons.append(
                    f"{profile_name} 同时发现 {name} 的额外版本: {', '.join(additional)}"
                )
        direct_matrix.append(
            {
                "requirement": f"{name}=={expected}",
                "name": name,
                "expected_version": expected,
                "profiles": observations,
            }
        )

    pairwise: dict[str, Any] = {}
    for left, right in (("source", "image"), ("source", "portable"), ("image", "portable")):
        left_ids = profiles[left]["package_identities"]
        right_ids = profiles[right]["package_identities"]
        pairwise[f"{left}_vs_{right}"] = {
            "shared": len(left_ids & right_ids),
            f"only_{left}": sorted(left_ids - right_ids),
            f"only_{right}": sorted(right_ids - left_ids),
        }

    portable_conflicts = [
        {"name": name, "versions": sorted(versions)}
        for name, versions in sorted(profiles["portable"]["package_versions"].items())
        if len(versions) > 1
    ]
    result = {
        "evidence_type": "INTERNAL_THREE_PROFILE_SBOM_RECONCILIATION",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "automated_result": "REVIEW" if review_reasons else "PASS_AUTOMATED",
        "customer_evidence": False,
        "conformity_decision": False,
        "release_decision": False,
        "profiles_are_interchangeable": False,
        "all_generation_bindings_validated": all(
            profile["generation_binding"]["binding_validated"]
            for profile in profiles.values()
        ),
        "requirements_sha256": sha256_file(args.requirements.resolve()),
        "profiles": {name: public_profile(value) for name, value in profiles.items()},
        "direct_dependency_matrix": direct_matrix,
        "pairwise_package_comparison": pairwise,
        "portable_multi_version_observations": portable_conflicts,
        "review_reasons": list(dict.fromkeys(review_reasons)),
        "interpretation": [
            "Source scan observes dependency declarations and source-visible packages.",
            "Image scan observes the built Linux container filesystem, including transitive and OS packages.",
            "Portable scan observes the staged Windows runtime and may expose stale or duplicate installed metadata.",
            "Differences require build/release reconciliation; they do not by themselves establish a nonconformity.",
        ],
    }

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "three-profile-reconciliation.json"
    markdown_path = output_dir / "three-profile-reconciliation.md"
    if json_path.exists() or markdown_path.exists():
        raise SystemExit("refusing to overwrite existing reconciliation evidence")
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# 三类 SBOM 内部候选对账",
        "",
        f"自动化结果：`{result['automated_result']}`。这不是符合性、发布或客户交付结论。",
        "",
        "| 身份 | CycloneDX 组件 | 非 file 包身份 | dependencies 条目 |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name, profile in profiles.items():
        lines.append(
            f"| {name} | {profile['component_count']} | "
            f"{len(profile['package_identities'])} | {profile['dependency_entry_count']} |"
        )
    lines.extend(
        [
            "",
            "## 锁定直接依赖",
            "",
            "| 依赖 | source | image | portable |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in direct_matrix:
        rendered = []
        for profile_name in ("source", "image", "portable"):
            item = row["profiles"][profile_name]
            versions = ", ".join(item["observed_versions"]) or "未发现"
            rendered.append(
                ("OK " if item["expected_version_present"] and not item["additional_versions"] else "REVIEW ")
                + versions
            )
        lines.append(f"| {row['requirement']} | {rendered[0]} | {rendered[1]} | {rendered[2]} |")
    lines.extend(["", "## 需复核事项", ""])
    lines.extend(
        [f"- {reason}" for reason in result["review_reasons"]]
        or ["- 无自动化直接依赖差异。"]
    )
    lines.extend(
        [
            "",
            "## 边界",
            "",
            "源码、Linux Docker 镜像和 Windows 便携包是三个不同制品身份；本报告禁止将其互相替代。",
            "自动化 PASS/REVIEW 仅是内部候选证据，不代表 CRA 符合、正式发布或客户证据。",
            "",
        ]
    )
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    print(
        json.dumps(
            {
                "status": result["automated_result"],
                "json": str(json_path),
                "markdown": str(markdown_path),
                "review_reason_count": len(result["review_reasons"]),
                "portable_multi_version_count": len(portable_conflicts),
                "conformity_decision": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
