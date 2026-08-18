#!/usr/bin/env python3
"""Generate a controlled candidate SBOM through the isolated Syft sidecar."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


PROJECT_DIR = Path(__file__).resolve().parent.parent
SCANNER_IMAGE = (
    "anchore/syft:v1.50.0@"
    "sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026"
)
SCANNER_VERSION = "1.50.0"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "backups",
    "data",
    "experiments",
    "exports",
    "outputs",
    "runtime",
    "self-test",
}
SOURCE_EXCLUDE_GLOBS = (
    "./.git/**",
    "./.mypy_cache/**",
    "./.pytest_cache/**",
    "./.ruff_cache/**",
    "./__pycache__/**",
    "./backups/**",
    "./data/**",
    "./experiments/**",
    "./exports/**",
    "./outputs/**",
    "./runtime/**",
    "./self-test/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.DS_Store",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def excluded_source_path(relative: Path) -> bool:
    return any(part in SOURCE_EXCLUDED_PARTS for part in relative.parts) or (
        relative.name == ".DS_Store" or relative.suffix == ".pyc"
    )


def directory_entries(root: Path, kind: str) -> Iterator[dict[str, Any]]:
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if kind == "source" and excluded_source_path(relative):
            continue
        if path.is_symlink():
            yield {
                "path": relative.as_posix(),
                "type": "symlink",
                "target": os.readlink(path),
            }
        elif path.is_file():
            yield {
                "path": relative.as_posix(),
                "type": "file",
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }


def write_input_manifest(
    source: Path,
    kind: str,
    target: Path,
) -> tuple[str, int]:
    if kind == "docker-archive":
        entries = [
            {
                "path": source.name,
                "type": "docker-archive",
                "size_bytes": source.stat().st_size,
                "sha256": sha256_file(source),
            }
        ]
    else:
        entries = directory_entries(source, kind)
    count = 0
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for entry in entries:
            handle.write(
                json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            )
            count += 1
    return sha256_file(target), count


def docker_archive_identity(path: Path) -> dict[str, Any]:
    with tarfile.open(path, mode="r") as archive:
        try:
            index_handle = archive.extractfile(archive.getmember("index.json"))
            if index_handle is None:
                raise ValueError("docker archive index.json is unreadable")
            index = json.loads(index_handle.read())
            manifest_member = archive.getmember("manifest.json")
            manifest_handle = archive.extractfile(manifest_member)
            if manifest_handle is None:
                raise ValueError("docker archive manifest.json is unreadable")
            manifest = json.loads(manifest_handle.read())
        except (KeyError, json.JSONDecodeError) as exc:
            raise ValueError("docker archive has no valid index/manifest JSON") from exc
        index_rows = index.get("manifests") if isinstance(index, dict) else None
        if not isinstance(index_rows, list) or len(index_rows) != 1:
            raise ValueError("docker archive index must contain exactly one root descriptor")
        root_digest = str(index_rows[0].get("digest") or "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", root_digest):
            raise ValueError("docker archive root descriptor digest is invalid")
        root_blob_name = "blobs/sha256/" + root_digest.split(":", 1)[1]
        try:
            root_handle = archive.extractfile(archive.getmember(root_blob_name))
            if root_handle is None:
                raise ValueError("docker archive root descriptor blob is unreadable")
            root_bytes = root_handle.read()
            if hashlib.sha256(root_bytes).hexdigest() != root_digest.split(":", 1)[1]:
                raise ValueError("docker archive root descriptor blob hash mismatches")
            root_document = json.loads(root_bytes)
        except (KeyError, json.JSONDecodeError) as exc:
            raise ValueError("docker archive root descriptor blob is invalid") from exc
        platform_rows = [
            item
            for item in (root_document.get("manifests") or [])
            if isinstance(item, dict)
            and (item.get("platform") or {}).get("os") not in {None, "unknown"}
        ]
        if len(platform_rows) != 1:
            raise ValueError("docker archive must resolve to exactly one platform manifest")
        platform_manifest_digest = str(platform_rows[0].get("digest") or "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", platform_manifest_digest):
            raise ValueError("docker archive platform manifest digest is invalid")
        platform_blob_name = (
            "blobs/sha256/" + platform_manifest_digest.split(":", 1)[1]
        )
        try:
            platform_handle = archive.extractfile(
                archive.getmember(platform_blob_name)
            )
            if platform_handle is None:
                raise ValueError("docker archive platform manifest is unreadable")
            platform_bytes = platform_handle.read()
            if hashlib.sha256(platform_bytes).hexdigest() != (
                platform_manifest_digest.split(":", 1)[1]
            ):
                raise ValueError("docker archive platform manifest hash mismatches")
            platform_document = json.loads(platform_bytes)
        except (KeyError, json.JSONDecodeError) as exc:
            raise ValueError("docker archive platform manifest is invalid") from exc
        platform_config_digest = str(
            (platform_document.get("config") or {}).get("digest") or ""
        )
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError("docker archive must contain exactly one image manifest")
        row = manifest[0]
        config_name = str(row.get("Config") or "")
        try:
            config_member = archive.getmember(config_name)
            config_handle = archive.extractfile(config_member)
            if config_handle is None:
                raise ValueError("docker archive image config is unreadable")
            config_bytes = config_handle.read()
        except KeyError as exc:
            raise ValueError("docker archive image config is missing") from exc
        config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
        if platform_config_digest != config_digest:
            raise ValueError("docker archive platform manifest/config digest mismatches")
    return {
        "archive_sha256": sha256_file(path),
        "archive_size_bytes": path.stat().st_size,
        "derived_image_id": root_digest,
        "platform_manifest_digest": platform_manifest_digest,
        "config_digest": config_digest,
        "config_file": config_name,
        "repo_tags": list(row.get("RepoTags") or []),
        "layer_count": len(row.get("Layers") or []),
    }


def validate_outputs(cyclonedx_path: Path, syft_path: Path) -> dict[str, Any]:
    cyclonedx = json.loads(cyclonedx_path.read_text(encoding="utf-8"))
    syft = json.loads(syft_path.read_text(encoding="utf-8"))
    if cyclonedx.get("bomFormat") != "CycloneDX":
        raise ValueError("scanner output is not CycloneDX JSON")
    if not isinstance(cyclonedx.get("components"), list):
        raise ValueError("CycloneDX output has no components array")
    if not isinstance(syft.get("artifacts"), list):
        raise ValueError("Syft JSON output has no artifacts array")
    descriptor = syft.get("descriptor") or {}
    if str(descriptor.get("name") or "").casefold() != "syft":
        raise ValueError("Syft JSON descriptor does not identify Syft")
    if str(descriptor.get("version") or "") != SCANNER_VERSION:
        raise ValueError(
            "Syft JSON descriptor version does not match the pinned scanner: "
            f"{descriptor.get('version')}"
        )
    return {
        "cyclonedx_spec_version": str(cyclonedx.get("specVersion") or ""),
        "cyclonedx_serial_number": str(cyclonedx.get("serialNumber") or ""),
        "cyclonedx_bom_version": cyclonedx.get("version"),
        "cyclonedx_component_count": len(cyclonedx["components"]),
        "syft_artifact_count": len(syft["artifacts"]),
        "syft_descriptor_version": str(descriptor.get("version") or ""),
    }


def run_json(command: list[str], environment: dict[str, str]) -> Any:
    completed = subprocess.run(
        command,
        cwd=PROJECT_DIR,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ValueError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr or completed.stdout}"
        )
    return json.loads(completed.stdout)


def validate_rendered_service(service: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if service.get("image") != SCANNER_IMAGE:
        issues.append("rendered scanner image is not the pinned digest")
    if service.get("network_mode") != "none":
        issues.append("rendered scanner network_mode is not none")
    if service.get("read_only") is not True:
        issues.append("rendered scanner root filesystem is not read-only")
    if "ALL" not in (service.get("cap_drop") or []):
        issues.append("rendered scanner does not drop ALL capabilities")
    if "no-new-privileges:true" not in (service.get("security_opt") or []):
        issues.append("rendered scanner lacks no-new-privileges")
    input_mounts = [
        item
        for item in service.get("volumes") or []
        if isinstance(item, dict) and item.get("target") == "/scan-input"
    ]
    if len(input_mounts) != 1 or input_mounts[0].get("read_only") is not True:
        issues.append("rendered /scan-input bind is not uniquely read-only")
    all_mount_text = json.dumps(service.get("volumes") or [], sort_keys=True)
    if "docker.sock" in all_mount_text:
        issues.append("rendered scanner unexpectedly mounts a Docker socket")
    return issues


def runtime_observation(inspect_payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    host = inspect_payload.get("HostConfig") or {}
    config = inspect_payload.get("Config") or {}
    mounts = inspect_payload.get("Mounts") or []
    observation = {
        "container_id": str(inspect_payload.get("Id") or ""),
        "image_id": str(inspect_payload.get("Image") or ""),
        "user": str(config.get("User") or ""),
        "network_mode": str(host.get("NetworkMode") or ""),
        "read_only_rootfs": bool(host.get("ReadonlyRootfs")),
        "cap_drop": list(host.get("CapDrop") or []),
        "security_opt": list(host.get("SecurityOpt") or []),
        "mounts": [
            {
                "type": item.get("Type"),
                "source": item.get("Source"),
                "destination": item.get("Destination"),
                "rw": item.get("RW"),
            }
            for item in mounts
            if isinstance(item, dict)
        ],
    }
    issues: list[str] = []
    if observation["network_mode"] != "none":
        issues.append("actual scanner container network mode is not none")
    if observation["user"].split(":", 1)[0] in {"", "0", "root"}:
        issues.append("actual scanner container runs as root or has no explicit user")
    if not observation["read_only_rootfs"]:
        issues.append("actual scanner container root filesystem is not read-only")
    if "ALL" not in observation["cap_drop"]:
        issues.append("actual scanner container does not drop ALL capabilities")
    if "no-new-privileges:true" not in observation["security_opt"]:
        issues.append("actual scanner container lacks no-new-privileges")
    input_mounts = [
        item for item in observation["mounts"] if item["destination"] == "/scan-input"
    ]
    if len(input_mounts) != 1 or input_mounts[0]["rw"] is not False:
        issues.append("actual /scan-input mount is not uniquely read-only")
    if any(
        "docker.sock" in str(item.get("source") or "")
        or "docker.sock" in str(item.get("destination") or "")
        for item in observation["mounts"]
    ):
        issues.append("actual scanner container mounts a Docker socket")
    return observation, issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("source", "portable", "docker-archive"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--source-version", default="candidate")
    parser.add_argument(
        "--expected-image-id",
        default="",
        help="required for docker-archive; bind the exported archive to docker image inspect",
    )
    args = parser.parse_args()

    if not SAFE_ID.fullmatch(args.identity):
        raise SystemExit("--identity must match [A-Za-z0-9][A-Za-z0-9._-]{0,119}")
    source = args.input.resolve()
    output_dir = args.output_dir.resolve()
    if args.kind == "docker-archive":
        if not source.is_file():
            raise SystemExit("docker-archive input must be an existing file")
        if not IMAGE_ID.fullmatch(args.expected_image_id):
            raise SystemExit(
                "docker-archive requires --expected-image-id sha256:<64 lowercase hex>"
            )
    elif not source.is_dir():
        raise SystemExit(f"{args.kind} input must be an existing directory")
    output_dir.mkdir(parents=True, exist_ok=True)

    cyclonedx_path = output_dir / f"{args.identity}.cdx.json"
    syft_path = output_dir / f"{args.identity}.syft.json"
    manifest_path = output_dir / f"{args.identity}.input-manifest.jsonl"
    evidence_path = output_dir / f"{args.identity}.generation.json"
    control_path = output_dir / f"{args.identity}.scanner-control.json"
    failed_path = output_dir / f"{args.identity}.generation.failed.json"
    for target in (
        cyclonedx_path,
        syft_path,
        manifest_path,
        evidence_path,
        control_path,
        failed_path,
    ):
        if target.exists():
            raise SystemExit(f"refusing to overwrite existing evidence: {target}")

    manifest_sha256, manifest_entries = write_input_manifest(
        source, args.kind, manifest_path
    )
    source_identity: dict[str, Any] = {
        "kind": args.kind,
        "input_path": str(source),
    }
    if args.kind == "docker-archive":
        source_identity.update(docker_archive_identity(source))
        source_identity["expected_image_id"] = args.expected_image_id
        source_identity["image_id_matches_expected"] = (
            source_identity["derived_image_id"] == args.expected_image_id
        )
        if not source_identity["image_id_matches_expected"]:
            failed_path.write_text(
                json.dumps(
                    {
                        "evidence_type": "INTERNAL_SBOM_GENERATION_FAILURE",
                        "customer_evidence": False,
                        "conformity_decision": False,
                        "identity": args.identity,
                        "source_kind": args.kind,
                        "failed_at": utc_now(),
                        "failure_stage": "docker-archive-identity",
                        "source_identity": source_identity,
                        "input_manifest": {
                            "file": manifest_path.name,
                            "sha256": manifest_sha256,
                            "entry_count": manifest_entries,
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            raise SystemExit(
                f"docker archive image ID mismatch; evidence: {failed_path}"
            )
    environment = os.environ.copy()
    for inherited_override in (
        "COMPOSE_FILE",
        "COMPOSE_PATH_SEPARATOR",
        "COMPOSE_PROFILES",
    ):
        environment.pop(inherited_override, None)
    environment.update(
        {
            "SBOM_SCAN_INPUT_PATH": str(source),
            "SBOM_SCAN_OUTPUT_PATH": str(output_dir),
            "SBOM_SCANNER_UID": str(os.getuid()),
            "SBOM_SCANNER_GID": str(os.getgid()),
        }
    )
    scan_target = (
        "docker-archive:/scan-input"
        if args.kind == "docker-archive"
        else "dir:/scan-input"
    )
    compose_base = [
        "docker",
        "compose",
        "--file",
        str(PROJECT_DIR / "docker-compose.yml"),
        "--project-name",
        "euvd-sbom-evidence",
        "--profile",
        "sbom",
    ]
    control: dict[str, Any] = {
        "compose_file": {
            "path": str(PROJECT_DIR / "docker-compose.yml"),
            "sha256": sha256_file(PROJECT_DIR / "docker-compose.yml"),
        },
        "inherited_compose_overrides_removed": [
            "COMPOSE_FILE",
            "COMPOSE_PATH_SEPARATOR",
            "COMPOSE_PROFILES",
        ],
        "scanner_image_reference": SCANNER_IMAGE,
    }
    preflight_issues: list[str] = []
    try:
        rendered = run_json(
            [*compose_base, "config", "--format", "json"], environment
        )
        rendered_service = (rendered.get("services") or {}).get("sbom-generator")
        if not isinstance(rendered_service, dict):
            raise ValueError("rendered Compose config has no sbom-generator service")
        preflight_issues.extend(validate_rendered_service(rendered_service))
        rendered_canonical = json.dumps(
            rendered_service,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        control["rendered_service"] = rendered_service
        control["rendered_service_sha256"] = hashlib.sha256(
            rendered_canonical
        ).hexdigest()
        image_inspect = run_json(
            ["docker", "image", "inspect", SCANNER_IMAGE], environment
        )
        if not isinstance(image_inspect, list) or not image_inspect:
            raise ValueError("pinned scanner image inspect returned no image")
        image_row = image_inspect[0]
        repo_digests = list(image_row.get("RepoDigests") or [])
        expected_digest = SCANNER_IMAGE.rsplit("@", 1)[-1]
        if not any(value.endswith("@" + expected_digest) for value in repo_digests):
            preflight_issues.append(
                "local scanner image RepoDigests do not contain the pinned digest"
            )
        control["scanner_image"] = {
            "id": str(image_row.get("Id") or ""),
            "repo_digests": repo_digests,
            "expected_digest": expected_digest,
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        preflight_issues.append(str(exc))

    if preflight_issues:
        failed_path.write_text(
            json.dumps(
                {
                    "evidence_type": "INTERNAL_SBOM_GENERATION_FAILURE",
                    "customer_evidence": False,
                    "conformity_decision": False,
                    "identity": args.identity,
                    "source_kind": args.kind,
                    "source_identity": source_identity,
                    "failed_at": utc_now(),
                    "failure_stage": "scanner-control-preflight",
                    "control_issues": preflight_issues,
                    "scanner_control": control,
                    "input_manifest": {
                        "file": manifest_path.name,
                        "sha256": manifest_sha256,
                        "entry_count": manifest_entries,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        raise SystemExit(f"scanner control preflight failed; evidence: {failed_path}")

    container_name = (
        f"euvd-sbom-{args.identity.casefold()}-{os.getpid()}-{time.time_ns()}"
    )
    command = [
        *compose_base,
        "run",
        "--name",
        container_name,
        "sbom-generator",
        "scan",
        scan_target,
        "--source-name",
        args.identity,
        "--source-version",
        args.source_version,
        "--output",
        f"syft-json=/scan-output/{syft_path.name}",
        "--output",
        f"cyclonedx-json@1.6=/scan-output/{cyclonedx_path.name}",
        "--quiet",
    ]
    if args.kind == "source":
        for pattern in SOURCE_EXCLUDE_GLOBS:
            command.extend(("--exclude", pattern))

    started_at = utc_now()
    completed = subprocess.run(
        command,
        cwd=PROJECT_DIR,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    runtime_issues: list[str] = []
    try:
        inspected = run_json(["docker", "inspect", container_name], environment)
        if not isinstance(inspected, list) or not inspected:
            raise ValueError("scanner container inspect returned no container")
        runtime, observed_issues = runtime_observation(inspected[0])
        runtime_issues.extend(observed_issues)
        if runtime["image_id"] != control["scanner_image"]["id"]:
            runtime_issues.append(
                "actual scanner container image ID differs from pinned image inspect"
            )
        control["actual_container"] = runtime
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        runtime_issues.append(str(exc))
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            cwd=PROJECT_DIR,
            env=environment,
            check=False,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    control["control_issues"] = runtime_issues
    control["all_controls_passed"] = not runtime_issues
    control_path.write_text(
        json.dumps(control, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    if completed.returncode != 0 or runtime_issues:
        partial_outputs = []
        for path in (cyclonedx_path, syft_path):
            if path.exists():
                partial_outputs.append(
                    {
                        "file": path.name,
                        "sha256": sha256_file(path),
                        "size_bytes": path.stat().st_size,
                    }
                )
        failed_path.write_text(
            json.dumps(
                {
                    "evidence_type": "INTERNAL_SBOM_GENERATION_FAILURE",
                    "customer_evidence": False,
                    "conformity_decision": False,
                    "identity": args.identity,
                    "source_kind": args.kind,
                    "source_identity": source_identity,
                    "started_at": started_at,
                    "failed_at": utc_now(),
                    "scanner_image": SCANNER_IMAGE,
                    "exit_code": completed.returncode,
                    "scanner_output": completed.stdout,
                    "failure_stage": (
                        "scanner-runtime-control"
                        if runtime_issues
                        else "scanner-execution"
                    ),
                    "control_issues": runtime_issues,
                    "scanner_control": {
                        "file": control_path.name,
                        "sha256": sha256_file(control_path),
                    },
                    "input_manifest": {
                        "file": manifest_path.name,
                        "sha256": manifest_sha256,
                        "entry_count": manifest_entries,
                    },
                    "partial_outputs": partial_outputs,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(completed.stdout, file=sys.stderr)
        raise SystemExit(
            f"Syft sidecar/control validation failed with exit code "
            f"{completed.returncode}; evidence: {failed_path}"
        )

    observations = validate_outputs(cyclonedx_path, syft_path)
    evidence = {
        "evidence_type": "INTERNAL_SBOM_GENERATION_CANDIDATE",
        "customer_evidence": False,
        "conformity_decision": False,
        "identity": args.identity,
        "source_kind": args.kind,
        "source_identity": source_identity,
        "source_version": args.source_version,
        "started_at": started_at,
        "completed_at": utc_now(),
        "scanner": {
            "name": "Syft",
            "version": SCANNER_VERSION,
            "image": SCANNER_IMAGE,
            "network_mode": "none",
            "docker_socket_mounted": False,
            "input_read_only": True,
            "controls_bound_to_rendered_and_actual_container": True,
        },
        "scanner_control": {
            "file": control_path.name,
            "sha256": sha256_file(control_path),
            "rendered_service_sha256": control["rendered_service_sha256"],
            "container_id": control["actual_container"]["container_id"],
            "image_id": control["actual_container"]["image_id"],
            "all_controls_passed": control["all_controls_passed"],
        },
        "input_manifest": {
            "file": manifest_path.name,
            "sha256": manifest_sha256,
            "entry_count": manifest_entries,
        },
        "outputs": {
            "cyclonedx": {
                "file": cyclonedx_path.name,
                "sha256": sha256_file(cyclonedx_path),
                "size_bytes": cyclonedx_path.stat().st_size,
            },
            "syft_json": {
                "file": syft_path.name,
                "sha256": sha256_file(syft_path),
                "size_bytes": syft_path.stat().st_size,
            },
            "scanner_control": {
                "file": control_path.name,
                "sha256": sha256_file(control_path),
                "size_bytes": control_path.stat().st_size,
            },
        },
        "observations": observations,
        "limitations": [
            "This is an internal candidate generated by an automated cataloger.",
            "Package discovery does not prove the completeness of the shipped product population.",
            "Source, container image, and portable release identities must remain separate.",
            "No C, PC, NC, CRA conformity, release, or Article 14 decision is produced.",
        ],
    }
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    result = {
        "status": "PASS",
        "identity": args.identity,
        "source_kind": args.kind,
        "evidence": str(evidence_path),
        "cyclonedx": str(cyclonedx_path),
        "syft_json": str(syft_path),
        **observations,
        "automatic_conformity_decision": False,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
