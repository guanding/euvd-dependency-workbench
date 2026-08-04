from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterator


CYCLONEDX_SAFETY_MAX_COMPONENTS = 10_000
CYCLONEDX_SAFETY_MAX_DEPTH = 100


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _flatten_components(
    components: list[Any],
    path: str = "$.components",
) -> Iterator[tuple[dict[str, Any], str]]:
    stack: list[tuple[Any, str, int]] = [
        (component, f"{path}[{index}]", 1)
        for index, component in reversed(list(enumerate(components)))
    ]
    yielded = 0
    while stack:
        component, component_path, depth = stack.pop()
        if not isinstance(component, dict):
            continue
        yielded += 1
        if yielded > CYCLONEDX_SAFETY_MAX_COMPONENTS:
            raise ValueError(
                "CycloneDX 组件数超过解析安全上限 "
                f"{CYCLONEDX_SAFETY_MAX_COMPONENTS}"
            )
        if depth > CYCLONEDX_SAFETY_MAX_DEPTH:
            raise ValueError(
                "CycloneDX 组件嵌套深度超过解析安全上限 "
                f"{CYCLONEDX_SAFETY_MAX_DEPTH}"
            )
        yield component, component_path
        children = component.get("components")
        if isinstance(children, list):
            stack.extend(
                (child, f"{component_path}.components[{index}]", depth + 1)
                for index, child in reversed(list(enumerate(children)))
            )


def _producer_candidates(component: dict[str, Any], path: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    named_objects = (
        ("supplier", component.get("supplier")),
        ("manufacturer", component.get("manufacturer")),
    )
    for field, value in named_objects:
        if isinstance(value, dict) and _text(value.get("name")):
            candidates.append(
                {
                    "source": f"{path}.{field}.name",
                    "value": _text(value.get("name")),
                }
            )
    for field in ("publisher", "author", "group"):
        if _text(component.get(field)):
            candidates.append(
                {
                    "source": f"{path}.{field}",
                    "value": _text(component.get(field)),
                }
            )
    return candidates


def _identifier_candidates(component: dict[str, Any], path: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for field, kind in (("purl", "purl"), ("cpe", "cpe"), ("bom-ref", "bom-ref")):
        if _text(component.get(field)):
            candidates.append(
                {
                    "type": kind,
                    "source": f"{path}.{field}",
                    "value": _text(component.get(field)),
                }
            )
    swid = component.get("swid")
    if isinstance(swid, dict) and _text(swid.get("tagId")):
        candidates.append(
            {
                "type": "swid-tag-id",
                "source": f"{path}.swid.tagId",
                "value": _text(swid.get("tagId")),
            }
        )
    return candidates


def _metadata_author_present(metadata: dict[str, Any]) -> bool:
    authors = metadata.get("authors")
    if isinstance(authors, list) and any(bool(item) for item in authors):
        return True
    return bool(metadata.get("author"))


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def extract_cyclonedx_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Preserve CycloneDX evidence fields and summarize their observable presence.

    The returned PRE-7 summary deliberately contains no C/PC/NC decision. It is
    an artifact-field inventory for a later scoped human assessment.
    """

    warnings: list[str] = []
    metadata_value = payload.get("metadata")
    if metadata_value is None:
        metadata: dict[str, Any] = {}
    elif isinstance(metadata_value, dict):
        metadata = metadata_value
    else:
        metadata = {}
        warnings.append("CycloneDX metadata 不是对象，已保留原值但无法生成元数据摘要")

    components_value = payload.get("components")
    components = components_value if isinstance(components_value, list) else []
    flattened_components = list(_flatten_components(components))

    component_refs: set[str] = set()
    duplicate_refs: set[str] = set()
    for component, _ in flattened_components:
        reference = _text(component.get("bom-ref"))
        if not reference:
            continue
        if reference in component_refs:
            duplicate_refs.add(reference)
        component_refs.add(reference)
    for reference in sorted(duplicate_refs):
        warnings.append(f"CycloneDX bom-ref 重复: {reference}")

    dependencies_value = payload.get("dependencies", [])
    dependencies = dependencies_value if isinstance(dependencies_value, list) else []
    if not isinstance(dependencies_value, list):
        warnings.append("CycloneDX dependencies 不是数组，已保留原值但无法建立关系摘要")

    dependency_by_ref: dict[str, list[dict[str, Any]]] = {}
    depended_on_by: dict[str, list[str]] = {}
    for index, entry in enumerate(dependencies):
        if not isinstance(entry, dict):
            warnings.append(f"CycloneDX dependencies[{index}] 不是对象，已跳过关系解析")
            continue
        reference = _text(entry.get("ref"))
        if not reference:
            warnings.append(f"CycloneDX dependencies[{index}] 缺少 ref")
            continue
        dependency_by_ref.setdefault(reference, []).append(entry)
        depends_on = entry.get("dependsOn")
        if isinstance(depends_on, list):
            for target in depends_on:
                target_ref = _text(target)
                if target_ref:
                    depended_on_by.setdefault(target_ref, []).append(reference)

    item_summaries: list[dict[str, Any]] = []
    for component, path in flattened_components:
        reference = _text(component.get("bom-ref"))
        producers = _producer_candidates(component, path)
        identifiers = _identifier_candidates(component, path)
        dependency_entries = dependency_by_ref.get(reference, []) if reference else []
        depends_on: list[str] = []
        provides: list[str] = []
        for entry in dependency_entries:
            if isinstance(entry.get("dependsOn"), list):
                depends_on.extend(_text(value) for value in entry["dependsOn"])
            if isinstance(entry.get("provides"), list):
                provides.extend(_text(value) for value in entry["provides"])

        hashes_value = component.get("hashes", [])
        if hashes_value is not None and not isinstance(hashes_value, list):
            warnings.append(f"{path}.hashes 不是数组，已保留原值")
        hashes = hashes_value
        field_presence = {
            "producer_candidate": bool(producers),
            "name": bool(_text(component.get("name"))),
            "version": bool(_text(component.get("version"))),
            "bom_ref": bool(reference),
            "purl": bool(_text(component.get("purl"))),
            "cpe": bool(_text(component.get("cpe"))),
            "identifier_candidate": bool(identifiers),
            "external_identifier_candidate": any(
                item["type"] != "bom-ref" for item in identifiers
            ),
            "dependency_entry": bool(dependency_entries),
            "hashes": bool(hashes_value),
        }
        item_summaries.append(
            {
                "source_path": path,
                "bom_ref": reference,
                "name": deepcopy(component.get("name")),
                "version": deepcopy(component.get("version")),
                "producer_candidates": producers,
                "identifiers": identifiers,
                "purl": deepcopy(component.get("purl")),
                "cpe": deepcopy(component.get("cpe")),
                "hashes": hashes,
                "dependency_relationship": {
                    "entry_present": bool(dependency_entries),
                    "entries": dependency_entries,
                    "depends_on": _dedupe(depends_on),
                    "provides": _dedupe(provides),
                    "depended_on_by": _dedupe(depended_on_by.get(reference, [])),
                },
                "field_presence": field_presence,
                "missing_observations": [
                    field
                    for field in (
                        "producer_candidate",
                        "name",
                        "version",
                        "identifier_candidate",
                        "dependency_entry",
                    )
                    if not field_presence[field]
                ],
            }
        )

    component_count = len(item_summaries)

    def count_present(field: str) -> int:
        return sum(
            1 for item in item_summaries if item["field_presence"].get(field)
        )

    rq06_observations = {
        "author_present": _metadata_author_present(metadata),
        "bom_version_present": payload.get("version") not in (None, ""),
        "timestamp_present": bool(_text(metadata.get("timestamp"))),
        "authors": deepcopy(metadata.get("authors", metadata.get("author"))),
        "bom_version": deepcopy(payload.get("version")),
        "timestamp": deepcopy(metadata.get("timestamp")),
        "tools": deepcopy(metadata.get("tools")),
        "tools_present": bool(metadata.get("tools")),
    }
    rq06_gaps = []
    if not rq06_observations["author_present"]:
        rq06_gaps.append("metadata.authors/author 未提供可观察的 SBOM Author 字段")
    if not rq06_observations["bom_version_present"]:
        rq06_gaps.append("顶层 version 未提供可观察的 BOM 版本")
    if not rq06_observations["timestamp_present"]:
        rq06_gaps.append("metadata.timestamp 未提供可观察的时间戳")

    rq07_counts = {
        "component_count": component_count,
        "with_producer_candidate": count_present("producer_candidate"),
        "with_name": count_present("name"),
        "with_version": count_present("version"),
        "with_bom_ref": count_present("bom_ref"),
        "with_identifier_candidate": count_present("identifier_candidate"),
        "with_external_identifier_candidate": count_present(
            "external_identifier_candidate"
        ),
        "with_dependency_entry": count_present("dependency_entry"),
        "with_hashes": count_present("hashes"),
    }
    rq07_gaps = []
    gap_labels = (
        ("with_producer_candidate", "producer 候选字段"),
        ("with_name", "name"),
        ("with_version", "version"),
        ("with_identifier_candidate", "唯一标识候选字段"),
        ("with_dependency_entry", "dependencies 关系条目"),
    )
    for key, label in gap_labels:
        missing = component_count - rq07_counts[key]
        if missing:
            rq07_gaps.append(f"{missing}/{component_count} 个组件缺少可观察的 {label}")

    document_identity = {
        "bom_format": deepcopy(payload.get("bomFormat")),
        "spec_version": deepcopy(payload.get("specVersion")),
        "serial_number": deepcopy(payload.get("serialNumber")),
        "bom_version": deepcopy(payload.get("version")),
    }
    source_document = {
        "bomFormat": deepcopy(payload.get("bomFormat")),
        "specVersion": deepcopy(payload.get("specVersion")),
        "serialNumber": deepcopy(payload.get("serialNumber")),
        "version": deepcopy(payload.get("version")),
        "metadata": metadata_value,
        "components": components_value,
        "dependencies": dependencies_value,
    }
    evidence_summary = {
        "summary_type": "artifact_field_presence",
        "automatic_conformity_decision": False,
        "requirements": {
            "PRE-7-RQ-06": {
                "evidence_observations": rq06_observations,
                "evidence_paths": {
                    "author": ["$.metadata.authors", "$.metadata.author"],
                    "version": ["$.version"],
                    "timestamp": ["$.metadata.timestamp"],
                    "tools": ["$.metadata.tools"],
                },
                "evidence_gaps": rq06_gaps,
            },
            "PRE-7-RQ-07": {
                "coverage_counts": rq07_counts,
                "items": item_summaries,
                "evidence_gaps": rq07_gaps,
            },
        },
        "limitations": [
            "本摘要只记录制品字段与位置，不自动输出 C、PC 或 NC。",
            "SBOM 不能单独证明产品内组件总体完整性，还需与构建、二进制和发布证据对账。",
            "bom-ref、PURL、CPE 和 SWID 仅作为标识候选，其唯一性与归属仍需评审。",
            "hash 字段出现不自动证明 PRE-7-RQ-07-RE 已激活或满足。",
        ],
    }
    return {
        "document_identity": document_identity,
        "source_document": source_document,
        "sbom_metadata": metadata_value,
        "dependencies": dependencies_value,
        "source_components": components_value,
        "warnings": _dedupe(warnings),
        "pre7_evidence_summary": evidence_summary,
    }
