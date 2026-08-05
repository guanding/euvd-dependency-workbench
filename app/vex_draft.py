"""VEX draft suggestion (backlog 4).

Turns match signals (component_applicability, affected_versions, match_reason)
into a drafted (applicability_status, applicability_justification) so the
analyst doesn't hand-write every case from a blank form. The output is a
DRAFT — always editable via update_case, and it never auto-claims
known_not_affected (the CSAF VEX profile requires positive evidence for a
not_affected statement, which only a human can attest).
"""

from __future__ import annotations

from typing import Any


def suggest_applicability(finding: dict[str, Any]) -> tuple[str, str]:
    """Draft (status, justification) from a match finding.

    "受影响版本条件命中" (version range hit + vendor match) -> known_affected,
    with a rationale carrying the EUVD affected-versions expression and the
    match reason. Anything else -> under_investigation, still carrying the
    signals so the analyst sees why it wasn't auto-confirmed.
    """
    applicability = str(finding.get("component_applicability") or "")
    affected_versions = str(finding.get("affected_versions") or "").strip()
    match_reason = str(finding.get("match_reason") or "").strip()
    parts: list[str] = []
    if affected_versions:
        parts.append(f"EUVD 受影响版本：{affected_versions}")
    if match_reason:
        parts.append(match_reason)
    rationale = "；".join(parts) or "匹配信号待人工核验"
    if applicability == "受影响版本条件命中":
        return (
            "known_affected",
            f"机器判定受影响（{rationale}）；需人工确认产品包含性与可达路径",
        )
    return "under_investigation", f"待人工核验（{rationale}）"
