from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import os
import re
import sqlite3
import time
import unicodedata
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import quote, unquote

import httpx
from packaging.version import InvalidVersion, Version

from .version import USER_AGENT


EUVD_BASE_URL = os.getenv("EUVD_BASE_URL", "https://euvdservices.enisa.europa.eu").rstrip("/")
CACHE_HOURS = int(os.getenv("EUVD_CACHE_HOURS", "24"))
CONCURRENCY = max(1, int(os.getenv("EUVD_CONCURRENCY", "4")))
MAX_PAGES = max(1, int(os.getenv("EUVD_MAX_PAGES", "100")))
# Cap on product-candidate matches per component. The product path can return
# thousands of records for common names (Linux/Chrome); keep the highest-
# confidence slice and surface truncation rather than flood the report
# (VALIDATION_REPORT §2: 88 candidates/component median). CVE-exact matches
# (query_mode identifier-exact) are never capped.
MAX_PRODUCT_CANDIDATES = max(5, int(os.getenv("EUVD_MAX_PRODUCT_CANDIDATES", "50")))
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
CACHE_DB = DATA_DIR / "euvd-cache.sqlite3"
ROOT_DIR = Path(__file__).resolve().parent.parent
ALIAS_FILE = ROOT_DIR / "config" / "product-aliases.csv"
CVE_MAPPING_FILE = DATA_DIR / "cve-euvd-mapping.csv"
KEV_DUMP_FILE = DATA_DIR / "euvd-kev.json"
LOCAL_EUVD_DB = Path(os.getenv("EUVD_LOCAL_DB", str(DATA_DIR / "euvd-readonly.sqlite3")))
LOCAL_EUVD_SHA256_FILE = Path(
    os.getenv(
        "EUVD_LOCAL_DB_SHA256_FILE",
        str(Path(str(LOCAL_EUVD_DB) + ".sha256")),
    )
)
LOCAL_EUVD_EXPECTED_SHA256 = os.getenv("EUVD_LOCAL_DB_SHA256", "").strip().casefold()
NETWORK_FALLBACK = os.getenv("EUVD_NETWORK_FALLBACK", "false").strip().casefold() in {
    "1",
    "true",
    "yes",
    "on",
}
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
EUVD_PATTERN = re.compile(r"\bEUVD-\d{4}-\d+\b", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Component:
    row_number: int
    name: str
    version: str = ""
    vendor: str = ""
    purl: str = ""
    cpe: str = ""
    scope: str = ""
    license: str = ""
    cve_ids: str = ""
    euvd_ids: str = ""


def repair_text(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if "â" in text or "Ã" in text:
        try:
            text = text.encode("latin1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    return unicodedata.normalize("NFKC", text)


def normalize_key(value: Any) -> str:
    text = repair_text(value).casefold()
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", text)


def extract_identifiers(value: Any, kind: str) -> list[str]:
    pattern = CVE_PATTERN if kind == "cve" else EUVD_PATTERN
    return list(dict.fromkeys(match.upper() for match in pattern.findall(repair_text(value))))


def normalize_vendor(value: Any) -> str:
    text = repair_text(value).casefold()
    text = re.sub(
        r"\b(corporation|corp|incorporated|inc|limited|ltd|llc|company|co|gmbh|ag)\b",
        " ",
        text,
    )
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", " ", text).strip()


def token_similarity(left: str, right: str) -> float:
    a = set(normalize_vendor(left).split())
    b = set(normalize_vendor(right).split())
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    intersection = len(a & b)
    union = len(a | b)
    score = intersection / union if union else 0.0
    left_key = normalize_key(left)
    right_key = normalize_key(right)
    if left_key and right_key and (left_key in right_key or right_key in left_key):
        score = max(score, min(len(left_key), len(right_key)) / max(len(left_key), len(right_key)))
    left_initials = "".join(token[0] for token in normalize_vendor(left).split() if token)
    right_initials = "".join(token[0] for token in normalize_vendor(right).split() if token)
    if (
        len(left_key) >= 2
        and len(right_key) >= 2
        and (left_key == right_initials or right_key == left_initials)
    ):
        score = 1.0
    return score


def parse_purl(purl: str) -> dict[str, str]:
    result = {"name": "", "version": "", "vendor": ""}
    text = repair_text(purl)
    if not text.startswith("pkg:"):
        return result

    body = text[4:].split("#", 1)[0].split("?", 1)[0]
    if "@" in body:
        body, version = body.rsplit("@", 1)
        result["version"] = unquote(version)
    parts = body.split("/", 1)
    path = parts[1] if len(parts) == 2 else parts[0]
    segments = [unquote(part) for part in path.split("/") if part]
    if segments:
        result["name"] = segments[-1]
    if len(segments) > 1:
        result["vendor"] = "/".join(segments[:-1])
    return result


def parse_cpe(cpe: str) -> dict[str, str]:
    result = {"name": "", "version": "", "vendor": ""}
    text = repair_text(cpe)
    if not text.startswith("cpe:2.3:"):
        return result
    parts = text.split(":")
    if len(parts) < 6:
        return result
    result["vendor"] = parts[3].replace("\\", "").replace("_", " ")
    result["name"] = parts[4].replace("\\", "").replace("_", " ")
    result["version"] = "" if parts[5] in ("*", "-") else parts[5].replace("\\", "")
    return result


def enrich_component(component: Component) -> Component:
    purl = parse_purl(component.purl)
    cpe = parse_cpe(component.cpe)
    if not component.name:
        component.name = cpe["name"] or purl["name"]
    if not component.version:
        component.version = cpe["version"] or purl["version"]
    if not component.vendor:
        component.vendor = cpe["vendor"] or purl["vendor"]
    return component


def _load_product_aliases() -> list[dict[str, str]]:
    if not ALIAS_FILE.exists():
        return []
    with ALIAS_FILE.open("r", encoding="utf-8-sig", newline="") as handle:
        return [
            {key: repair_text(value) for key, value in row.items()}
            for row in csv.DictReader(handle)
        ]


PRODUCT_ALIASES = _load_product_aliases()


def query_identity(component: Component) -> tuple[str, str]:
    component_name = normalize_key(component.name)
    component_vendor = normalize_key(component.vendor)
    for alias in PRODUCT_ALIASES:
        if normalize_key(alias.get("component_name")) != component_name:
            continue
        alias_vendor = normalize_key(alias.get("component_vendor"))
        if alias_vendor and component_vendor and alias_vendor != component_vendor:
            continue
        return (
            alias.get("euvd_product") or component.name,
            alias.get("euvd_vendor") or component.vendor,
        )

    product = re.sub(r"[_-]+", " ", component.name).strip()
    vendor = re.sub(r"[_-]+", " ", component.vendor).strip()
    return product, vendor


def _coerce_version(value: str) -> Version | None:
    text = repair_text(value).strip().lstrip("vV")
    text = re.sub(r"[^0-9A-Za-z.+!_-].*$", "", text)
    if not text:
        return None
    try:
        return Version(text)
    except InvalidVersion:
        numeric = re.findall(r"\d+", text)
        if not numeric:
            return None
        try:
            return Version(".".join(numeric))
        except InvalidVersion:
            return None


def _compare_versions(left: str, right: str) -> int | None:
    a = _coerce_version(left)
    b = _coerce_version(right)
    if a is None or b is None:
        return None
    return (a > b) - (a < b)


def version_is_affected(component_version: str, affected_text: str) -> tuple[bool | None, str]:
    version = repair_text(component_version)
    expression = repair_text(affected_text)
    if not version:
        return None, "SBOM 未提供版本"
    if not expression:
        return None, "EUVD 未提供结构化受影响版本"

    lowered = expression.casefold().strip()
    lowered = lowered.replace("≤", "<=").replace("≥", ">=")
    lowered = lowered.replace("–", "-").replace("—", "-")
    if lowered in {"*", "all", "any", "all versions", "unspecified"}:
        return True, f"EUVD 标记所有版本受影响: {expression}"

    version_pattern = r"[vV]?\d+(?:[._-][0-9A-Za-z]+)*"

    range_patterns = [
        rf"from\s+({version_pattern})\s+up\s+to\s+(?:and\s+including\s+)?({version_pattern})",
        rf"(?:from\s+)?({version_pattern})\s+(?:through|to|-)\s+({version_pattern})",
        rf"({version_pattern})\s*<=\s*({version_pattern})",
    ]
    for pattern in range_patterns:
        match = re.search(pattern, lowered)
        if match:
            low, high = match.group(1), match.group(2)
            low_cmp = _compare_versions(version, low)
            high_cmp = _compare_versions(version, high)
            if low_cmp is None or high_cmp is None:
                return None, f"无法可靠解析版本范围: {expression}"
            return low_cmp >= 0 and high_cmp <= 0, f"EUVD 版本范围 {low} 至 {high}"

    upper_inclusive_patterns = [
        rf"(?:0\s*)?<=\s*({version_pattern})",
        rf"(?:up\s+to|through)\s+({version_pattern})",
        rf"({version_pattern})\s+(?:and\s+prior|or\s+earlier|and\s+earlier|and\s+below)",
    ]
    for pattern in upper_inclusive_patterns:
        match = re.search(pattern, lowered)
        if match:
            limit = match.group(1)
            comparison = _compare_versions(version, limit)
            if comparison is None:
                return None, f"无法可靠解析上限版本: {expression}"
            return comparison <= 0, f"EUVD 版本上限包含 {limit}"

    upper_exclusive_patterns = [
        rf"<\s*({version_pattern})",
        rf"(?:before|prior\s+to|earlier\s+than)\s+({version_pattern})",
    ]
    for pattern in upper_exclusive_patterns:
        match = re.search(pattern, lowered)
        if match:
            limit = match.group(1)
            comparison = _compare_versions(version, limit)
            if comparison is None:
                return None, f"无法可靠解析上限版本: {expression}"
            return comparison < 0, f"EUVD 版本上限不包含 {limit}"

    lower_inclusive = re.search(rf">=\s*({version_pattern})", lowered)
    if lower_inclusive:
        limit = lower_inclusive.group(1)
        comparison = _compare_versions(version, limit)
        if comparison is None:
            return None, f"无法可靠解析下限版本: {expression}"
        return comparison >= 0, f"EUVD 版本下限包含 {limit}"

    if re.fullmatch(version_pattern, lowered):
        comparison = _compare_versions(version, lowered)
        if comparison is None:
            return None, f"无法可靠比较版本: {expression}"
        return comparison == 0, f"EUVD 指定版本 {expression}"

    # Fuzzy rescue (VALIDATION_REPORT §3 #3): prose the strict patterns
    # above missed. Conservative — only rules with unambiguous range
    # semantics decide True/False; bare product+version mentions, "fixed in",
    # and placeholders stay None (human review), since guessing True there
    # would over-include unrelated older releases.

    # "V and later / above / newer" → affected >= V (lower inclusive).
    later = re.search(
        rf"({version_pattern})\s+and\s+(?:later|above|newer)",
        lowered,
    )
    if later:
        comparison = _compare_versions(version, later.group(1))
        if comparison is not None:
            return comparison >= 0, f"EUVD 标记 {later.group(1)} 及以后受影响"

    # "before <filler words> V" — strict `before V` failed because product-
    # name words sit between 'before' and the version (e.g. "before Linux
    # kernel 2.4.20", "before version 6.16"); strip them.
    before_filler = re.search(
        rf"before\s+(?:[a-z][a-z]*\s+){{0,4}}({version_pattern})",
        lowered,
    )
    if before_filler:
        comparison = _compare_versions(version, before_filler.group(1))
        if comparison is not None:
            return comparison < 0, f"EUVD 版本上限不包含 {before_filler.group(1)}"

    return None, f"需人工核对 EUVD 版本表达式: {expression}"


class EuvdClient:
    _local_validation_cache: tuple[tuple[Any, ...], dict[str, Any]] | None = None

    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.semaphore = asyncio.Semaphore(CONCURRENCY)
        self.request_lock = asyncio.Lock()
        self.last_request_at = 0.0
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(CACHE_DB, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _expected_local_sha256() -> tuple[str, str]:
        if LOCAL_EUVD_EXPECTED_SHA256:
            expected = LOCAL_EUVD_EXPECTED_SHA256
            source = "EUVD_LOCAL_DB_SHA256"
        else:
            try:
                expected = LOCAL_EUVD_SHA256_FILE.read_text(
                    encoding="ascii"
                ).split()[0].strip().casefold()
            except (OSError, IndexError, UnicodeDecodeError):
                return "", f"缺少外部预期 SHA-256 文件: {LOCAL_EUVD_SHA256_FILE}"
            source = str(LOCAL_EUVD_SHA256_FILE)
        if not SHA256_PATTERN.fullmatch(expected):
            return "", f"外部预期 SHA-256 无效: {source}"
        return expected, source

    @classmethod
    def _local_validation(cls) -> dict[str, Any]:
        if not LOCAL_EUVD_DB.is_file():
            return {
                "ok": False,
                "status": "missing",
                "detail": f"本地 EUVD 快照不存在: {LOCAL_EUVD_DB}",
                "expected_sha256": "",
                "actual_sha256": "",
            }
        expected, expected_source = cls._expected_local_sha256()
        if not expected:
            return {
                "ok": False,
                "status": "unverified",
                "detail": expected_source,
                "expected_sha256": "",
                "actual_sha256": "",
            }
        before = LOCAL_EUVD_DB.stat()
        cache_key = (
            str(LOCAL_EUVD_DB.resolve()),
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            expected,
        )
        cached = cls._local_validation_cache
        if cached is not None and cached[0] == cache_key:
            return dict(cached[1])
        try:
            actual = cls._sha256_file(LOCAL_EUVD_DB)
            after = LOCAL_EUVD_DB.stat()
        except OSError as exc:
            return {
                "ok": False,
                "status": "unavailable",
                "detail": f"本地 EUVD 快照哈希校验失败: {repair_text(exc)}",
                "expected_sha256": expected,
                "actual_sha256": "",
            }
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            result = {
                "ok": False,
                "status": "changed_during_validation",
                "detail": "本地 EUVD 快照在哈希校验期间发生变化",
                "expected_sha256": expected,
                "actual_sha256": actual,
            }
        elif actual != expected:
            result = {
                "ok": False,
                "status": "hash_mismatch",
                "detail": "本地 EUVD 快照 SHA-256 与容器外部期望值不一致",
                "expected_sha256": expected,
                "actual_sha256": actual,
            }
        else:
            result = {
                "ok": True,
                "status": "verified",
                "detail": "",
                "expected_sha256": expected,
                "actual_sha256": actual,
                "expected_sha256_source": expected_source,
            }
        cls._local_validation_cache = (cache_key, dict(result))
        return result

    @classmethod
    def _local_available(cls) -> bool:
        return bool(cls._local_validation().get("ok"))

    @staticmethod
    def _local_connect() -> sqlite3.Connection:
        validation = EuvdClient._local_validation()
        if not validation.get("ok"):
            raise ValueError(
                "本地 EUVD 只读快照未通过外部哈希校验: "
                + str(validation.get("detail") or validation.get("status"))
            )
        try:
            connection = sqlite3.connect(
                f"file:{LOCAL_EUVD_DB.resolve().as_posix()}?mode=ro&immutable=1",
                uri=True,
                timeout=30,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            return connection
        except sqlite3.Error as exc:
            raise ValueError(f"本地 EUVD 只读快照不可用: {repair_text(exc)}") from exc

    @classmethod
    def local_snapshot_status(cls) -> dict[str, Any] | None:
        validation = cls._local_validation()
        if validation.get("status") == "missing":
            return None
        if not validation.get("ok"):
            return {
                "status": "local_unavailable",
                "source_id": "EUVD_LOCAL_MIRROR",
                "detail": validation.get("detail", ""),
                "snapshot_validation_status": validation.get("status", ""),
                "snapshot_expected_sha256": validation.get("expected_sha256", ""),
                "snapshot_actual_sha256": validation.get("actual_sha256", ""),
                "network_fallback_enabled": NETWORK_FALLBACK,
            }
        try:
            with closing(cls._local_connect()) as connection:
                metadata = {
                    str(row["key"]): str(row["value"])
                    for row in connection.execute(
                        "SELECT key, value FROM web_snapshot_metadata"
                    )
                }
        except (sqlite3.Error, ValueError) as exc:
            return {
                "status": "local_unavailable",
                "source_id": "EUVD_LOCAL_MIRROR",
                "detail": repair_text(exc),
            }
        reference_freshness = metadata.get("reference_data_freshness", "unknown")
        degraded = reference_freshness != "fresh"
        return {
            "status": "local_degraded" if degraded else "local_ready",
            "source_id": metadata.get("source_id", "EUVD_LOCAL_MIRROR"),
            "query_mode": "local-read-only-snapshot",
            "snapshot_created_at": metadata.get("snapshot_created_at", ""),
            "last_successful_to_date": metadata.get("last_successful_to_date", ""),
            "reference_data_freshness": reference_freshness,
            "vulnerability_count": int(metadata.get("vulnerability_count", "0") or 0),
            "mapping_count": int(metadata.get("mapping_count", "0") or 0),
            "known_exploited_count": int(
                metadata.get("known_exploited_count", "0") or 0
            ),
            "product_index_count": int(metadata.get("product_index_count", "0") or 0),
            "source_db_sha256": metadata.get("source_db_sha256", ""),
            "snapshot_sha256": validation.get("actual_sha256", ""),
            "snapshot_expected_sha256": validation.get("expected_sha256", ""),
            "snapshot_validation_status": validation.get("status", ""),
            "integrity_check_at_build": metadata.get(
                "snapshot_integrity_check_at_build", "not-recorded"
            ),
            "network_required_for_queries": False,
            "network_fallback_enabled": NETWORK_FALLBACK,
            "important_boundary": metadata.get("consumer_boundary", ""),
        }

    @classmethod
    def list_euvd_records(
        cls,
        page: int = 1,
        page_size: int = 50,
        sort: str = "euvd_id_desc",
        q: str = "",
        actively_exploited_only: bool = False,
    ) -> dict[str, Any] | None:
        """改进1：只读快照上的 EUVD 目录浏览（分页 + 搜索），不联网、不写快照。

        搜索 q：CVE 前缀（CVE-2024-）走 cve_euvd_mapping PK；否则按 EUVD ID 前缀
        走 vulnerabilities PK（SQLite LIKE 大小写不敏感）。默认排序 euvd_id_desc
        ——updated_raw/published_raw 存的是 EUVD 原文字符串（如 "Sep 9, 2025,
        8:59:21 PM"），字典序≠日期序；PK 序（创建序）可靠且走索引。返回 None
        表示本地快照不可用或哈希失配（调用方应 503，不得静默降级）。

        actively_exploited_only：只返回积极利用漏洞（CRA Art.3(42)），SQL 层按
        KEV 子表过滤；每条 record 的 actively_exploited 字段在 Python 层取
        KEV∪record.exploitedSince（与 apply_exploitation_evidence 一致）。注意
        设计约束#5：未命中 KEV ≠ "未被利用"，只表示"当前快照未列入"。
        """
        if not cls._local_validation().get("ok"):
            return None
        page = max(1, int(page))
        page_size = max(1, min(100, int(page_size)))
        offset = (page - 1) * page_size
        q = (q or "").strip()
        order = "euvd_id ASC" if sort == "euvd_id_asc" else "euvd_id DESC"

        with closing(cls._local_connect()) as connection:
            euvd_ids: list[str] = []
            total = 0
            kev_subquery = (
                "euvd_id IN (SELECT euvd_id FROM known_exploited)"
                if actively_exploited_only
                else ""
            )
            if q.upper().startswith("CVE"):
                pattern = f"{q}%"  # LIKE 大小写不敏感
                kev_cond = f"AND {kev_subquery}" if kev_subquery else ""
                total = int(
                    connection.execute(
                        f"SELECT COUNT(DISTINCT euvd_id) FROM cve_euvd_mapping "
                        f"WHERE cve_id LIKE ? {kev_cond}",
                        (pattern,),
                    ).fetchone()[0]
                )
                rows = connection.execute(
                    f"SELECT DISTINCT euvd_id FROM cve_euvd_mapping "
                    f"WHERE cve_id LIKE ? {kev_cond} ORDER BY euvd_id DESC "
                    f"LIMIT ? OFFSET ?",
                    (pattern, page_size, offset),
                ).fetchall()
                euvd_ids = [str(r["euvd_id"]) for r in rows]
            else:
                conditions: list[str] = []
                params_total: list[Any] = []
                params_list: list[Any] = []
                if q:
                    conditions.append("euvd_id LIKE ?")
                    params_total.append(f"{q}%")
                    params_list.append(f"{q}%")
                if kev_subquery:
                    conditions.append(kev_subquery)
                where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
                total = int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM vulnerabilities {where}", params_total
                    ).fetchone()[0]
                )
                rows = connection.execute(
                    f"SELECT euvd_id FROM vulnerabilities {where} ORDER BY {order} "
                    f"LIMIT ? OFFSET ?",
                    [*params_list, page_size, offset],
                ).fetchall()
                euvd_ids = [str(r["euvd_id"]) for r in rows]

            if not euvd_ids:
                return {
                    "records": [], "total": total, "page": page,
                    "page_size": page_size, "sort": sort, "query": q,
                }

            placeholders = ",".join("?" * len(euvd_ids))
            rec_rows = connection.execute(
                f"SELECT euvd_id, record_json FROM vulnerabilities "
                f"WHERE euvd_id IN ({placeholders})",
                euvd_ids,
            ).fetchall()
            rec_map = {str(r["euvd_id"]): str(r["record_json"]) for r in rec_rows}

            kev_rows = connection.execute(
                f"SELECT DISTINCT euvd_id FROM known_exploited "
                f"WHERE euvd_id IN ({placeholders})",
                euvd_ids,
            ).fetchall()
            kev_set = {str(r["euvd_id"]) for r in kev_rows}

            cve_rows = connection.execute(
                f"SELECT euvd_id, cve_id FROM cve_euvd_mapping "
                f"WHERE euvd_id IN ({placeholders})",
                euvd_ids,
            ).fetchall()
            cve_map: dict[str, list[str]] = {}
            for r in cve_rows:
                cve_map.setdefault(str(r["euvd_id"]), []).append(str(r["cve_id"]))

            source_rows = connection.execute(
                f"SELECT DISTINCT euvd_id, source FROM known_exploited_sources "
                f"WHERE euvd_id IN ({placeholders})",
                euvd_ids,
            ).fetchall()
            source_map: dict[str, list[str]] = {}
            for r in source_rows:
                source_map.setdefault(str(r["euvd_id"]), []).append(str(r["source"]))

        records: list[dict[str, Any]] = []
        for eid in euvd_ids:
            raw = rec_map.get(eid)
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
            products: list[dict[str, str]] = []
            for entry in (payload.get("enisaIdProduct") or [])[:3]:
                if isinstance(entry, dict):
                    prod = entry.get("product")
                    if not isinstance(prod, dict):
                        continue
                    vendor = prod.get("vendor")
                    products.append(
                        {
                            "name": str(prod.get("name") or ""),
                            "vendor": str(vendor.get("name") or "")
                            if isinstance(vendor, dict)
                            else "",
                        }
                    )
            score = payload.get("baseScore")
            try:
                score_val = float(score) if score is not None else None
            except (TypeError, ValueError):
                score_val = None
            if score_val is None:
                severity = "未评级"
            elif score_val >= 9:
                severity = "严重"
            elif score_val >= 7:
                severity = "高"
            elif score_val >= 4:
                severity = "中"
            else:
                severity = "低"
            cves = cve_map.get(eid, [])
            exploited_since = str(payload.get("exploitedSince") or "")
            is_kev = eid in kev_set
            records.append(
                {
                    "euvd_id": eid,
                    "cve_id": cves[0] if cves else None,
                    "cve_ids": cves,
                    "base_score": score,
                    "severity": severity,
                    "date_published": str(payload.get("datePublished") or ""),
                    "date_updated": str(payload.get("dateUpdated") or ""),
                    "products": products,
                    "kev": is_kev,
                    "actively_exploited": is_kev or bool(exploited_since),
                    "exploited_since": exploited_since,
                    "kev_sources": source_map.get(eid, []),
                    "description_preview": str(payload.get("description") or "")[:200],
                }
            )

        return {
            "records": records,
            "total": total,
            "page": page,
            "page_size": page_size,
            "sort": sort,
            "query": q,
            "actively_exploited_only": actively_exploited_only,
        }

    @classmethod
    def local_feed_snapshots(cls) -> list[dict[str, Any]] | None:
        status = cls.local_snapshot_status()
        if status is None or status.get("status") == "local_unavailable":
            return None
        with closing(cls._local_connect()) as connection:
            metadata = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key, value FROM web_snapshot_metadata"
                )
            }
        try:
            versions = json.loads(metadata.get("current_source_versions_json", "[]"))
        except json.JSONDecodeError:
            versions = []
        feed_status = (
            "fresh"
            if metadata.get("reference_data_freshness") == "fresh"
            else "degraded"
        )
        rows = [
            {
                "feed_name": "euvd-vulnerabilities",
                "status": "degraded" if status.get("status") == "local_degraded" else "fresh",
                "retrieved_at": metadata.get("last_successful_to_date", ""),
                "sha256": metadata.get("source_db_sha256", ""),
                "record_count": status.get("vulnerability_count", 0),
                "detail": (
                    "本地只读镜像；未命中不能解释为当前 EUVD 不存在。"
                    if status.get("status") == "local_degraded"
                    else "本地只读镜像。"
                ),
            }
        ]
        for item in versions if isinstance(versions, list) else []:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "feed_name": str(item.get("source_name") or "EUVD-reference"),
                    "status": feed_status,
                    "retrieved_at": str(
                        item.get("last_modified")
                        or item.get("last_checked_at")
                        or ""
                    ),
                    "sha256": str(item.get("content_sha256") or ""),
                    "record_count": int(item.get("record_count") or 0),
                    "detail": (
                        "显式导入的 last-known-good 文件；不是当天网络刷新。"
                        if int(item.get("http_status") or 0) == 0
                        else "EUVD 网络快照。"
                    ),
                }
            )
        return rows

    @staticmethod
    def _current_source_metadata(
        connection: sqlite3.Connection,
        source_name: str,
    ) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT last_checked_at, last_modified, content_sha256,
                   record_count, http_status, source_url
            FROM data_source_versions
            WHERE source_name = ? AND is_current = 1
            """,
            (source_name,),
        ).fetchone()
        return dict(row) if row else {}

    @staticmethod
    def _local_metadata(connection: sqlite3.Connection) -> dict[str, str]:
        return {
            str(row["key"]): str(row["value"])
            for row in connection.execute(
                "SELECT key, value FROM web_snapshot_metadata"
            )
        }

    @classmethod
    def _query_local_cve_mapping(
        cls,
        requested_cves: set[str],
    ) -> tuple[dict[str, list[str]], dict[str, Any]]:
        mapping: dict[str, list[str]] = {cve: [] for cve in requested_cves}
        try:
            with closing(cls._local_connect()) as connection:
                requested = sorted(requested_cves)
                for offset in range(0, len(requested), 900):
                    batch = requested[offset : offset + 900]
                    placeholders = ",".join("?" for _ in batch)
                    for row in connection.execute(
                        "SELECT cve_id, euvd_id FROM cve_euvd_mapping "
                        f"WHERE cve_id IN ({placeholders}) ORDER BY cve_id, euvd_id",
                        batch,
                    ):
                        mapping[str(row["cve_id"])].append(str(row["euvd_id"]))
                source = cls._current_source_metadata(
                    connection, "cve_euvd_mapping"
                )
                metadata = cls._local_metadata(connection)
        except sqlite3.Error as exc:
            raise ValueError(
                f"本地 CVE→EUVD 映射查询失败: {repair_text(exc)}"
            ) from exc
        return mapping, {
            "mapping_checked_at": source.get("last_checked_at", ""),
            "mapping_downloaded_at": source.get("last_modified", ""),
            "mapping_snapshot_sha256": source.get("content_sha256", ""),
            "mapping_snapshot_age_seconds": None,
            "mapping_freshness": metadata.get(
                "reference_data_freshness", "unknown"
            ),
            "mapping_snapshot_source": "local-read-only-mirror",
            "mapping_fallback_error": "",
            "mirror_last_successful_to_date": metadata.get(
                "last_successful_to_date", ""
            ),
        }

    @classmethod
    def _query_local_kev(
        cls,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
        index: dict[str, dict[str, Any]] = {}
        try:
            with closing(cls._local_connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT kev.cve_id, kev.euvd_id, kev.date_added,
                           GROUP_CONCAT(src.source, ',') AS sources
                    FROM known_exploited kev
                    LEFT JOIN known_exploited_sources src
                      ON src.cve_id = kev.cve_id AND src.euvd_id = kev.euvd_id
                    GROUP BY kev.cve_id, kev.euvd_id, kev.date_added
                    """
                ).fetchall()
                for row in rows:
                    entry = {
                        "cveId": str(row["cve_id"]),
                        "euvdId": str(row["euvd_id"]),
                        "dateAdded": str(row["date_added"]),
                        "sources": [
                            value
                            for value in str(row["sources"] or "").split(",")
                            if value
                        ],
                    }
                    if entry["cveId"]:
                        index[entry["cveId"]] = entry
                    if entry["euvdId"]:
                        index[entry["euvdId"]] = entry
                source = cls._current_source_metadata(
                    connection, "known_exploited"
                )
                metadata = cls._local_metadata(connection)
        except sqlite3.Error as exc:
            raise ValueError(f"本地 KEV 查询失败: {repair_text(exc)}") from exc
        return index, {
            "evidence_checked_at": source.get("last_checked_at", ""),
            "kev_downloaded_at": source.get("last_modified", ""),
            "kev_snapshot_sha256": source.get("content_sha256", ""),
            "kev_snapshot_age_seconds": None,
            "kev_freshness": metadata.get("reference_data_freshness", "unknown"),
            "kev_snapshot_source": "local-read-only-mirror",
            "kev_fallback_error": "",
            "mirror_last_successful_to_date": metadata.get(
                "last_successful_to_date", ""
            ),
        }

    @classmethod
    def _query_local_detail(cls, euvd_id: str) -> dict[str, Any] | None:
        try:
            with closing(cls._local_connect()) as connection:
                row = connection.execute(
                    "SELECT record_json FROM vulnerabilities WHERE euvd_id = ?",
                    (repair_text(euvd_id).upper(),),
                ).fetchone()
        except sqlite3.Error as exc:
            raise ValueError(f"本地 EUVD 详情查询失败: {repair_text(exc)}") from exc
        if row is None:
            return None
        try:
            return json.loads(str(row["record_json"]))
        except json.JSONDecodeError as exc:
            raise ValueError(f"本地 EUVD 记录 JSON 无效: {euvd_id}") from exc

    @classmethod
    def _query_local_product(
        cls,
        product: str,
        vendor: str,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        product_key = normalize_key(product)
        vendor_key = normalize_key(vendor) if vendor else ""
        limit = MAX_PAGES * 100
        try:
            with closing(cls._local_connect()) as connection:

                def _fetch(where_extra: str, params: list[str]) -> tuple[list, int]:
                    total = int(
                        connection.execute(
                            "SELECT COUNT(DISTINCT p.euvd_id) FROM local_products p "
                            "WHERE p.product_key = ?" + where_extra,
                            [product_key, *params],
                        ).fetchone()[0]
                    )
                    fetched = connection.execute(
                        """
                        SELECT DISTINCT v.euvd_id, v.record_json, v.updated_raw
                        FROM local_products p
                        JOIN vulnerabilities v ON v.euvd_id = p.euvd_id
                        WHERE p.product_key = ?
                        """
                        + where_extra
                        + """
                        ORDER BY v.updated_raw DESC, v.euvd_id
                        LIMIT ?
                        """,
                        [product_key, *params, limit],
                    ).fetchall()
                    return fetched, total

                # vendor+product joint match narrows Linux/Chrome-style wide
                # buckets (VALIDATION_REPORT §3). If the joint match is empty
                # the SBOM-supplied vendor may just disagree with EUVD's vendor
                # spelling — widen back to product-only rather than miss silently
                # (design constraint #5: 未命中≠不存在).
                if vendor_key:
                    rows, total = _fetch(" AND p.vendor_key = ?", [vendor_key])
                    vendor_filter = "joint" if rows else "fallback"
                    if not rows:
                        rows, total = _fetch("", [])
                else:
                    rows, total = _fetch("", [])
                    vendor_filter = "none"
                metadata = cls._local_metadata(connection)
        except sqlite3.Error as exc:
            raise ValueError(f"本地 EUVD 产品查询失败: {repair_text(exc)}") from exc
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                items.append(json.loads(str(row["record_json"])))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"本地 EUVD 记录 JSON 无效: {row['euvd_id']}"
                ) from exc
        return items, {
            "api_total": total,
            "fetched_count": len(items),
            "pages_fetched": (len(items) + 99) // 100 if items else 0,
            "truncated": total > len(items),
            "query_mode": "local-mirror-product-exact",
            "requested_vendor": vendor,
            "vendor_filter": vendor_filter,
            "mirror_snapshot_created_at": metadata.get("snapshot_created_at", ""),
            "mirror_last_successful_to_date": metadata.get(
                "last_successful_to_date", ""
            ),
            "mirror_reference_freshness": metadata.get(
                "reference_data_freshness", "unknown"
            ),
        }

    def _init_db(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS search_cache (
                    cache_key TEXT PRIMARY KEY,
                    fetched_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def _read_cache(self, cache_key: str) -> dict[str, Any] | None:
        cutoff = int(time.time()) - CACHE_HOURS * 3600
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT payload FROM search_cache WHERE cache_key = ? AND fetched_at >= ?",
                (cache_key, cutoff),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def _write_cache(self, cache_key: str, payload: dict[str, Any]) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO search_cache(cache_key, fetched_at, payload)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    fetched_at = excluded.fetched_at,
                    payload = excluded.payload
                """,
                (cache_key, int(time.time()), json.dumps(payload, ensure_ascii=False)),
            )

    async def _request(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        response: httpx.Response | None = None
        for attempt in range(5):
            async with self.semaphore:
                async with self.request_lock:
                    elapsed = time.monotonic() - self.last_request_at
                    if elapsed < 0.45:
                        await asyncio.sleep(0.45 - elapsed)
                    response = await client.get(f"{EUVD_BASE_URL}{path}", params=params)
                    self.last_request_at = time.monotonic()
            if response.status_code != 429:
                break
            retry_after = response.headers.get("Retry-After")
            wait_seconds = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt
            await asyncio.sleep(min(12.0, max(1.0, wait_seconds)))
        if response is None:
            raise RuntimeError("EUVD request was not executed")
        return response

    async def _download_snapshot(
        self,
        client: httpx.AsyncClient,
        path: str,
        target: Path,
        force: bool = False,
    ) -> tuple[bytes, dict[str, Any]]:
        cutoff = time.time() - CACHE_HOURS * 3600
        source = "cache"
        fallback_error = ""
        if not force and target.exists() and target.stat().st_mtime >= cutoff:
            content = await asyncio.to_thread(target.read_bytes)
        else:
            try:
                response = await self._request(client, path)
                response.raise_for_status()
                content = response.content
                if not content:
                    raise ValueError("EUVD 快照为空")
                if target.suffix == ".json":
                    parsed = json.loads(content)
                    if not isinstance(parsed, list):
                        raise ValueError("EUVD KEV 快照根节点不是列表")
                else:
                    header = content[:200].decode("utf-8-sig", errors="replace")
                    if "cve_id" not in header or "euvd_id" not in header:
                        raise ValueError("EUVD CVE 映射快照表头无效")
                temporary = target.with_suffix(target.suffix + f".{time.time_ns()}.tmp")
                await asyncio.to_thread(temporary.write_bytes, content)
                temporary.replace(target)
                source = "network"
            except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError) as exc:
                if not target.exists():
                    raise
                content = await asyncio.to_thread(target.read_bytes)
                source = "last_known_good"
                fallback_error = repair_text(exc)
        checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        digest = hashlib.sha256(content).hexdigest()
        downloaded_at = datetime.fromtimestamp(
            target.stat().st_mtime, tz=timezone.utc
        ).isoformat(timespec="seconds")
        age_seconds = max(0, int(time.time() - target.stat().st_mtime))
        return content, {
            "checked_at": checked_at,
            "downloaded_at": downloaded_at,
            "snapshot_sha256": digest,
            "age_seconds": age_seconds,
            "freshness": "fresh" if age_seconds <= CACHE_HOURS * 3600 else "stale",
            "source": source,
            "fallback_error": fallback_error,
        }

    async def cve_mapping(
        self,
        client: httpx.AsyncClient,
        requested_cves: set[str],
    ) -> tuple[dict[str, list[str]], dict[str, Any]]:
        if not requested_cves:
            return {}, {}
        if await asyncio.to_thread(self._local_available):
            return await asyncio.to_thread(
                self._query_local_cve_mapping, requested_cves
            )
        if not NETWORK_FALLBACK:
            raise ValueError(
                "本地 EUVD 快照不可用或未通过哈希校验，且网络回退未启用"
            )
        content, snapshot_meta = await self._download_snapshot(
            client,
            "/api/dump/cve-euvd-mapping",
            CVE_MAPPING_FILE,
        )
        mapping: dict[str, list[str]] = {cve: [] for cve in requested_cves}
        reader = csv.DictReader(content.decode("utf-8-sig").splitlines())
        for row in reader:
            cve_id = repair_text(row.get("cve_id")).upper()
            euvd_id = repair_text(row.get("euvd_id")).upper()
            if cve_id in mapping and EUVD_PATTERN.fullmatch(euvd_id):
                mapping[cve_id].append(euvd_id)
        return mapping, {
            "mapping_checked_at": snapshot_meta["checked_at"],
            "mapping_downloaded_at": snapshot_meta["downloaded_at"],
            "mapping_snapshot_sha256": snapshot_meta["snapshot_sha256"],
            "mapping_snapshot_age_seconds": snapshot_meta["age_seconds"],
            "mapping_freshness": snapshot_meta["freshness"],
            "mapping_snapshot_source": snapshot_meta["source"],
            "mapping_fallback_error": snapshot_meta["fallback_error"],
        }

    async def kev_index(
        self,
        client: httpx.AsyncClient,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
        if await asyncio.to_thread(self._local_available):
            return await asyncio.to_thread(self._query_local_kev)
        if not NETWORK_FALLBACK:
            raise ValueError(
                "本地 EUVD 快照不可用或未通过哈希校验，且网络回退未启用"
            )
        content, snapshot_meta = await self._download_snapshot(
            client,
            "/api/kev/dump",
            KEV_DUMP_FILE,
        )
        payload = json.loads(content)
        index: dict[str, dict[str, Any]] = {}
        for entry in payload if isinstance(payload, list) else []:
            cve_id = repair_text(entry.get("cveId")).upper()
            euvd_id = repair_text(entry.get("euvdId")).upper()
            if cve_id:
                index[cve_id] = entry
            if euvd_id:
                index[euvd_id] = entry
        return index, {
            "evidence_checked_at": snapshot_meta["checked_at"],
            "kev_downloaded_at": snapshot_meta["downloaded_at"],
            "kev_snapshot_sha256": snapshot_meta["snapshot_sha256"],
            "kev_snapshot_age_seconds": snapshot_meta["age_seconds"],
            "kev_freshness": snapshot_meta["freshness"],
            "kev_snapshot_source": snapshot_meta["source"],
            "kev_fallback_error": snapshot_meta["fallback_error"],
        }

    async def detail(
        self,
        client: httpx.AsyncClient,
        euvd_id: str,
    ) -> dict[str, Any] | None:
        if await asyncio.to_thread(self._local_available):
            return await asyncio.to_thread(self._query_local_detail, euvd_id)
        if not NETWORK_FALLBACK:
            raise ValueError(
                "本地 EUVD 快照不可用或未通过哈希校验，且网络回退未启用"
            )
        cache_key = json.dumps({"enisaid": euvd_id}, sort_keys=True)
        cached = await asyncio.to_thread(self._read_cache, cache_key)
        if cached is not None:
            return None if cached.get("_not_found") else cached
        response = await self._request(client, "/api/enisaid", {"id": euvd_id})
        if response.status_code == 204:
            await asyncio.to_thread(self._write_cache, cache_key, {"_not_found": True})
            return None
        response.raise_for_status()
        payload = response.json()
        await asyncio.to_thread(self._write_cache, cache_key, payload)
        return payload

    async def _get_page(
        self,
        client: httpx.AsyncClient,
        product: str,
        page: int,
    ) -> dict[str, Any]:
        cache_key = json.dumps(
            {"product": product, "page": page},
            sort_keys=True,
            ensure_ascii=False,
        )
        cached = await asyncio.to_thread(self._read_cache, cache_key)
        if cached is not None:
            return cached

        params: dict[str, Any] = {"product": product, "page": page, "size": 100}
        response: httpx.Response | None = None
        for attempt in range(5):
            async with self.semaphore:
                async with self.request_lock:
                    elapsed = time.monotonic() - self.last_request_at
                    if elapsed < 0.45:
                        await asyncio.sleep(0.45 - elapsed)
                    response = await client.get(f"{EUVD_BASE_URL}/api/search", params=params)
                    self.last_request_at = time.monotonic()
            if response.status_code != 429:
                break
            retry_after = response.headers.get("Retry-After")
            wait_seconds = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt
            await asyncio.sleep(min(12.0, max(1.0, wait_seconds)))

        if response is None:
            raise RuntimeError("EUVD request was not executed")
        response.raise_for_status()
        payload = response.json()
        await asyncio.to_thread(self._write_cache, cache_key, payload)
        return payload

    async def search(
        self,
        client: httpx.AsyncClient,
        product: str,
        vendor: str,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if not product:
            return [], {
                "api_total": 0,
                "fetched_count": 0,
                "pages_fetched": 0,
                "truncated": False,
                "query_mode": "no-product",
            }

        if await asyncio.to_thread(self._local_available):
            return await asyncio.to_thread(
                self._query_local_product, product, vendor
            )

        if not NETWORK_FALLBACK:
            raise ValueError(
                "本地 EUVD 快照不可用或未通过哈希校验，且网络回退未启用"
            )

        # EUVD vendor names are not always normalized the same way as SBOM suppliers.
        # Query the complete product result set and verify vendor/version locally so
        # spelling differences do not silently remove candidates at the API layer.
        first = await self._get_page(client, product, 0)
        items = list(first.get("items") or [])
        total = int(first.get("total") or len(items))
        available_pages = max(1, (total + 99) // 100)
        pages = min(MAX_PAGES, available_pages)
        if pages > 1:
            remaining = await asyncio.gather(
                *[self._get_page(client, product, page) for page in range(1, pages)]
            )
            for payload in remaining:
                items.extend(payload.get("items") or [])

        unique: dict[str, dict[str, Any]] = {}
        for item in items:
            item_id = repair_text(item.get("id"))
            if item_id:
                unique[item_id] = item
        deduplicated = list(unique.values())
        return deduplicated, {
            "api_total": total,
            "fetched_count": len(deduplicated),
            "pages_fetched": pages,
            "truncated": available_pages > pages,
            "query_mode": "product-only-local-vendor-check",
            "requested_vendor": vendor,
        }


async def refresh_public_snapshots(force: bool = True) -> dict[str, dict[str, Any]]:
    """Refresh or inspect the two public EUVD snapshots.

    A stale last-known-good file is returned as degraded evidence when the network
    update fails. It is never presented as a successful current snapshot.
    """

    if not NETWORK_FALLBACK:
        raise ValueError(
            "Web 服务的网络回退未启用；请在独立 EUVD 镜像项目执行正式同步"
        )
    wrapper = EuvdClient()
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(60.0, connect=15.0),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        mapping_content, mapping_meta = await wrapper._download_snapshot(
            client,
            "/api/dump/cve-euvd-mapping",
            CVE_MAPPING_FILE,
            force=force,
        )
        kev_content, kev_meta = await wrapper._download_snapshot(
            client,
            "/api/kev/dump",
            KEV_DUMP_FILE,
            force=force,
        )
    mapping_count = max(
        0, sum(1 for _ in mapping_content.decode("utf-8-sig").splitlines()) - 1
    )
    kev_payload = json.loads(kev_content)
    return {
        "cve-euvd-mapping": {
            **mapping_meta,
            "record_count": mapping_count,
            "status": (
                "degraded"
                if mapping_meta["source"] == "last_known_good"
                else mapping_meta["freshness"]
            ),
        },
        "euvd-kev": {
            **kev_meta,
            "record_count": len(kev_payload) if isinstance(kev_payload, list) else 0,
            "status": (
                "degraded"
                if kev_meta["source"] == "last_known_good"
                else kev_meta["freshness"]
            ),
        },
    }


def _severity(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "未评级"
    if value >= 9.0:
        return "严重"
    if value >= 7.0:
        return "高"
    if value >= 4.0:
        return "中"
    if value > 0:
        return "低"
    return "未评级"


def _item_url(euvd_id: str) -> str:
    return f"https://euvd.enisa.europa.eu/vulnerability/{quote(euvd_id)}"


def evaluate_item(component: Component, item: dict[str, Any]) -> dict[str, Any] | None:
    best: dict[str, Any] | None = None
    evaluation_name, evaluation_vendor = query_identity(component)
    component_name_key = normalize_key(evaluation_name)
    for product_entry in item.get("enisaIdProduct") or []:
        product = product_entry.get("product") or {}
        euvd_name = repair_text(product.get("name"))
        if component_name_key != normalize_key(euvd_name):
            continue

        euvd_vendor = repair_text((product.get("vendor") or {}).get("name"))
        vendor_for_match = evaluation_vendor or component.vendor
        vendor_score = token_similarity(vendor_for_match, euvd_vendor) if vendor_for_match else 0.0
        affected_range = repair_text(product_entry.get("product_version"))
        affected, version_reason = version_is_affected(component.version, affected_range)
        if affected is False:
            continue

        if affected is True and vendor_for_match and vendor_score >= 0.55:
            status = "已匹配"
            confidence = round(85 + min(vendor_score, 1.0) * 15)
        else:
            status = "需复核"
            confidence = 68 if affected is True else 52
            if not component.vendor:
                confidence -= 8
            elif vendor_score < 0.55:
                confidence -= 12

        reasons = [f"产品名精确匹配: {euvd_name}", version_reason]
        if evaluation_name != component.name or evaluation_vendor != component.vendor:
            reasons.append(
                f"产品别名归一化: {evaluation_name} / {evaluation_vendor or '未提供厂商'}"
            )
        if vendor_for_match:
            reasons.append(f"厂商相似度: {vendor_score:.0%}")
        else:
            reasons.append("SBOM 未提供厂商")

        candidate = {
            "component_row": component.row_number,
            "component_name": component.name,
            "component_version": component.version,
            "component_vendor": component.vendor,
            "component_purl": component.purl,
            "component_cpe": component.cpe,
            "euvd_id": repair_text(item.get("id")),
            "alternative_ids": ", ".join(
                part.strip()
                for part in re.split(r"[\r\n,;]+", repair_text(item.get("aliases")))
                if part.strip()
            ),
            "severity": _severity(item.get("baseScore")),
            "cvss_score": item.get("baseScore"),
            "cvss_version": repair_text(item.get("baseScoreVersion")),
            "cvss_vector": repair_text(item.get("baseScoreVector")),
            "epss_percent": item.get("epss"),
            "affected_product": euvd_name,
            "affected_vendor": euvd_vendor,
            "affected_versions": affected_range,
            "published": repair_text(item.get("datePublished")),
            "updated": repair_text(item.get("dateUpdated")),
            "description": repair_text(item.get("description")),
            "references": repair_text(item.get("references")),
            "euvd_url": _item_url(repair_text(item.get("id"))),
            "match_status": status,
            "mapping_status": "产品候选匹配",
            "source_identifier": "",
            "match_basis": "EUVD 产品名检索",
            "component_applicability": (
                "受影响版本条件命中"
                if affected is True and (not vendor_for_match or vendor_score >= 0.55)
                else "待人工核验"
            ),
            "confidence": max(0, min(100, confidence)),
            "match_reason": "；".join(reasons),
        }
        if best is None or candidate["confidence"] > best["confidence"]:
            best = candidate
    return best


def evaluate_identifier_item(
    component: Component,
    item: dict[str, Any],
    source_identifier: str,
    match_basis: str,
) -> dict[str, Any]:
    euvd_id = repair_text(item.get("id")).upper()
    aliases = ", ".join(
        part.strip()
        for part in re.split(r"[\r\n,;]+", repair_text(item.get("aliases")))
        if part.strip()
    )
    evaluation_name, evaluation_vendor = query_identity(component)
    component_name_key = normalize_key(evaluation_name)
    selected_product = ""
    selected_vendor = ""
    selected_versions = ""
    applicability = "待人工核验"
    applicability_reason = "EUVD 映射已确认；客户产品中的版本、配置、可达性和 VEX 仍需人工核验"
    version_miss_reason = ""
    version_uncertain = False

    for product_entry in item.get("enisaIdProduct") or []:
        product = product_entry.get("product") or {}
        euvd_name = repair_text(product.get("name"))
        euvd_vendor = repair_text((product.get("vendor") or {}).get("name"))
        affected_range = repair_text(product_entry.get("product_version"))
        if not selected_product:
            selected_product = euvd_name
            selected_vendor = euvd_vendor
            selected_versions = affected_range
        if not component_name_key or component_name_key != normalize_key(euvd_name):
            continue
        vendor_for_match = evaluation_vendor or component.vendor
        vendor_score = token_similarity(vendor_for_match, euvd_vendor) if vendor_for_match else 0.0
        affected, version_reason = version_is_affected(component.version, affected_range)
        selected_product = euvd_name
        selected_vendor = euvd_vendor
        selected_versions = affected_range
        if affected is False:
            version_miss_reason = version_reason
            continue
        if affected is True and (not vendor_for_match or vendor_score >= 0.55):
            applicability = "受影响版本条件命中"
            applicability_reason = (
                f"{version_reason}；厂商相似度 {vendor_score:.0%}"
                if vendor_for_match
                else f"{version_reason}；SBOM 未提供厂商"
            )
            break
        applicability_reason = (
            f"{version_reason}；厂商相似度 {vendor_score:.0%}，仍需人工核验"
            if vendor_for_match
            else f"{version_reason}；SBOM 未提供厂商，仍需人工核验"
        )
        version_uncertain = True

    if (
        applicability != "受影响版本条件命中"
        and version_miss_reason
        and not version_uncertain
    ):
        applicability = "版本条件不命中"
        applicability_reason = version_miss_reason

    return {
        "component_row": component.row_number,
        "component_name": component.name,
        "component_version": component.version,
        "component_vendor": component.vendor,
        "component_purl": component.purl,
        "component_cpe": component.cpe,
        "input_cve_ids": component.cve_ids,
        "input_euvd_ids": component.euvd_ids,
        "source_identifier": source_identifier,
        "euvd_id": euvd_id,
        "alternative_ids": aliases,
        "severity": _severity(item.get("baseScore")),
        "cvss_score": item.get("baseScore"),
        "cvss_version": repair_text(item.get("baseScoreVersion")),
        "cvss_vector": repair_text(item.get("baseScoreVector")),
        "epss_percent": item.get("epss"),
        "affected_product": selected_product,
        "affected_vendor": selected_vendor,
        "affected_versions": selected_versions,
        "published": repair_text(item.get("datePublished")),
        "updated": repair_text(item.get("dateUpdated")),
        "description": repair_text(item.get("description")),
        "references": repair_text(item.get("references")),
        "euvd_url": _item_url(euvd_id),
        "match_status": "已匹配",
        "mapping_status": "EUVD精确匹配",
        "match_basis": match_basis,
        "component_applicability": applicability,
        "confidence": 100,
        "match_reason": f"{match_basis}: {source_identifier} → {euvd_id}；{applicability_reason}",
    }


def apply_exploitation_evidence(
    candidate: dict[str, Any],
    item: dict[str, Any],
    kev_index: dict[str, dict[str, Any]],
    evidence_meta: dict[str, str],
) -> dict[str, Any]:
    identifiers = [
        candidate.get("euvd_id"),
        candidate.get("source_identifier"),
        *extract_identifiers(candidate.get("alternative_ids"), "cve"),
    ]
    kev_entry = next((kev_index[value] for value in identifiers if value in kev_index), None)
    exploited_since = repair_text(item.get("exploitedSince"))
    applicability = candidate.get("component_applicability")
    sources = list(kev_entry.get("sources") or []) if kev_entry else []
    source_labels = {
        "cisa_kev": "CISA KEV",
        "eu_kev": "EU KEV",
        "eukev_kev": "EU KEV",
    }

    if evidence_meta.get("evidence_error"):
        exploitation_status = "未知—KEV数据查询失败"
        evidence_confidence = "未知"
        art14_readiness = "数据不足—转人工核验"
        srp_readiness = "未准备—不得据此排除Art.14"
        cra_review_required = True
    elif kev_entry or exploited_since:
        exploitation_status = (
            "KEV已知利用信号" if kev_entry else "EUVD已知利用信号"
        )
        evidence_confidence = "高（公开KEV情报）"
        if applicability == "受影响版本条件命中":
            art14_readiness = "紧急人工评估"
        elif applicability == "版本条件不命中":
            art14_readiness = "版本条件不命中—保存VEX/分析依据"
        else:
            art14_readiness = "紧急核验客户产品适用性"
        srp_readiness = "未准备—待产品级恶意利用证据及制造商awareness确认"
        cra_review_required = applicability != "版本条件不命中"
    else:
        exploitation_status = "未列入当前KEV快照（不代表未被利用）"
        evidence_confidence = "未发现公开KEV证据"
        art14_readiness = "公开证据未命中—仍需产品适用性判断并持续监测其他可靠来源"
        srp_readiness = "未准备—未启动24h/72h法定时钟"
        cra_review_required = True

    candidate.update(
        {
            "exploitation_status": exploitation_status,
            "exploited_since": exploited_since,
            "kev_sources": ", ".join(source_labels.get(value, value) for value in sources),
            "kev_date_added": repair_text(kev_entry.get("dateAdded")) if kev_entry else "",
            "evidence_confidence": evidence_confidence,
            "evidence_checked_at": evidence_meta.get("evidence_checked_at", ""),
            "kev_downloaded_at": evidence_meta.get("kev_downloaded_at", ""),
            "kev_snapshot_age_seconds": evidence_meta.get(
                "kev_snapshot_age_seconds"
            ),
            "kev_freshness": evidence_meta.get("kev_freshness", "unknown"),
            "kev_snapshot_source": evidence_meta.get("kev_snapshot_source", ""),
            "kev_fallback_error": evidence_meta.get("kev_fallback_error", ""),
            "kev_snapshot_sha256": evidence_meta.get("kev_snapshot_sha256", ""),
            "cra_review_required": cra_review_required,
            "art14_readiness": art14_readiness,
            "srp_readiness": srp_readiness,
        }
    )
    return candidate


async def match_components(
    components: list[Component],
    progress: Callable[[int, int, str], Awaitable[None]] | None = None,
    *,
    monitoring_candidate_only: bool = False,
) -> dict[str, Any]:
    client_wrapper = EuvdClient()
    local_status = await asyncio.to_thread(client_wrapper.local_snapshot_status)
    data_provenance = local_status or {
        "status": "network",
        "query_mode": "network-euvd-api",
        "source_id": "ENISA_EUVD_NETWORK",
        "last_successful_to_date": "",
        "reference_data_freshness": "network-request",
        "source_db_sha256": "",
        "snapshot_created_at": "",
    }
    provenance_fields = {
        "euvd_data_status": data_provenance.get("status", "unknown"),
        "euvd_query_source": data_provenance.get("query_mode", "unknown"),
        "euvd_last_successful_to_date": data_provenance.get(
            "last_successful_to_date", ""
        ),
        "euvd_reference_freshness": data_provenance.get(
            "reference_data_freshness", "unknown"
        ),
        "euvd_source_db_sha256": data_provenance.get("source_db_sha256", ""),
        "euvd_snapshot_created_at": data_provenance.get(
            "snapshot_created_at", ""
        ),
    }
    total = len(components)
    completed = 0
    progress_lock = asyncio.Lock()

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(45.0, connect=15.0),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as http_client:
        requested_cves = {
            cve
            for component in components
            for cve in extract_identifiers(component.cve_ids, "cve")
        }
        mapping_error = ""
        try:
            cve_mapping, mapping_meta = await client_wrapper.cve_mapping(
                http_client,
                requested_cves,
            )
        except (httpx.HTTPError, ValueError, OSError, json.JSONDecodeError) as exc:
            cve_mapping = {}
            mapping_meta = {"mapping_error": repair_text(exc)}
            mapping_error = repair_text(exc)

        try:
            kev_index, evidence_meta = await client_wrapper.kev_index(http_client)
        except (httpx.HTTPError, ValueError, OSError, json.JSONDecodeError) as exc:
            kev_index = {}
            evidence_meta = {"evidence_error": repair_text(exc)}

        async def process(
            component: Component,
        ) -> tuple[Component, list[dict[str, Any]], str | None, dict[str, Any]]:
            nonlocal completed
            error: str | None = None
            matches: list[dict[str, Any]] = []
            query_meta: dict[str, Any] = {
                "api_total": 0,
                "fetched_count": 0,
                "pages_fetched": 0,
                "truncated": False,
                "query_mode": "not-run",
            }
            try:
                seen: set[str] = set()
                input_cves = extract_identifiers(component.cve_ids, "cve")
                input_euvds = extract_identifiers(component.euvd_ids, "euvd")
                if input_cves or input_euvds:
                    resolved: dict[str, tuple[str, str]] = {
                        euvd_id: (euvd_id, "SBOM EUVD ID")
                        for euvd_id in input_euvds
                    }
                    unmapped: list[str] = []
                    for cve_id in input_cves:
                        euvd_ids = cve_mapping.get(cve_id) or []
                        if not euvd_ids:
                            unmapped.append(cve_id)
                        for euvd_id in euvd_ids:
                            resolved.setdefault(
                                euvd_id,
                                (cve_id, "SBOM CVE→EUVD 官方映射"),
                            )
                    if mapping_error and input_cves and not resolved:
                        raise ValueError(f"CVE→EUVD 映射快照获取失败: {mapping_error}")
                    missing_euvd: list[str] = []
                    for euvd_id, (source_identifier, basis) in resolved.items():
                        item = await client_wrapper.detail(http_client, euvd_id)
                        if item is None:
                            missing_euvd.append(euvd_id)
                            continue
                        candidate = evaluate_identifier_item(
                            component,
                            item,
                            source_identifier,
                            basis,
                        )
                        candidate.update(provenance_fields)
                        matches.append(
                            apply_exploitation_evidence(
                                candidate,
                                item,
                                kev_index,
                                evidence_meta,
                            )
                        )
                    query_meta = {
                        "api_total": len(resolved),
                        "fetched_count": len(matches),
                        "pages_fetched": 1 if resolved else 0,
                        "truncated": False,
                        "query_mode": "identifier-exact",
                        "unmapped_identifiers": unmapped + missing_euvd,
                        **mapping_meta,
                    }
                    # 兜底：精确分支未产生匹配（典型：CVE 未在本地映射且未提供命中的
                    # EUVD ID）时回退产品候选搜索，避免静默漏报。设计约束#5
                    # "未命中≠不存在"——CVE 未映射只是"本地映射表未覆盖该 CVE"，
                    # 不等于该组件无漏洞。回退产生的候选标记"需复核"，不冒充精确匹配。
                    if not matches:
                        query_product, query_vendor = query_identity(component)
                        items, fallback_meta = await client_wrapper.search(
                            http_client,
                            query_product,
                            query_vendor,
                        )
                        for item in items:
                            candidate = evaluate_item(component, item)
                            if candidate and candidate["euvd_id"] not in seen:
                                seen.add(candidate["euvd_id"])
                                candidate.update(provenance_fields)
                                matches.append(
                                    apply_exploitation_evidence(
                                        candidate,
                                        item,
                                        kev_index,
                                        evidence_meta,
                                    )
                                )
                        query_meta = {
                            **fallback_meta,
                            "query_mode": "identifier-exact-then-product-fallback",
                            "unmapped_identifiers": unmapped + missing_euvd,
                            **mapping_meta,
                        }
                else:
                    query_product, query_vendor = query_identity(component)
                    items, query_meta = await client_wrapper.search(
                        http_client,
                        query_product,
                        query_vendor,
                    )
                    for item in items:
                        candidate = evaluate_item(component, item)
                        if candidate and candidate["euvd_id"] not in seen:
                            seen.add(candidate["euvd_id"])
                            candidate.update(provenance_fields)
                            matches.append(
                                apply_exploitation_evidence(
                                    candidate,
                                    item,
                                    kev_index,
                                    evidence_meta,
                                )
                            )
                if monitoring_candidate_only:
                    for candidate in matches:
                        candidate["original_match_status"] = candidate.get(
                            "match_status", ""
                        )
                        candidate["original_component_applicability"] = candidate.get(
                            "component_applicability", ""
                        )
                        candidate["match_status"] = "需复核"
                        candidate["component_applicability"] = (
                            "待人工核验（周期重扫候选）"
                        )
                        candidate["monitoring_candidate_only"] = True
                        candidate["automatic_vulnerability_confirmation"] = False
                        candidate["automatic_art14_decision"] = False
                        candidate["version_applicability_boundary"] = (
                            "MANUAL_REVIEW_REQUIRED"
                        )
                matches.sort(
                    key=lambda row: (
                        not row.get("cra_review_required"),
                        row["match_status"] != "已匹配",
                        -(float(row["cvss_score"]) if row["cvss_score"] is not None else -1),
                        row["euvd_id"],
                    )
                )
                # Cap product-candidate noise. The sort above already floats
                # "已匹配" and higher-CVSS rows to the front, so capping only
                # drops the low-confidence "需复核" tail — never a confirmed
                # match. The CVE-exact path (query_mode identifier-exact) is
                # excluded so exact matches are never lost.
                if (
                    len(matches) > MAX_PRODUCT_CANDIDATES
                    and "product" in str(query_meta.get("query_mode", ""))
                ):
                    query_meta["truncated"] = True
                    query_meta["product_candidates_cap"] = {
                        "before": len(matches),
                        "after": MAX_PRODUCT_CANDIDATES,
                    }
                    matches = matches[:MAX_PRODUCT_CANDIDATES]
            except (httpx.HTTPError, ValueError) as exc:
                error = str(exc)

            async with progress_lock:
                completed += 1
                if progress:
                    await progress(completed, total, component.name)
            return component, matches, error, query_meta

        component_workers = asyncio.Semaphore(CONCURRENCY)

        async def limited_process(
            component: Component,
        ) -> tuple[Component, list[dict[str, Any]], str, dict[str, Any]]:
            async with component_workers:
                return await process(component)

        processed = await asyncio.gather(
            *[limited_process(component) for component in components]
        )

    all_matches: list[dict[str, Any]] = []
    component_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for component, matches, error, query_meta in processed:
        confirmed_count = sum(1 for row in matches if row["match_status"] == "已匹配")
        review_count = sum(1 for row in matches if row["match_status"] == "需复核")
        identity_ready = bool(
            component.cve_ids
            or component.euvd_ids
            or (
                component.name
                and component.version
                and (component.vendor or component.purl or component.cpe)
            )
        )
        component_rows.append(
            {
                **asdict(component),
                "confirmed_count": confirmed_count,
                "review_count": review_count,
                "identity_ready": identity_ready,
                "query_status": "错误" if error else "成功",
                "query_result_count": query_meta.get("fetched_count", 0),
                "query_api_total": query_meta.get("api_total", 0),
                "query_pages": query_meta.get("pages_fetched", 0),
                "query_truncated": bool(query_meta.get("truncated")),
                "query_mode": query_meta.get("query_mode", ""),
                "monitoring_candidate_only": monitoring_candidate_only,
                "unmapped_identifiers": ", ".join(query_meta.get("unmapped_identifiers") or []),
                "mapping_checked_at": query_meta.get("mapping_checked_at", ""),
                "mapping_snapshot_sha256": query_meta.get("mapping_snapshot_sha256", ""),
                **provenance_fields,
                "result": (
                    "发现EUVD记录"
                    if confirmed_count
                    else "需人工确认"
                    if review_count
                    else "未找到EUVD映射"
                    if query_meta.get("unmapped_identifiers")
                    else "未发现候选"
                ),
            }
        )
        all_matches.extend(matches)
        if error:
            errors.append(
                {
                    "component_row": component.row_number,
                    "component_name": component.name,
                    "error": error,
                }
            )

    component_count = len(components)
    identity_ready_count = sum(1 for row in component_rows if row["identity_ready"])
    query_success_count = component_count - len(errors)
    complete_fetch_count = sum(
        1
        for row in component_rows
        if row["query_status"] == "成功" and not row["query_truncated"]
    )
    result = {
        "data_provenance": data_provenance,
        "components": component_rows,
        "matches": all_matches,
        "errors": errors,
        "summary": {
            "component_count": component_count,
            "components_with_confirmed": sum(
                1 for row in component_rows if row["confirmed_count"] > 0
            ),
            "confirmed_findings": sum(
                1 for row in all_matches if row["match_status"] == "已匹配"
            ),
            "review_findings": sum(
                1 for row in all_matches if row["match_status"] == "需复核"
            ),
            "unmatched_components": sum(
                1
                for row in component_rows
                if row["result"] in {"未找到EUVD映射", "未发现候选"}
            ),
            "known_exploited_findings": sum(
                1
                for row in all_matches
                if row.get("exploitation_status")
                in {"KEV已知利用信号", "EUVD已知利用信号"}
            ),
            "art14_review_findings": sum(
                1 for row in all_matches if row.get("cra_review_required")
            ),
            "unmapped_identifier_count": sum(
                len(
                    [
                        value
                        for value in row.get("unmapped_identifiers", "").split(",")
                        if value.strip()
                    ]
                )
                for row in component_rows
            ),
            "error_count": len(errors),
            "identity_ready_components": identity_ready_count,
            "identity_coverage_percent": round(
                identity_ready_count * 100 / component_count
            )
            if component_count
            else 100,
            "query_success_components": query_success_count,
            "query_coverage_percent": round(
                query_success_count * 100 / component_count
            )
            if component_count
            else 100,
            "complete_fetch_components": complete_fetch_count,
            "retrieval_coverage_percent": round(
                complete_fetch_count * 100 / query_success_count
            )
            if query_success_count
            else 0,
            "review_components": sum(
                1 for row in component_rows if row["review_count"] > 0
            ),
            "truncated_queries": sum(
                1 for row in component_rows if row["query_truncated"]
            ),
        },
    }
    if monitoring_candidate_only:
        result["monitoring_contract"] = {
            "purpose": "PERIODIC_COMPONENT_RESCAN_CANDIDATE_ONLY",
            "component_rescan_candidate_only": True,
            "automatic_vulnerability_confirmation": False,
            "automatic_art14_decision": False,
            "version_applicability_boundary": "MANUAL_REVIEW_REQUIRED",
            "snapshot_absence_is_not_no_vulnerability_proof": True,
        }
    return result
