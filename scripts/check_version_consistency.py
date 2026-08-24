#!/usr/bin/env python3
"""校验版本号单一源一致性（D0，架构审查中危#版本号散落）。

``APP_VERSION`` (app/version.py) 是版本号唯一权威来源。本脚本校验 docker-compose
镜像 tag 与之一致；若 Web 服务在运行，也校验 ``/api/health`` 的 version。

退出码：0 一致；1 不一致或无法判定。用于 CI / 发布前强制门。

用法：
    python scripts/check_version_consistency.py
    python scripts/check_version_consistency.py --no-health
    python scripts/check_version_consistency.py --health-url http://127.0.0.1:8090/api/health
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_MODULE = ROOT / "app" / "version.py"
COMPOSE = ROOT / "docker-compose.yml"
HEALTH_DEFAULT = "http://127.0.0.1:8090/api/health"


def app_version() -> str:
    text = VERSION_MODULE.read_text(encoding="utf-8")
    m = re.search(r'^APP_VERSION\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        raise SystemExit(f"无法在 {VERSION_MODULE} 找到 APP_VERSION 定义")
    return m.group(1)


def compose_tag() -> str | None:
    text = COMPOSE.read_text(encoding="utf-8")
    m = re.search(
        r"^\s*image:\s*euvd-dependency-workbench:([^\s]+)",
        text,
        re.MULTILINE,
    )
    return m.group(1) if m else None


def health_version(url: str) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return str(json.loads(resp.read()).get("version") or "")
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--health-url", default=HEALTH_DEFAULT)
    parser.add_argument("--no-health", action="store_true", help="跳过 /api/health 校验")
    args = parser.parse_args()

    expected = app_version()
    tag = compose_tag()
    mismatches: list[str] = []

    print(f"APP_VERSION (app/version.py)= {expected}")
    print(f"docker-compose image tag    = {tag}")
    if tag is None:
        mismatches.append("docker-compose.yml 未找到 euvd-dependency-workbench 镜像 tag")
    elif tag != expected:
        mismatches.append(f"docker-compose tag '{tag}' != APP_VERSION '{expected}'")

    if not args.no_health:
        hv = health_version(args.health_url)
        print(f"/api/health version         = {hv if hv else '(服务未运行，跳过)'}")
        if hv and hv != expected:
            mismatches.append(f"/api/health version '{hv}' != APP_VERSION '{expected}'")

    if mismatches:
        print("\n✗ 版本不一致：", file=sys.stderr)
        for m in mismatches:
            print(f"  - {m}", file=sys.stderr)
        print("\n修复：统一改为 app/version.py 的 APP_VERSION 值后重试。", file=sys.stderr)
        return 1
    print("\n✓ 版本一致")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
