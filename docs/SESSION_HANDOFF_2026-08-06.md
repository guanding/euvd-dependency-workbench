# EUVD 平台交接备忘（2026-08-06）

**本轮**：VALIDATION_REPORT §3 优化 #1/#2/#3 实施 + 部署。上一轮（审查路线图收官）交接见 `SESSION_HANDOFF_2026-08-04.md`。

## 本轮交付（4 commit，Web 项目 main 分支）

| commit | 内容 |
|---|---|
| `08b5828` | perf: #1 产品噪声治理 + #2 CVE 回填（5 文件 +407/-23） |
| `f6f951e` | docs: VALIDATION_REPORT §5 实施记录 |
| `f8efda4` | feat: #3 版本表达式 fuzzy 救援（+112） |
| `dc5c925` | docs: §5 补 #3 诚实评估 |

镜像项目 `/Users/mac/EUVD-Local-Mirror` **未改动**（#2 backfill 在 web 侧 build_snapshot，不动镜像权威库）。

## 优化实效（真实 852MB mirror DB）

| # | 优化 | 落点 | before → after |
|---|---|---|---|
| 1a | 过滤 n/a 占位产品 | `build_local_euvd_snapshot.py:product_rows` | local_products 1,113,450 → **969,305**（-144,145，0 残留） |
| 2 | CVE mapping 回填 | 同上 `_build_snapshot`（遍历 record aliases INSERT OR IGNORE） | mapping 355,046 → **372,484**（+17,438，**CVE 路径 95.32% → 100%**） |
| 1b | vendor+product 联合 | `matcher.py:_query_local_product` | joint/fallback/none 三态，无结果回退（设计约束 #5） |
| 1c | 产品候选 top-N cap | `matcher.py:match_components` | 默认 `MAX_PRODUCT_CANDIDATES=50`，CVE 精确路径不截断 |
| 3 | 版本 fuzzy 救援 | `matcher.py:version_is_affected` | None 429,947 → 428,619（**-1,328**，保守零误判） |

详见 `docs/VALIDATION_REPORT.md §5`。

## 部署状态

- **#1/#2 已部署**：`data/euvd-readonly.sqlite3` 已原子替换，sha 重算 verified。备份在 `data/euvd-readonly.sqlite3.bak-20260806`（1GB，**确认稳定后可删**）。
- **#3 待 web 服务重启生效**：matcher 逻辑层改动，当前无服务运行，下次 `uvicorn app.main:app` 启动即用新 `version_is_affected`。

## 测试

- **Web 131 passed**（115 基线 + 16 新测试：build_snapshot 2 / local_euvd 4 / version_normalizer 10）
- **镜像 47 passed**
- `tests/conftest.py` 新增：设 `DATA_DIR`/`OUTPUT_DIR` env，修复测试套件对容器路径 `/app` 的硬依赖（本地 hermetic 运行）

## 关键文件（续做定位）

- `app/matcher.py`
  - `version_is_affected` L230：strict 判定 + L295 fuzzy 救援块（and-later / before-filler）
  - `_query_local_product` L870：vendor 联合 + fallback
  - `match_components` L1748：top-N cap（CVE 路径 `identifier-exact` 不截断）
  - `MAX_PRODUCT_CANDIDATES` L28（env `EUVD_MAX_PRODUCT_CANDIDATES`，默认 50）
- `scripts/build_local_euvd_snapshot.py`
  - `product_rows` L91：`_PLACEHOLDER_PRODUCT_NAMES` 过滤
  - `_build_snapshot`：`cve_euvd_mapping` lean 重建（5→2 列）+ aliases backfill + `CVE_PATTERN`
- `docs/VALIDATION_REPORT.md` — 边界量化 + §5 实施记录 + §3 backlog

## 剩余 backlog（§3，价值递减）

- **#4 Windows SKU 归一化** — top-15 候选中 12 个是 Windows SKU 碎片（Server Core / Version 变体），合并为 (product, major-version) family。仅 Windows 场景。
- **#5 放弃 CPE 基础设施** — 0.004% 覆盖（39/1,117,611），`parse_cpe` 等为死代码，清理减负。

## 数据天花板（诚实结论）

EUVD 是文本语料，51% 版本表达式不可机器解析（`n/a`/`unknown` 占位 + 模糊人类描述，如 Cisco "23.0 ap383515"）。保守 fuzzy 仅救有明确范围语义的 ~0.14%；激进救 placeholder/fixed-in/bare-product 会冒**误判 True 牵连无关旧版本**风险，违反"宁可待核验不可误报"原则。

**最优输入路径是带 CVE 的 SBOM**（grype 类工具，非纯 syft）——CVE 精确路径现已 100%。

## 续做命令

```bash
# 跑测试
cd "/Users/mac/Documents/AI-Cybersecurity/CRA/解读文件/SBOM工具/euvd-sbom-matcher" && python -m pytest tests/ -q   # Web 131
cd "/Users/mac/EUVD-Local-Mirror" && python -m pytest tests/ -q                                              # 镜像 47

# 重建 consumer snapshot（部署 snapshot 类改动后）
python scripts/build_local_euvd_snapshot.py <mirror.sqlite3> <output.sqlite3>
sha256sum output.sqlite3 > output.sqlite3.sha256   # matcher 校验依赖 sidecar

# #3 生效（matcher 逻辑层）
uvicorn app.main:app --reload   # 重启即用新 version_is_affected
```
