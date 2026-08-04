# EUVD 平台开发交接备忘 — 2026-08-04 会话

**文档日期**：2026-08-04
**会话范围**：7 维度架构审查 → D0 工程治理 → 改进 1/2 → CVE 漏报修复 → 积极利用标注 → 同步硬化(403)
**前置文档**：`docs/DEVELOPER_HANDOFF_v2.3.1.md`（v2.3.1 as-built 状态）
**状态**：本次改动已 commit 到双项目本地 Git 仓库（尚未 push，无远端）；正式容器 8090 已运行新版并经用户验收。

---

## 1. 本次会话总览

从一次 7 维度并行架构审查 Workflow 出发（6/7 维度成功，1 维度因 API 速率限制未完成），按优先级交付：客户数据外泄堵漏、双项目版本控制基线、版本号单一源、EUVD 目录列表/搜索（改进 1）、数据日期展示 + 按钮文案修正（改进 2a/Phase1）、CVE 匹配静默漏报修复、积极利用漏洞标注（CRA Art.3(42)）、403 fail-fast。

**12 个 Web commit + 5 个 Mirror commit；Web 测试 40→79 项，Mirror 测试 17→36 项，全绿。**

---

## 2. 项目架构（不变，提醒）

| 项目 | 路径 | 职责 |
|---|---|---|
| Web 工作台 | `/Users/mac/Documents/AI-Cybersecurity/CRA/解读文件/SBOM工具/euvd-sbom-matcher` | FastAPI + 原生前端，导入/匹配/报告/Art.14 工作流，只读消费 EUVD 快照 |
| 正式 Mirror | `/Users/mac/EUVD-Local-Mirror` | EUVD 同步权威库（`euvd_sync.py` + `sbom_match.py`） |

**数据流**：ENISA API → Mirror 增量同步（人工排他窗口）→ `scripts/build_local_euvd_snapshot.py`（原子替换 + WAL 漂移检测 + SHA sidecar）→ `data/euvd-readonly.sqlite3`（只读快照）→ Web 只读查询。

**必须维护的设计约束**（DEVELOPER_HANDOFF §14，本次未突破）：
1. 本地优先（默认不把客户数据发公网，`EUVD_NETWORK_FALLBACK=false`）
2. 哈希失败关闭（DB/sidecar 缺失或失配不可静默降级）
3. **同步权威分离**（Web 不写正式 Mirror；快照只能由 build 脚本生成）
4. 新鲜度显式（fresh/stale/degraded/unavailable）
5. **未命中 ≠ 不存在**（尤其 KEV、403、本地快照未命中）
6. CVE/EUVD 精确优先（产品模糊匹配只产生候选）
7. 制造商 awareness 必须人工确认
8. 四眼审批不能同账户
9. 证据与结论分离
10. PRE-7 只做字段观察（`automatic_conformity_decision=false` 固定）
11. 制品身份分离（source/image/portable 各自 SBOM+hash）
12. 保留失败证据

---

## 3. 本次会话成果（按 commit）

### Web 项目（8 commit，main 分支）
| commit | 类型 | 内容 | 测试 |
|---|---|---|---|
| `7b4fa27` | chore | D0: Web Git 基线 + .gitignore（53 文件，排除 data/backups/outputs/self-test/runtime/samples，无敏感） | — |
| `efc2f88` | feat | D0: 消费者快照表 allowlist + VACUUM 物理清除客户审计数据（堵 `sbom_lookup_runs/results` 外泄，问题#4） | +5 (test_build_snapshot) |
| `7fc2faf` | feat | D0: 版本号单一源 `APP_VERSION` + `scripts/check_version_consistency.py` 校验门 | +2 (test_version_consistency) |
| `c6ba1db` | feat | 改进 2(a)+Phase1: 头部数据日期徽章（`last_successful_to_date`/计数/freshness）+ "更新 EUVD/KEV"按钮改"复核本地快照状态" | node --check |
| `cb33c57` | feat | 改进 1 后端: `GET /api/euvd/records` 列表/搜索/分页（只读快照，走索引） | +10 (test_euvd_records) |
| `c6cf2d2` | feat | 改进 1 前端: "EUVD 目录"页签（列表+搜索+排序+分页） | docker 端到端 |
| `568b9ad` | fix | CVE 精确优先改"优先+兜底"，CVE 未映射时回退产品候选（修复静默漏报，审查 HIGH#1） | +3 (test_matcher_cve_fallback) |
| `ee6fc27` | feat | 积极利用标注 + 筛选（CRA Art.3(42)，`actively_exploited=KEV∪exploitedSince`，行标红 + "仅积极利用"开关） | +5 (test_euvd_records 增项) |

### Mirror 项目（5 commit，main 分支）
| commit | 类型 | 内容 | 测试 |
|---|---|---|---|
| `38a649b` | chore | D0: Mirror Git 基线 + 补 .gitignore（排除 backups/data/lkg，401 文件含 vendor 锁定依赖） | — |
| `5e6e9bd` | fix | 403 fail-fast（移出瞬时重试集 `{403,429,5xx}`→`{429,5xx}`，不再阻塞约 9 分钟） | +1 (test_403) |
| `e94d83c` | feat | 4-3 `MirrorStore.exclusive_lock` 跨进程 advisory lock（fcntl.flock sidecar 锁文件，None/0/>0 超时；改进 2(b) 并发前置基础设施，main/snapshot 入口接线留待 Phase2） | +6 (test_mirror_lock) |
| `de229ab` | feat | 4-4 reference pair 原子性（`import_reference_pair` 单事务 + sync_all fetch-first，mapping+KEV 同代提交/同回滚，消除跨代 mismatch） | +3 (test_reference_pair_atomicity) |
| `de24ddd` | fix | 4-2 bootstrap 状态机（`decide_bootstrap_phase` 纯函数 + `_run_bootstrap_flow`，paging_completed_at 守卫，catchup 失败不再触发 ~37 万漏洞全量重做） | +9 (test_bootstrap_state_machine) |

---

## 4. 架构审查发现修复进度

审查共 48 个发现（1 critical / 13 high / 25 medium / 9 low），13 个 critical/high 已对抗性验证。

| 严重度 | 问题 | 位置 | 状态 |
|---|---|---|---|
| CRITICAL | 改进 2(b) 一键更新架构不可达成（Web 不写 Mirror） | main.py:726 | ⏳ 设计已定 Phase1/2/3 分期，Phase1 完成 |
| HIGH | 客户审计数据外泄到快照 | build_local_euvd_snapshot.py | ✅ allowlist+VACUUM |
| HIGH | 零 Git 无 .gitignore | 双项目 | ✅ Git 基线 |
| HIGH | 版本号散落致漂移 | APP_VERSION/docker tag/README | ✅ 单一源+校验门 |
| HIGH | CVE 精确优先漏报 | matcher.py:1442 (match_components) | ✅ 优先+兜底 |
| HIGH | awareness 可被覆盖（approved/submitted 案件） | workflow_store.py:831 | ⏳ 第七步 |
| HIGH | stale 重开不区分 customer | workflow_store.py:474 | ⏳ 第七步 |
| 中危 | 无跨进程 advisory lock | euvd_sync.py MirrorStore | ✅ 4-3 exclusive_lock |
| 中危 | 403 重试 9 分钟 | euvd_sync.py EuvdClient | ✅ fail-fast |
| 中危 | bootstrap 全量回滚 | euvd_sync.py main | ✅ 4-2 状态机 |
| 中危 | reference pair 非原子 | euvd_sync.py sync_all | ✅ 4-4 import_reference_pair |
| 中危 | JSON 任务与 SQLite 非原子 | main.py:440 | ⏳ D2 |
| 中危 | startup 删 7 天上传无 dry-run | main.py:1276 | ⏳ D2 |
| 中危 | 无 schema migration | euvd_sync.py:274 | ⏳ D1/D3 |
| 中危 | audit 无 hash chain | workflow_store.py:229 | ⏳ 第七步 |

> **未完成审查维度**：parsing-evidence（表格解析/PRE-7）因 API 速率限制 429 未跑。该层是客户手写 Excel 的核心输入路径，建议下次单独补审（公式注入防护、脏数据容错、Metadata 绑定）。

---

## 5. 重要遗留（需行动）

### 5.1 快照重建 — ✅ 已完成（2026-08-04 续做，commit 818841d）

修复 `build_local_euvd_snapshot` 的 WAL 漂移检测（WAL 模式读连接 touch `-wal`/`-shm` 的 mtime，旧全状态比较误判；改为只比 WAL size），重建 `euvd-readonly.sqlite3`：`sbom_lookup_runs`/`sbom_lookup_results` 彻底移除（VACUUM 物理清除），370723→372484 漏洞，sha verified，Web 健康。下方 runbook 命令保留供后续重建。
表 allowlist 只改了代码 + 单元测试。线上 `euvd-readonly.sqlite3`（1GB）仍是旧脚本构建，**仍含 `sbom_lookup_runs/sbom_lookup_results`**。要在维护窗口用新脚本重建：
```bash
cd euvd-sbom-matcher
# §9.4 runbook：先备份当前快照，再构建
python3 scripts/build_local_euvd_snapshot.py \
  --source /Users/mac/EUVD-Local-Mirror/data/euvd-mirror.sqlite3 \
  --output data/euvd-readonly.sqlite3 \
  --output-json outputs/euvd-snapshot-build-<run_id>.json
# 验证：新快照 web_snapshot_metadata 含 consumer_excluded_tables=sbom_lookup_runs,...
docker compose up -d --force-recreate matcher
curl -fsS http://127.0.0.1:8090/api/health  # snapshot_sha256 一致
```

### 5.2 正式容器
8090 已运行新版（用户验收改进 1/2a/积极利用通过）。`APP_VERSION` 仍是 `2.3.1`（本次是功能增量，未升版本号）；下次正式发布可升 `2.3.2` 并同步 docker-compose tag + README（用 `scripts/check_version_consistency.py` 校验）。

### 5.3 数据状态
**已推进到 fresh**（2026-08-04 续做）：403 确诊为瞬时速率限制（同 EuvdClient UA + 日期参数 8/4 恢复 HTTP 200，代码 fail-fast 行为正确无 bug），incremental + reference-data 重同步成功，数据截止 **2026-08-04**（372484 漏洞 / 1662 KEV / 355046 mapping），`reference_data_freshness=fresh`，`local_status=local_ready`。403 fail-fast 保留，若再发则保留 LKG 不损坏。

---

## 6. 剩余路线图

### 第四步（同步引擎硬化）— ✅ 已完成（2026-08-04 续做，commit e94d83c/de229ab/de24ddd，Mirror 测试 18→36）

> 三项已交付（4-3 advisory lock / 4-4 reference 原子性 / 4-2 bootstrap 状态机），下方原始设计描述保留作为实现依据。

**4-2 bootstrap 状态机**（`euvd_sync.py` main:1416-1437 + sync_pages:1225-1227）
- 问题：bootstrap completed 立即设 `bootstrap_next_page=0`，随后的 catchup 失败 → 下次 bootstrap 因 `start_page==0` 重置 anchor → 全量重做（37 万漏洞数小时）
- 修复：用 `bootstrap_completed_at` + `bootstrap_catchup_completed_at` 分阶段判断；catchup 失败只重试 catchup，不重做 bootstrap
- 复杂度：涉及 main CLI 重构，**难单元测**（需把 bootstrap 流程提取为可测函数）；中风险

**4-3 跨进程 advisory lock**（`MirrorStore`）
- 问题：无 fcntl/应用层锁，仅靠 SQLite timeout=30 + WAL；同步与快照构建并发竞争同一 SQLite
- 修复：`fcntl.flock` 锁文件（如 `path + ".lock"`），`MirrorStore` 提供 `exclusive_lock()` 上下文管理器；同步/快照脚本入口 acquire
- 复杂度：**改进 2(b) 一键更新的并发安全前置**；可测（flock 互斥）；中复杂

**4-4 reference 原子性**（`ReferenceDataSynchronizer.sync_all` euvd_sync.py:1128）
- 问题：`sync_mapping` + `sync_known_exploited` 各自独立事务；mapping 成功 commit 后 KEV 失败 → mapping 跳新代、KEV 停旧代（跨代）
- 修复：拆 fetch/import 两步，两者都 fetch 成功后统一 import（单事务）；或失败时回滚 mapping 的 `is_current` 翻转；或显式记录 `reference_pair_mismatch` 状态
- 复杂度：涉及 import 函数事务边界重构；可测；中风险

### 后续步骤（设计文档 D1-D4 + 审查剩余）
- **第五步** — ✅ 已完成（2026-08-04 续做，commit `da73ca5` D1 + `f51b5ef` D2，Web 测试 65→79）：D1 `01_Metadata_元数据` sheet → product 身份绑定（预填可改 + hardware_revision/release_date/sbom_version 证据）；D2 BackgroundTasks 增强（`uuid5` 幂等键 / `POST /cancel` + `/retry` / `_write_json(completed)` 先于 `register_snapshot` 的原子顺序修复 + startup reconcile 兜底 / 前端取消·重试按钮）。下方原设计描述保留。
- **第六步**：改进 2 Phase2（Mirror ops 编排器 + Web 进度轮询 = 真正"一键更新"，不违反约束#3）；Phase3 独立 ops 容器
- **第七步**：工作流安全门（awareness 覆盖防护 workflow_store.py:831；stale 重开按 customer 隔离 :474；audit hash chain）
- **D3**：工程化发布（CI lint/unit/contract/E2E/dep scan/image scan；签名 SBOM+provenance；性能/故障注入测试）
- **补审**：parsing-evidence 维度（429 未完成）

---

## 7. 关键技术决策（供续做参考）

| 决策 | 内容 | 依据 |
|---|---|---|
| 改进 1 API | `GET /api/euvd/records?page=&page_size=&sort=&q=&actively_exploited_only=`；默认排序 `euvd_id_desc` | `updated_raw`/`published_raw` 是 EUVD 原文字符串（"Sep 9, 2025..."），字典序≠日期序；PK 序（创建序）可靠走索引 |
| 积极利用判定 | `actively_exploited = KEV(known_exploited) ∪ record.exploitedSince` | 与 `apply_exploitation_evidence` 一致；对齐 CRA Art.3(42)；筛选 SQL 层按 KEV（1660），标记 Python 层 KEV∪exploitedSince（1662，差 2 条可接受） |
| KEV 来源 | CISA KEV (1655) + EU KEV (35) = 1660 | `known_exploited_sources.source` |
| 改进 2 分期 | Phase1 完成（按钮文案 + 日期徽章）；Phase2/3 待 D2 | 约束#3：Web 不写 Mirror；一键更新需 Mirror ops 编排器 |
| 版本单一源 | `APP_VERSION` (main.py:52) | CI 用 `scripts/check_version_consistency.py` 强制 docker tag 一致 |
| 消费者快照 allowlist | `CONSUMER_TABLE_ALLOWLIST` 9 表（vulnerabilities/cve_euvd_mapping/known_exploited/known_exploited_sources/data_source_versions/sync_state/sync_runs/local_products/web_snapshot_metadata） | 排除 `sbom_lookup_runs/results`；VACUUM 物理清除空闲页 |
| CVE 优先+兜底 | 精确分支零 match 时回退产品候选（`query_mode=identifier-exact-then-product-fallback`） | 约束#5 未命中≠不存在；回退候选标"需复核"不冒充精确 |

---

## 8. 如何续做

### 8.1 跑测试
```bash
# Web（65 项）
cd "/Users/mac/Documents/AI-Cybersecurity/CRA/解读文件/SBOM工具/euvd-sbom-matcher"
handoff=$(mktemp -d)
DATA_DIR="$handoff/data" OUTPUT_DIR="$handoff/outputs" \
EUVD_LOCAL_DB="$PWD/data/euvd-readonly.sqlite3" \
EUVD_LOCAL_DB_SHA256_FILE="$PWD/data/euvd-readonly.sqlite3.sha256" \
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests
rm -rf "$handoff"

# Mirror（36 项）
cd /Users/mac/EUVD-Local-Mirror
python3 -m unittest discover -s tests
```

### 8.2 版本一致性校验
```bash
cd euvd-sbom-matcher
python3 scripts/check_version_consistency.py --no-health   # APP_VERSION == docker tag
```

### 8.3 重建正式容器（部署前端/后端改动）
```bash
cd euvd-sbom-matcher
# §8.1：startup hook 删 7 天前 uploads，先检查 + 备份
find data/uploads -type f -mtime +7 | wc -l   # 应为 0 或先备份
bk="backups/rebuild-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$bk"
sqlite3 data/workbench.sqlite3 ".backup '$bk/workbench.sqlite3'"
docker compose up -d --build --force-recreate matcher
curl -fsS http://127.0.0.1:8090/api/health | python3 -m json.tool
```

### 8.4 续第四步剩余（每项独立 commit + 测试）
- **4-2 bootstrap**：提取 `_run_bootstrap_flow(store, mirror, ...)` 为可测函数；测试 catchup 失败后不重做 bootstrap
- **4-3 lock**：`fcntl.flock` 锁文件；测试两进程/两锁请求互斥
- **4-4 reference**：拆 `sync_mapping`/`sync_known_exploited` 为 fetch + import；测试 mapping 成功 + KEV 失败 → 不跨代

### 8.5 Git 状态
- 两项目均为本地 Git 仓库（main 分支），**未 push（无远端）**
- 后续应建立远端（如内部 GitLab）+ `.gitignore` 已就绪（客户数据/大文件已排除）
- 提交身份：`EUVD Dev <euvd-dev@local>`（本地，可按组织调整）

---

## 9. 给接手人的提醒

1. **先读 `DEVELOPER_HANDOFF_v2.3.1.md`**（架构/约束/runbook 全貌），本备忘只覆盖 2026-08-04 会话增量。
2. **同步权威分离是硬约束**：任何"Web 上一键同步"的诱惑都要抵抗，用 Mirror ops 编排器 + Web 只读轮询实现（改进 2 Phase2/3）。
3. **allowlist 改动必须重建快照才实战生效**（§5.1），否则线上快照仍含客户审计表。
4. **403 当前持续**：数据停留在 2026-07-28，这是 ENISA 出口受限，不是代码 bug；修复合法访问条件或接受 LKG。
5. **积极利用 ≠ 自动 reportable**：`actively_exploited` 是公开利用信号（CRA Art.3(42) 的输入），产品级 reportable 判定仍需 awareness + 证据 + 四眼（系统不自动判）。
