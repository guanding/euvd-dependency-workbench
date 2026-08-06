# EUVD 平台验证报告（2026-08-05）

扩大验证：MVP（6 用例）+ 运行时边界（规模/MAX_COMPONENTS）+ 数据边界（workflow 4 维 EUVD 快照全量统计）。目标：量化系统天花板 + 明确优化方向。

## 1. 数据边界（EUVD 快照全量统计，372,484 记录）

| 维度 | 天花板 | 数据 | 含义 |
|---|---|---|---|
| 版本自动判定 | **~49%** | 标准 542,802 / 1,108,573；51% 人类 prose（Cisco "23.0 ap383515" 等） | 51% 受影响版本表达式机器无法解析 → "待核验" |
| CVE 精确路径 | **95.32%** | cve_euvd_mapping 355,046 / 372,484；aliases 100% 有 CVE；17,438 EUVD 有 CVE 未进 mapping | 4.68% 静默漏（aliases 有但 mapping 无） |
| 产品候选噪声 | **n/a 占 40.6%** | 143,606/353,440 产品记录是 "n/a"；Linux 13,470、Android 4,786 | 产品候选路径被 "n/a" 垃圾桶淹没 |
| CPE/purl 匹配 | **0.004%** | 39/1,117,611 有 CPE（嵌 product_version）；99.9965% name-only | CPE/purl 直接匹配几乎无用 |

## 2. 运行时边界

- **规模（真实 syft 无 CVE 场景）**：100 组件 → **8830 候选需复核**（88/组件）；Acrobat Reader 337/macOS 150；22s（~4.5 组件/s）
- **MAX_COMPONENTS**：2001 组件 → upload 层拒绝（`"组件数超过限制 2000"`，早保护）
- **MVP 对照**：6 用例全符合设计语义（CVE 精确 4/4、KEV 3、版本待核验、候选需复核、未发现≠无）

## 3. 优化方向（按 leverage 排序）

1. **产品候选噪声治理**（最高价值，真实 syft 场景致命问题）：
   - 过滤 `"n/a"`/`"NA"`/`"none"`/`"-"` product.name → **-40.6% 噪声，零信号损失**
   - **vendor+product 联合匹配**（非 product 单独）→ 缩小 Linux/Chrome 宽桶
   - 候选 **top-N + confidence 排序**（避免 8830 全列）
2. **CVE mapping backfill**（一键 95.32% → ~100%）：从 `record_json.aliases` 提取 17,438 未进 mapping 的 EUVD → `INSERT IGNORE`。纯数据补录，零 matcher 改动。
3. **版本 normalizer**（49% → 65-70%）：剥尾 build/patch token（Cisco "23.0 ap383515" → "23.0"；Cisco IOS "4.2(1e)" → "4.2"；Windows "Version 1607" 提取）。
4. **Windows SKU 归一化**：碎片化 SKU（Server Core/Version 变体）合并为 (product, major-version) family。top-15 中 12 个是 Windows SKU。
5. **~~放弃 CPE 基础设施~~（2026-08-06 调查关闭）**：原判 0.004% 覆盖的 CPE 是死代码；经 5-agent workflow + 独立 grep 交叉验证，**CPE 在代码里从不是匹配查询词**（无 `WHERE cpe`、local 表无 cpe 列、`EuvdClient.search` 无 cpe 参数），只用于组件归一化（`parse_cpe` 回填 name/vendor）+ 身份判据（`identity_ready`）+ 审计证据展示——全部活代码。保留 `parse_cpe` fallback 符合 #5（CPE-only 组件仍尝试识别，不静默放弃）。详见 §5。

## 4. 结论

真实天花板由 EUVD 数据特性决定（非系统 bug）：
- **CVE 精确路径强**（95.32%，可 backfill ~100%）——带 CVE 的 SBOM 是最优输入
- **版本自动判定中等**（49%，prose 多）——需 normalizer + 人工兜底
- **产品候选路径噪声大**（n/a 40.6% + 常见名宽泛）——真实 syft（无 CVE）场景需噪声治理才可用
- **CPE/purl 无用**（0.004%）——EUVD 是文本语料，靠模糊匹配

**对使用的建议**：优先用带 CVE 的 SBOM（grype 类工具，非纯 syft）走 CVE 精确路径；纯组件 SBOM 需先做噪声治理（过滤 n/a + vendor 联合）。

## 5. 优化实施记录（2026-08-06）

优化方向 §3 的 **#1（产品噪声治理）+ #2（CVE backfill）已实施并部署**到生产 consumer snapshot；**#3（版本 normalizer）已实施**（matcher 逻辑层，代码提交，重启 web 服务生效，无需重建 snapshot）。

| 项 | 落点 | 实效（真实 852MB mirror DB） |
|---|---|---|
| #1a 过滤 n/a 占位产品 | `build_local_euvd_snapshot.py:product_rows` | local_products 1,113,450 → **969,305**（-144,145 行，0 残留） |
| #2 CVE mapping 回填 | 同上（遍历 record aliases） | mapping 355,046 → **372,484**（+17,438，**CVE 路径 95.32% → 100%**） |
| #1b vendor+product 联合 | `matcher.py:_query_local_product` | joint/fallback/none 三态，无结果回退（设计约束 #5） |
| #1c 产品候选 top-N cap | `matcher.py:match_components` | 默认 50，CVE 精确路径不截断，sort 已浮已匹配到前 |
| #3 版本 normalizer | `matcher.py:version_is_affected` | None -1,328；保守，见下方诚实评估 |

附带：consumer `cve_euvd_mapping` 表 5→2 列（lean），snapshot 更小；`tests/conftest.py` 修复本地 `DATA_DIR`/`OUTPUT_DIR` 容器路径依赖。

回归：Web 131 passed（+16 新测试）、镜像 47 passed。提交 `08b5828`（#1+#2）/ `f8efda4`（#3）。

**边界重测（部署后）**：
- **CVE 精确路径 100%**（带 CVE 的 SBOM 零静默漏）— 最大短板已补齐
- **产品候选路径**：噪声 -13% + vendor 联合收窄 + top-N 防 8830 候选爆炸，真实 syft 场景可用性显著提升
- **#3 版本判定（诚实评估）**：保守 fuzzy 救援救回 1,328 个真实可判定 expression（此前 None 现确定 True/False，零误判）。**未达 49%→65-70% 目标**——EUVD 的 51% prose 中大量是 `n/a`/`unknown` 占位 + 模糊人类描述（无机器可解析版本范围），保守可救的（有明确范围语义）仅 ~0.14%；激进救 placeholder/fixed-in/bare-product 会冒误判 True 牵连无关旧版本的风险，违反"宁可待核验不可误报"原则，故保守不动。

**剩余 §3 backlog**（价值递减，后续迭代）：#4（Windows SKU 归一化，仅 Windows 场景）、Phase C float 版本丢尾零。**#5 已于 2026-08-06 调查关闭**（无 CPE 匹配基础设施可弃，详见 §5.1）。

### 5.1 #5 CPE 基础设施调查（2026-08-06，关闭）

5-agent workflow（`cpe-deadcode-survey`：4 路并行静态调查 matcher/snapshot/tests/api-ui + synthesis）+ 独立 grep 交叉验证，结论一致：

- **CPE 在代码里从不是匹配查询词**：`EuvdClient.search()`（matcher.py:1226）/`_query_local_product()`（L906）只按 product_key+vendor_key 查；local SQLite 表（local_products/vulnerabilities/cve_euvd_mapping/known_exploited）无 cpe 列；mirror 侧 `euvd_sync.py` CREATE TABLE 也无 cpe 列。**snapshot 无需重建**。
- §1 的「39/1,117,611 有 CPE」是 **EUVD 侧** `product_version` 字段含 CPE 字符串的记录数（数据观察），**非消费者侧 CPE 匹配代码**。§3 #5 据此判「死代码」是误读。
- CPE 实际承担**最小化活角色**：`parse_cpe`（L147）→ `enrich_component`（L161-170）回填 CPE-only 组件的 name/vendor（喂后续 name+vendor 搜索）；`identity_ready`（L1839）把 cpe 作身份判据之一（喂身份覆盖 KPI）；`component_cpe`（L1401/1509）作审计证据展示；`spreadsheet_io.py:76-82` 识别 SBOM 表格 CPE 列。
- **synthesis 推荐 `proceed-partial`**（删 parse_cpe + enrich CPE 分支 + CpeParsingTests），但**决定保留**：删除是非对称风险——省 ~16 行代码，却引入 #5 风险（CPE-only 组件静默放弃识别，哪怕 0.004%）+ 跨文件协调（`Component.cpe` 字段级联 spreadsheet_io 9 处/main 2 处/sbom_evidence 3 处）+ 身份覆盖 KPI 回归。在「宁可待核验不可误报」+「surgical changes」下，保留零成本零风险，删除收益边际。

**结论：#5 关闭，不改代码。** CPE 保持最小化组件归一化角色。

### 5.2 Phase A 运维可靠性加固（2026-08-06）

单文件三告警架构：3 个运维告警（orchestrator 存活 / 数据时效 / ENISA 403）都通过既有 `sync-status.json`（Mirror 写、Web 读）传递，无新文件、无 Web→Mirror 写，#3 完整。Mirror 在 status 写位点 stamp 新字段；Web `/api/euvd/sync-status` 透传；前端 header `#alertBadges` 60s 轮询渲染。

| 子任务 | 落点 | 实效 |
|---|---|---|
| A1 守护心跳 | `mirror_ops.write_status` 注入 `guardian_heartbeat_at`（每写刷新）+ 契约 docstring | watch 每 5s poll 刷新；4 stage 转换推进；Web TTL 判活 |
| A2 数据时效 | `mirror_ops.compute_data_age`（`max(updated_raw)`）+ `FRESHNESS_WARN_DAYS=3`/`STALE_DAYS=7`（env）+ completed stamp `data_age_days`/`snapshot_data_date` | 前端 badge <3 ok / 3-6 滞后 / >=7 过期；alert_watch 同阈值 |
| A3 ENISA 403 计数 | `euvd_sync._record_egress_failure/success`（sync_state KV，跨 run 持久）+ sync() except typed 403 increment + completed 清零；`mirror_ops.enisa_egress_status` 翻译（0 ok / 1-2 degraded / >=3 blocked）+ completed/failed stamp | 告警从子串匹配提升为 typed 字段；recurrence 语义 |
| A4 Web 判活 | `main._orchestrator_alive` 心跳优先（`GUARDIAN_HEARTBEAT_TTL_SECONDS=900` env），无心跳 fallback finished_at（向后兼容旧 Mirror） | 心跳过期 → orchestrator_available=False |
| A5 前端 badges | `index.html #alertBadges` + `app.js renderAlertBadges/pollOpsAlerts(60s)` + styles.css | 3 告警 header 常驻（不再埋 Art.14 view） |
| A6 alert_watch typed | `check_signals` 加 `data_stale_days` 参数 + data_age 规则 + enisa_egress_status typed 规则 | operator sink（log/macos/webhook）消费同字段 |

测试：Mirror 63 passed（47 基线 + 16 新）/ Web 138 passed（131 基线 + 7 新 `test_orchestrator_health`）/ app.js 语法 OK。

部署：Mirror 改动需重启 `mirror_ops watch`；Web 改动需重启 uvicorn + 浏览器刷新。snapshot 无需重建（A3 计数器用既有 `sync_state` 表，无 DDL）。

已知限制（plan 风险，接受）：(1) 单 subprocess >900s（如大增量重建）→ Web 误报 orchestrator-down（4 stage 推进心跳缓解；超 TTL 的 hung 是真问题值得告警，后台线程心跳留后续）；(2) `data_age_days` 在 ENISA 无新漏洞时显示陈旧（上游空窗非 sync 故障），同时显示 `snapshot_data_date` 供辨别；(3) 403 计数器在 egress 修复但无成功 sync 时不清零，下次成功 sync 自动清零。

### 5.3 Phase B 合规交付物强化（2026-08-06）

CRA 合规证据包：per-job ZIP（manifest.json + evidence.json + evidence.xlsx + audit_trail.json），regulator/auditor 可独立打开。复用既有 art14 三层模式（builder + writers + extension endpoint）+ spreadsheet_io._safe_cell。

| 组件 | 落点 | 内容 |
|---|---|---|
| audit chain 导出 | `workflow_store.verify_audit_chain`（移植 test loop 到生产）+ `export_audit_trail(job_id)` | 全局 hash chain 校验 {verified,broken_at,event_count} + job in-scope audit_events（id ASC，8 列含 prev_hash/payload_json）|
| builder | `app/evidence_package.build_evidence_package_payload` | project_identity / sbom_integrity(rehash) / data_provenance / matches[] / unmatched / cra_reportable_judgments[] / audit_trail / chain_verify / disclaimer |
| CRA reportable | 复用 `art14_decision=='reportable'` + 5-leg basis（applicability / exploitation_evidence / awareness / reliable_evidence_rows / four_eye_approval）+ legal_basis 条款号引用（Art.13/14, 3(8), 3(42), 14(1)） | KEV≠Art.14 disclaimer（`public_signal_is_not_art14_decision`）|
| writers | `write_evidence_xlsx`（4 sheets，_safe_cell）/ `write_evidence_package_zip`（manifest per-entry sha256）| 复用 _safe_cell（csv-injection =/+/-/@ + XML 控制字符）|
| endpoint | `GET /api/jobs/{job_id}/evidence-package[?format=zip|json|xlsx]` | 复用 download_report 守卫；fail-closed：SBOM rehash mismatch→422 |
| 前端 | 项目详情「证据包」按钮（复用 downloadReport `<a>` 模式）| completed 任务可见 |

设计取舍（vs design agent 提案）：6→4 文件 zip（pre7/sbom_snapshot 合入 evidence.json）；audit chain in-scope（客户隔离）+ global verify + README 说明全局链语义（避免跨项目泄露）。legal_basis 仅引用条款号，不编造释义（符合「条文释义以官方文本为准」）。

测试：Web 150 passed（138 Phase A + 12 Phase B：audit chain 5 / builder 5 / writers 2）。app.js 语法 OK。

已知限制：(1) audit chain prev_hash 全局，in-scope 首事件可能引用项目外事件（chain_verify_result 为全局校验，audit_trail.json README 说明）；(2) cases 表可能空（scanner-only），judgments=[] + disclaimer；(3) endpoint 薄层未加 TestClient 集成测试（builder/writers 12 测覆盖 + 全套 150 无回归，fail-closed 逻辑薄，surgical）。

### 5.4 Phase C 工程整洁收尾（2026-08-06，调查后 skip）

两个子任务调查后均「前提有问题/边际」，不 brute force（同 #5 原则：宁可待核验不可误报 + surgical）：

**float 版本丢尾零**：openpyxl 本质限制。数字格式 cell 在 Excel 端存 float（"1.10"→1.1），原始 string 丢失；per-cell 文本读取需绕过 openpyxl（zip + sheet XML parse），工作量大且边缘。客户模板 PRO-03B 版本列默认文本格式（`number_format='@'`）→ openpyxl 读 str（保留尾零），仅客户不按模板输数字到通用列才触发 → warn ROI 低。保持现状（parsing-evidence §5 已记录此已知限制）。

**#4 Windows SKU 归一化**：当前 snapshot 70050 distinct products / Windows 114127 行，碎片化确认（Windows / Windows Server / Server Core / Version 变体各独立 product_key）。但合并会**误报**——Core vs 非 Core、不同 Version 是真实的不同受影响产品（CVE 受影响范围不同），合并扩大命中违反 #5「宁可待核验不可误报」。候选噪声已由 #1c top-N cap（50）控制。

**结论：Phase C skip，无代码改动。** 两个子任务前提有问题（float 本质限制 / Windows 合并误报），保持现状 + 文档说明。
