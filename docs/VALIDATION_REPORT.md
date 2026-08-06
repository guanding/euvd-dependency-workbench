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
5. **放弃 CPE 基础设施**：0.004% 覆盖不值得；全力 name+vendor 模糊匹配 + 版本范围解析。

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

**剩余 §3 backlog**（价值递减，后续迭代）：#4（Windows SKU 归一化，仅 Windows 场景）、#5（放弃 CPE 基础设施，0.004% 覆盖的死代码清理）。
