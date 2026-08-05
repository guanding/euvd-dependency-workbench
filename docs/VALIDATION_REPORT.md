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
