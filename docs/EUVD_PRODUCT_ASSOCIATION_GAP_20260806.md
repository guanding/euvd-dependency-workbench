# EUVD CVE→product 关联 gap：matcher product 路径的系统性漏报

> 测试日期 2026-08-06｜EUVD 快照 984MB（372484 漏洞 / 969305 产品记录 / 372484 CVE 映射）
> 配套：嵌入式 SBOM 盲区测试（EMBEDDED_SBOM_BLIND_SPOT_20260806.md）的姊妹发现

## 摘要

EUVD 收录了**完整 CVE**（372484 漏洞，CVE→EUVD 映射 100% 覆盖），但 **43.6%（162647）漏洞无 product 关联**（`local_products` 为空）。matcher 的 product 候选路径（组件 name → product_key → `local_products`）对这些漏洞**系统性漏报**。CVE 精确路径（组件带 CVE → `cve_euvd_mapping`）能突破。验证：FreeRTOS/STM32 的 5 个 CVE（含 CRITICAL 9.8）带 CVE 时**全命中**，不带 CVE 时**0 命中**。

## 关键数据

### 全局关联 gap 规模
| 指标 | 数量 | 占比 |
|---|---|---|
| EUVD 漏洞总数 | 372484 | 100% |
| 有 product 关联（`local_products` 非空） | 209837 | 56.4% |
| **无 product 关联** | **162647** | **43.6%** |

### FreeRTOS / STM32 验证（caw-bms 真实组件）
| CVE | EUVD ID | 严重度 | local_products 关联 |
|---|---|---|---|
| CVE-2018-16523（FreeRTOS+TCP 除零） | EUVD-2018-8332 | HIGH 7.4 | **0** |
| CVE-2021-31571（FreeRTOS queue.c 整数溢出） | EUVD-2021-18465 | — | **0** |
| CVE-2019-14236（STM32L4 PCROP 绕过） | EUVD-2019-5478 | **CRITICAL 9.8** | **0** |
| CVE-2020-27212（STM32L4 RDP） | EUVD-2020-19731 | — | **0** |
| CVE-2021-29414（STM32L4 物理访问） | EUVD-2021-16049 | — | **0** |

> FreeRTOS 产品本身在 EUVD 有 17 条产品记录、关联 11 个 EUVD 漏洞——但上面这 5 个 CVE 全部**没有**关联到任何产品。

## matcher 路径对比（实证）

同一批组件（FreeRTOS 10.0.1 + STM32L431），仅改变是否带 CVE：

| 组件输入 | matcher 路径 | 命中数 | 命中详情 |
|---|---|---|---|
| name + version（**无 CVE**） | product 候选（product_key → local_products） | **0** | 关联 gap 漏报全部 5 个 |
| **带 CVE** | CVE 精确（cve_id → cve_euvd_mapping） | **5（全 confirmed）** | EUVD-2018-8332 / 2021-18465 / 2019-5478 / 2020-19731 / 2021-16049 |

## 根因

EUVD（ENISA 欧洲漏洞库）上游的**CVE→product 关联不完整**：
- CVE 漏洞记录全（vulnerabilities 表 + cve_euvd_mapping）
- 但 `local_products`（CVE→具体产品 + affected_versions）只覆盖 56.4%
- matcher 的 product 候选路径完全依赖 `local_products` → 对 43.6% 无关联漏洞必然漏报
- CVE 精确路径走 `cve_euvd_mapping`（100% 覆盖）→ 不受关联 gap 影响

## CRA 合规含义（漏洞完整性）

1. **常规 SBOM 组件只带 name/version（不带 CVE）** → matcher product 路径漏报 43.6%，**含 CRITICAL 级**（如 STM32L4 PCROP 9.8）
2. SBOM 带 CVE（VEX-enriched）能突破，但**要求上游 SBOM 含已知 CVE**——这不符合 SBOM 的本质（SBOM 是组件清单，CVE 是匹配后发现的）
3. 这制造一个**悖论**：要 matcher 不漏报，SBOM 须先含 CVE；但 CVE 正是 matcher 该发现的

## 突破路径

1. **SBOM 带 CVE（VEX-enriched）**：上游 SBOM 工具链 enrich 已知 CVE（如从 NVD/OSV 预关联）→ matcher CVE 精确路径命中。但需 SBOM 生成时查 CVE 库。
2. **EUVD 补 product 关联**：上游数据治理（ENISA 补 `local_products`）。不可控（依赖 ENISA）。
3. **OSV 第二信任锚**（推荐）：OSV 的 `affected.range` 提供产品级精确版本范围匹配，补 EUVD 关联 gap。SBOM Workbench `SBOM_TOOL_LANDSCAPE_UPGRADE_PLAN.md` 已识别此方向：「EUVD 单源命中精度不足 → OSV 离线快照第二信任锚，绝不因 OSV 未命中放行 EUVD 命中（双源收紧，不放松）」。

## 印证 landscape plan

`SBOM_TOOL_LANDSCAPE_UPGRADE_PLAN.md` §3 P1：「**EUVD 单源命中精度不足**（包名布尔命中，不校验 affected version range）→ OSV 离线快照作第二信任锚」。本次测试**精确证实**：根因是 CVE→product 关联 gap（43.6%），不是数据缺失。OSV 的 `affected.range` 正好补这个 gap。

## 对方案 A 的影响

方案 A 的 EUVD 导入**中立**（消费任何合法 CycloneDX + receipt）。下游匹配的关联 gap 是 **EUVD 数据治理 + matcher 的既有局限**，非方案 A 引入。但方案 A 的用户须知晓：对无 product 关联的漏洞（43.6%），仅靠 name/version 匹配会漏报，需 SBOM 带 CVE 或引入 OSV 第二源。

## 复现

```bash
# 无 CVE：product 路径
Component(name='FreeRTOS', version='10.0.1')  # → 0 matches
# 带 CVE：CVE 精确路径
Component(name='FreeRTOS', version='10.0.1', cve_ids='CVE-2018-16523')  # → EUVD-2018-8332 命中
```
