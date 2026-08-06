# 嵌入式 SBOM 盲区：syft/cdxgen 对 STM32CubeMX 固件的覆盖 gap

> 测试日期 2026-08-06｜EUVD 快照 984MB（372484 漏洞）｜syft 1.50（governed）｜cdxgen（npx 最新）
> 配套：方案 A（SBOM Workbench handoff 导入槽，commit 35d3cab）

## 摘要

syft 1.50 与 cdxgen（默认 / `-t c` / `--deep` 三模式）对 STM32CubeMX 裸固件项目（caw-bms，844 个 C 文件）**均产出 0 组件**。根因是两个工具都依赖包管理器清单，而嵌入式固件的 HAL/FreeRTOS 以源码形式手动复制进 `Drivers/` / `Middlewares/Third_Party/`，无标准清单。真实组件信号（FreeRTOS V10.0.1 版本宏、HAL/CMSIS 目录）**确凿存在但未被提取**。突破需领域专用 cataloger。方案 A 的 EUVD 侧对此**完全中立**——消费任何合法 CycloneDX。

## 测试对象（3 个开源 BMS 项目）

| 项目 | 性质 | syft 结果 | 判定 |
|---|---|---|---|
| **BMS_BLE-HA** | Home Assistant 集成（Python/依赖清单） | 27 组件 | 正常，方案 A 全链路验证通过 |
| **SmartBMS** | KiCad 硬件 PCB + 2 个手写 Arduino `.ino` | 0 | **正确**——无标准软件依赖可扫 |
| **caw-bms** | STM32L4 固件（844 C 文件，STM32CubeMX `.ioc`） | 0 | **真盲区** |

## 工具矩阵（caw-bms）

| 工具 / 模式 | 组件数 |
|---|---|
| syft 1.50（source） | 0 |
| cdxgen 默认（自动检测） | 0 |
| cdxgen `-t c` | 0 |
| cdxgen `--deep`（C/C++ 深度模式） | 0 |
| **领域 cataloger 提取（演示）** | **3**：FreeRTOS 10.0.1 + STM32F1xx HAL + CMSIS |

## 根因

syft + cdxgen 都靠**包管理器清单**（pip/npm/conan/platformio/cargo）。STM32CubeMX 固件依赖（HAL、FreeRTOS）以**源码形式手动复制**进 `Drivers/` / `Middlewares/Third_Party/`，没有标准清单——两个工具的 cataloger 都无信号。这是 `.ioc` + STM32Make.make 构建系统范式，cdxgen `--deep` 的 C/C++ 头文件分析覆盖不到。

## 信号证据（caw-bms，证明是工具 gap 不是无信号）

```
Firmware/Middlewares/Third_Party/FreeRTOS/Source/tasks.c:
  #define tskKERNEL_VERSION_NUMBER "V10.0.1"      ← 版本宏就在源码里
Firmware/Drivers/STM32F1xx_HAL_Driver/             ← HAL 目录（91 个 hal 文件）
Firmware/Drivers/CMSIS/                            ← ARM CMSIS
caw-bms.ioc: Mcu.Family=STM32L4  Mcu.Name=STM32L431C(B-C)Ux
```

## 突破路径（已演示路径 2 可行）

1. **上游改造**：客户用 PlatformIO / Conan 管理依赖 → syft/cdxgen 能扫 → SBOM Workbench 正常（最合规，要求改构建）
2. **领域 cataloger**：自研 STM32CubeMX `.ioc` 解析 + `Third_Party/` 扫描 + 版本宏 grep → CycloneDX（演示已验证产出可被 EUVD 方案 A 消费）
3. **人工声明**：客户填 PRO-03B 依赖清单 + 制造商签发（CRA Annex I 接受工具辅助 + 人工声明组合）

## 方案 A 印证（EUVD 侧中立）

EUVD 方案 A 的 `_read_cyclonedx` + `_extract_handoff_binding` 对 CycloneDX **来源中立**——消费 syft / cdxgen / 手工任何合法 CycloneDX + receipt。突破后的嵌入式 SBOM（演示：FreeRTOS 10.0.1 + HAL + CMSIS 三组件）被 EUVD 正常导入（`metadata_binding.evidence.classification=SELF_TEST_NOT_CUSTOMER_EVIDENCE`，DECLARED provenance）+ 匹配。

> FreeRTOS/HAL 在 EUVD 0 命中是**真实数据**（欧洲漏洞库对嵌入式组件覆盖有限），非 bug。这又揭示一个 gap：EUVD 单源覆盖，landscape plan 已识别需 OSV 第二信任锚。

## 边界印证（SBOM Workbench 诚实声明）

`11_SBOM_Workbench/.planning/PROJECT.md` Out of Scope：「v1 不支持任意语言、任意构建系统和任意固件——无边界覆盖无法形成可验证的完整性主张」。caw-bms（STM32CubeMX 裸固件）在此边界外。`SBOM_TOOL_LANDSCAPE_UPGRADE_PLAN.md` 已识别"嵌入式/固件覆盖不足"为已知 gap。

## 合规建议（嵌入式客户的 CRA 合规 SBOM）

- **不能依赖 syft/cdxgen 自动生成**（盲区跨工具，非配置问题）
- 优先**上游改造**（PlatformIO/Conan），否则**领域 cataloger** 或**人工声明**
- SBOM 完整性声称必须诚实：工具自动扫描的 SBOM 在嵌入式场景是**部分覆盖**，需配合制造商声明
- 漏洞匹配注意 EUVD 单源 gap（FreeRTOS/HAL 0 命中 ≠ 无漏洞）

## 附录：测试脚本（可复现）

- `/tmp/gen_bms_handoffs.py`：Workbench 侧生成 DECLARED handoff（governed syft + prepare_euvd_handoff）
- `/tmp/verify_bms_euvd.py`：EUVD 侧全链路验证（read_sbom + match_components + evidence_package）
- `/tmp/demo_caw_breakthrough.py`：嵌入式盲区突破演示（手工提取 FreeRTOS/HAL → EUVD 消费）

## 三项目方案 A 链路结果

| 项目 | syft | handoff | EUVD 导入 | EUVD 匹配 | 证据包含声明 |
|---|---|---|---|---|---|
| BMS_BLE-HA | 27 record（20 组件） | ✓ DECLARED | ✓ evidence 全字段 | 0 命中（真实） | ✓ SELF_TEST 流转 |
| SmartBMS | 0（硬件项目，无软件） | — | — | — | — |
| caw-bms | 0（syft/cdxgen 盲区） | — | — | — | — |
| caw-bms（领域 cataloger 演示） | 3（FreeRTOS+HAL+CMSIS） | ✓ 手工 receipt | ✓ | 0（EUVD 单源 gap） | ✓ |
