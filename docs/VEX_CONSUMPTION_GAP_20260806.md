# VEX 消费链路现状与对接缺口

> 测试日期 2026-08-06｜配套：方案 A handoff 导入槽（35d3cab）+ 嵌入式盲区系列文档

## 摘要

EUVD Web `vex.py` 的 `POST /api/vex/import` 接受任意 JSON，**无 issuer allowlist / 签名验证 / hash 绑定**——是 `SBOM_TOOL_LANDSCAPE_UPGRADE_PLAN.md` 自己点名的「厂商自签 VEX 绕过命中」反模式。SBOM Workbench M8-1 完全落地 4 护栏。完整对接需 EUVD 加信任锚（中等改动），本次只做 **spec 放宽**（1.7→1.5/1.6/1.7，与 Workbench 一致，小改）。

## 两端现状对比

| 维度 | EUVD Web vex.py | SBOM Workbench M8-1 vex_consume.py |
|---|---|---|
| 消费端点 | `POST /api/vex/import`（main.py:1139） | CLI `intake-vex`（cli.py:2002） |
| CycloneDX VEX | ✅（vex.py:43，**本次放宽 1.5/1.6/1.7**） | ✅（不锁版本） |
| OpenVEX | ❌ | ✅ |
| CSAF 2.0 | ✅ | ❌ |
| issuer allowlist | ❌ **无** | ✅ `vex_issuer_allowlist.json`（当前空载占位） |
| cosign 签名验证 | ❌ **无** | ✅ 离线验签 |
| exact-set hash 绑定 | ❌ **无** | ✅ `verify_vex_intake_binding` 重算 fail-closed |
| 只收窄不放过 | ⚠️ 半（not_affected 缺 justification 降级） | ✅ NARROWED_BY_TRUSTED_VEX 仍保留命中 |
| 无签名 fail-closed | ❌ 接受所有 JSON | ✅ |

## 反模式风险（EUVD 侧）

`POST /api/vex/import` 接受裸 VEX 直接置 `known_not_affected` → 结构性阻断 Art.14 `reportable` 决策（`workflow_store.py:1089` 要求 `applicability_status==known_affected`）。这意味着**厂商可上传自签 VEX 关闭自己的命中**——正是 landscape plan §3（:82-83）明令禁止的逃逸门。

部分缓解：`not_affected` 缺 justification/detail 时降级为 `under_investigation`（vex.py:149-155）。但这不阻止有 justification 的裸 VEX。

## 对接缺口（6 项，按优先级）

1. **EUVD 缺信任锚**（最大）—— `/api/vex/import` 须加 issuer allowlist + cosign 验签/intake receipt 重算 + 拒绝裸 JSON
2. **身份模型不一致**——EUVD 用 `product_id`/bom-ref，Workbench 用 `purl`；decisions.json 无法精确匹配 EUVD case
3. **闭环回流路径不存在**——Workbench 明确不回写 euvd_handoff（`narrowing_reconcile.py:8-9`，4 方案对比选定 isolated-intake）；需新建独立 lane
4. **Art.14 语义不对齐**——Workbench `NARROWED_BY_TRUSTED_VEX` 是证据标注（boundary 明示不关闭命中），EUVD `known_not_affected` 会阻断 reportable；回流时人工仍须复核
5. **issuer allowlist 空载**——`vex_issuer_allowlist.json` 只有 `NOT_ADMITTED` 占位，真实 PSIRT 登记是运维任务
6. **EUVD spec 过严**——~~锁 1.7~~ **本次已修**（放宽 1.5/1.6/1.7）

## 推荐架构（Workbench 信任锚网关）

```
外部 PSIRT VEX ──→ [SBOM Workbench M8-1: issuer allowlist + cosign + exact-set hash]
                            ↓ 签名绑定的 intake receipt + decisions
                  [EUVD: 只接受 receipt + 原始 VEX，重算 verify_vex_intake_binding]
                            ↓ 人工复核
                  [EUVD applicability_status → known_not_affected → Art.14 决策]
```

- 所有外部 VEX 必须先进 Workbench M8-1（信任锚网关）
- EUVD `/api/vex/import` 改为**只接受 receipt + VEX**，重算绑定后才落库
- **永不让 EUVD 独立消费裸 VEX**（消除反模式）
- Workbench M8-2 decisions 作辅助证据，**人工**在 EUVD 决定 `known_not_affected`（不让 receipt 自动设状态，守 Workbench boundary）

## 本次小改（2026-08-06）

- `app/vex.py:43` spec 放宽 `1.7` → `{1.5, 1.6, 1.7}`（与 Workbench vex_consume 一致，外部 PSIRT 1.5/1.6 VEX 不再被拒）
- format 字段动态化 `cyclonedx-{spec}`（顶层 + entry）
- 测试 +1（`test_cyclonedx_1_5_accepted_after_spec_widening`），160 passed

## CRA 合规建议

EUVD 当前接受裸 VEX 是**真实合规风险**（厂商自签绕过命中）。完整修复（信任锚 + receipt 重算 + purl 映射）是中等改动，建议作为下一迭代。过渡期：
- 运维层限制 `/api/vex/import` 的访问（仅受信分析师）
- not_affected 必须人工四眼审批才置 Art.14 决策（现有 reportable 守卫）
- 登记 PSIRT issuer allowlist（Workbench + EUVD 共用），为对接做准备
