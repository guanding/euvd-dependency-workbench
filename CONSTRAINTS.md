# EUVD Dependency Workbench — 编号化架构约束

> 本文件记录不可突破的架构边界与已知残留风险。任何改动若与这些约束冲突，必须显式标注并获得确认。
> SBOM Workbench 侧（产出方）的对应约束由该项目公开候选中的 `README.md`、`RELEASE_PROCESS.md` 与测试契约独立维护。

## C-1: Web 工作台不是 EUVD 数据同步权威（约束 #3）

Web 工作台只读消费本地 EUVD 快照；数据同步由 Mirror（`EUVD-Local-Mirror`）的 `mirror_ops.py` 编排器权威执行。Web 通过 `sync-request.json` 信号文件触发同步、通过 `sync-status.json` 只读状态，**绝不在 Web 内 subprocess 同步、绝不写正式 Mirror**。

## C-2: 本地信任域定义

「本地」= SBOM Workbench 进程树及其 lane 隔离，**不含 EUVD Web 工作台进程**。客户源码只允许进入 SBOM Workbench 的本地进程树（Syft 三面扫描 + Qwen/Gemma shadow 辅助，adapter 默认关闭），**永不进入 EUVD Web 工作台**。EUVD Web 只接受成品 SBOM（已脱源码）。任何"在 Web 上传源码→扫描→生成 SBOM"的诉求击穿本边界，须先修订本文件。

## C-3: 单向 handoff（SBOM → EUVD）

SBOM Workbench 经 `euvd_handoff.py` 产出单向、hash-bound 的 CycloneDX handoff（`direction=SBOM_TO_EUVD_ONLY`，`reverse_fact_write=false`）。EUVD Web 入口（`upload_preview` 经 `_extract_handoff_binding`）对 receipt 做 fail-closed 校验，任一不符即 HTTP 400：
- `direction == "SBOM_TO_EUVD_ONLY"`
- `reverse_fact_write is False`
- `cyclonedx_sha256 == sha256(落盘 cyclonedx)`
- `classification == "SELF_TEST_NOT_CUSTOMER_EVIDENCE"`
- `authority_boundary == "NO_SBOM_FACT_RELEASE_CONFORMITY_OR_REPORTING_AUTHORITY"`
- `kev_boundary == "KEV_PRESENCE_IS_PRIORITIZATION_ONLY_ABSENCE_IS_NOT_NON_EXPLOITATION_PROOF"`

**已知残留**：单向性目前是字段级断言 + Web 入口校验，**非进程/网络级强制**。若有人在 EUVD Web 侧另写工具直读 SBOM Workbench `runtime/` 数据库，本机制不感知。升级为进程级强制需另立 sandbox-exec / 容器网络策略方案。

## C-4: 不冒充 CRA 符合

SBOM Workbench 产出是 `SOURCE_DERIVED_CANDIDATE / SELF_TEST_NOT_CUSTOMER_EVIDENCE`（工程内部候选 SBOM），**远未达 CRA Annex II 法定形态**（缺制造商授权 / 客户产品绑定 / 三面证据闭合）。`classification / authority_boundary / kev_boundary` 必须随 evidence package 流转（`evidence_package.build_evidence_package_payload` 写入 `sbom_source_declarations`；`_overview_sheet` 渲染；`evidence.json` 序列化）。前端声明面板（`renderSourceDeclarations`）显式区分 DECLARED（单面）/ VERIFIED（三面）provenance。

机械扫描 PASS、KEV 命中、漏洞匹配结果均**不等于** CRA Art.13/14 符合、不等于技术文档放行、不等于认证。

## C-5: EUVD 命中匹配 ≠ SBOM 生成或 CRA Art.14 报告

漏洞匹配是独立下游工作流。EUVD 命中（含 KEV）只做优先级排序，**不能**自动形成 Art.14 报告决定（需人工 awareness + 产品级证据 + 四眼审批）。

## C-6: Mirror CLI 与纯 SBOM 的已知 BLOCKER

`sbom_match.py`（Mirror 侧 CLI）的 `read_cyclonedx` 以 `vulnerabilities[]` 为唯一发射门，纯 SBOM（无 vulnerabilities）产出 0 observation；且 `_component_context` 不抽 cpe。因此 Web 工作台产出的 job（走 Web 自带 `matcher.py`）**不会自动落 Mirror CLI**。"在 EUVD 上传 SBOM"的心智模型不应默认包含 Mirror 定时重扫 / 批量 CLI 匹配。若需 Mirror 消费纯 SBOM，须先修 BLOCKER（增加 components[] 发射口 + cpe 抽取 + properties[].syft:cpe23 解析）。
