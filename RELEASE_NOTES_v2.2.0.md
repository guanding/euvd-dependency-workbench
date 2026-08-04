# Release Notes — v2.2.0

发布日期：2026-07-28

## 新增

- SQLite 持久化案件、SBOM 快照、证据、审批、回执、VEX、feed 和审计事件；
- CycloneDX 1.7 / CSAF 2.0 VEX 导入导出与冲突控制；
- 无 CVE/EUVD 的 zero-day 人工案件；
- 产品适用性、实际恶意利用结构化证据和制造商 awareness；
- 24h、72h、修正/缓解措施可用后 14 日时限；
- 技术提议 + 不同本地账户合规复核的一致性审批；
- ENISA SRP FAQ Q16 漏洞字段与 JSON/XLSX/HTML 草稿；
- early-warning、notification、final-report 独立人工回执；
- EUVD mapping / KEV 的 fresh、stale、degraded、unavailable 状态。

## 修正

- KEV 未命中不再关闭 CRA 人工评估；
- CVE 精确匹配在第一个版本范围不命中时继续检查后续范围；
- 报告下载限制在输出目录，阻断路径越界；
- 服务重启后不再把中断任务永久留在 running；
- VEX 不再生成虚假的 `CVE-UNKNOWN`；
- 移除运行界面的外部 CDN 依赖；
- Windows `WithData` 导出改用 SQLite online backup。

## 兼容与迁移

- 原 v2.1 任务 JSON 和报告保持可读；
- 启动时把已完成的旧任务幂等登记为 SQLite SBOM 快照；
- 新的 build/hash 变化会重开未提交的产品适用性和审批结论；
- 不自动迁移或伪造旧扫描缺失的源 SHA-256。

## 已知边界

- 本地 PIN 不是完整登录、SSO、电子签名或现实身份验证；
- 不自动提交 ENISA SRP；
- 不覆盖严重事件报告的完整工作流；
- prEN 40000-1-3 仍为项目冻结的 Enquiry draft，不构成协调标准符合性推定；
- 审计数据库不抵抗本机管理员篡改。
