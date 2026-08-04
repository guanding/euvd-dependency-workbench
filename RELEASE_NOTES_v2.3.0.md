# EUVD Dependency Workbench v2.3.0

v2.3.0 是本机 Docker 使用候选，新增：

- 独立 EUVD 正式镜像到 Web 只读快照的数据面；
- CVE→EUVD、KEV、产品索引和数据版本/新鲜度边界；
- CycloneDX metadata、文档身份、组件关系和 PRE-7 字段证据保真；
- 固定摘要、断网、非 root、无 Docker Socket 的 Syft SBOM 生成 sidecar；
- 扫描前渲染配置与扫描后实际容器 inspect 的双重控制绑定；
- Web EUVD 快照单文件只读挂载、外部 SHA-256 验证和默认禁止网络回退；
- 紧凑上传记录与组件/深度/大小的持久化前边界；
- JSON 原始 SBOM 与 `<upload_id>.upload-record.json` 分路径保存及原文 SHA-256 回归断言；
- source、Linux image、Windows portable 三类制品的独立自测与对账；
- 面向人工操作的启动、评估、镜像更新和源代码 SBOM 指南。

已知限制：

- 2026-08-04 ENISA 从当前出口返回 403；本机数据状态为 `local_degraded`，漏洞
  高水位仍为 2026-07-28；
- Windows portable runtime 发现 5 组旧/新直接依赖并存，v2.3 portable 候选不
  具备交付资格；
- 平台不自动决定 CRA Art.14 报告义务，不自动提交 SRP；
- 自生成 SBOM 和自动化测试不是产品 CRA 符合性证据或发布批准。

详细操作见 `docs/HUMAN_OPERATION_GUIDE_v2.3.md`；实施和测试边界见
`docs/V2.3_IMPLEMENTATION_AND_TEST_REPORT.md`。
