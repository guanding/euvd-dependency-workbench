# EUVD Dependency Workbench v2.3.1

v2.3.1 是基于 v2.3.0 的 SBOM 客户模板与导出闭环补丁：

- 网页下载清理后的 `PRO-03B v1.4` SBOM 内容兼容模板；
- 客户模板保持空白，Demo 数据与客户输入隔离；
- 自动选择最符合 SBOM 表头的可见工作表，不再固定读取元数据页；
- 精确识别 PRO-03B 兼容双语表头，并拆分 PURL、CPE、Internal ID；
- 新增许可证、CVE、EUVD ID 字段，支持 CVE→EUVD 确定性映射；
- 模板改为容器内版本化静态制品，避免 `outputs/` 旧缓存继续返回；
- 表格说明与组件数据分工作表，避免说明文字成为伪组件；
- XLSX 上传不再错误声明包含 PRE-7 item-level observations；
- EUVD 报告新增“输入SBOM快照”，保留客户填写的依赖、证据、构建边界与缺口；
- 新增空白模板、映射、静态资源、证据语义和闭环 Demo 测试。

边界：Demo PASS 只证明当前本机模板下载、导入、EUVD/KEV 匹配和报告导出链路。
它不证明 SBOM 完整性、客户产品受影响、CRA Art.14 可报告性、SRP 提交、符合性
或发布批准。当前 EUVD 本地快照仍保持其实际新鲜度状态，不因本补丁而提升。
