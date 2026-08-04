# EUVD Dependency Workbench

当前 Docker 本机候选版本：`v2.3.1`

这是一个本地、轻量、可迁移的客户 SBOM 漏洞管理工作台。信息架构参考
Dependency-Track 的项目化工作方式，但只查询 ENISA European Vulnerability
Database (EUVD) 的 CVE 映射、漏洞详情和 EU/CISA KEV 公开数据，不会下载
或展示 NVD、OSV、GitHub Advisory、OSS Index 或商业漏洞库的信息。

v2.2 增加了 SQLite 案件库、CycloneDX 1.7 / CSAF 2.0 VEX、CRA Art.14
人工判定、制造商 awareness 确认、24h/72h/最终报告时限、四眼审批、
ENISA SRP Q16 字段检查、分阶段草稿导出和手工提交回执。它是证据与工作流
工具，不是自动法律判定器，也不连接或代替 ENISA SRP。

v2.3 优先查询独立生成的 EUVD 本地只读镜像，保留 CVE 映射、KEV 和数据版本
边界；同时增加 CycloneDX PRE-7 字段证据保真和隔离 Syft SBOM 生成 sidecar。
当前 Windows portable 自测为 `REVIEW`，Docker 是 v2.3 的受控本机候选运行路径。

v2.3.1 将网页下载模板替换为基于 PRO-03B v1.4 SBOM 内容的清理派生版：保留
元数据、依赖、来源证据、目标构建、安全相关性和缺口字段，拆分 PURL/CPE/
Internal ID，并增加许可证、CVE 与 EUVD ID。客户模板保持空白；演示数据单独
生成。该补丁同时修复多工作表选择、双语表头映射、旧模板缓存和 XLSX PRE-7
证据标志，并在输出报告中增加“输入SBOM快照”。

## 适用流程

1. 客户提供 `.xlsx`、`.xlsm`、`.csv`、`.tsv` 或 CycloneDX `.json`。
2. 工具自动识别组件名称、版本、厂商、PURL、CPE、CVE 和 EUVD ID 等列。
3. 用户填写项目、版本、软件 build、客户并确认列映射。
4. 有 CVE/EUVD ID 时优先精确映射；没有漏洞标识符时回退到产品名候选检索。
5. 查询 EU/CISA KEV 公开信号；命中与未命中都进入产品级 CRA Art.14 人工评估。
6. 导入或导出 VEX，记录产品适用性、证据、awareness、双人审批和复核期限。
7. 检查 SRP Q16 分阶段字段，导出 JSON/XLSX/HTML 草稿并登记人工提交回执。
8. 下载带证据快照哈希、适用性状态和 SRP 准备度的 Excel 报告。

## 工作台

- `看板`：项目、组件、EUVD 记录、KEV 已知利用信号、Art.14 待评估和查询错误。
- `项目`：每次客户 SBOM 作为一个项目版本保存，可查看历史扫描。
- `组件`：跨项目查看版本、厂商、PURL/CPE、查询状态和匹配结果。
- `漏洞`：跨项目查看 CVE→EUVD 映射、外部利用情报、产品适用性和 Art.14 状态。
- `Art.14`：管理产品级案件、VEX、证据、awareness、时限、四眼审批及 SRP 草稿。
- `导入`：创建新的项目版本并上传客户 SBOM。

## 启动

### Docker（macOS / Linux / Windows）

Docker Desktop 或 Docker Engine 已启动后：

```text
docker compose up -d
```

打开 `http://localhost:8090`。服务仅绑定本机 `127.0.0.1`。

### Windows 便携模式

双击：

```text
start.cmd
```

工具地址：

```text
http://localhost:8090
```

停止时双击：

```text
stop.cmd
```

当前文件夹虽包含 Windows 独立运行时，但 v2.3 自测发现 5 组旧/新直接依赖并存。
清理并复核前，不应把 v2.3 portable 候选交付客户。

## 客户表格字段

至少需要组件名称、CVE 或 EUVD ID 之一。客户已有漏洞清单时，建议每行提供：

- CVE（一个单元格可包含多个）
- 组件名称
- 版本
- 厂商或供应商
- PURL 或 CPE（有其一即可）

网页右上角可下载 `客户SBOM导入模板_PRO-03B_v1.4兼容版.xlsx`。模板为清理后的
独立文件，不复制参考工作簿的个人/组织元数据；示例值只出现在说明列，不作为
组件数据。客户应填写 `01_Metadata_元数据` 和 `02_SBOM_Software`。

本机 Docker 启动后，可运行确定性闭环 Demo：

```text
/Users/mac/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node \
  scripts/demo_template_roundtrip.mjs \
  http://127.0.0.1:8090 \
  outputs/019fa756-edb7-7a12-98d5-aadf084adba2/template-demo
```

该脚本执行“下载空白模板 → 填入两条 Demo → 上传 → 本地 EUVD/KEV 匹配 →
下载并检查报告”。PASS 只证明此工具链闭环，不证明 SBOM 完整性、CRA Art.14
可报告性、SRP 提交、符合性或发布批准。

## 匹配和利用情报规则

- `EUVD精确匹配`：输入 CVE 通过 ENISA 每日官方映射文件关联到 EUVD，或输入 EUVD ID 查询成功。
- `产品候选匹配`：输入没有 CVE/EUVD ID，按产品名、厂商和版本进行候选检索。
- `KEV已知利用信号`：该 CVE/EUVD 存在于 ENISA 汇总的 EU/CISA KEV 快照。
- `未列入当前KEV快照`：不代表漏洞未被利用，不能作为不报告结论。
- 数据快照状态区分 `fresh`、`stale`、`degraded` 和 `unavailable`；更新失败时仅使用
  last-known-good 并明确降级，不把缓存读取时间冒充数据下载时间。
- `需复核`：产品名匹配，但厂商缺失/差异较大，或 EUVD 的版本文本无法可靠自动解析。
- `CRA Art.14 待评估`：表示需要核验客户产品包含性、配置/可达性、VEX、产品级恶意利用证据和制造商 awareness；不等于已触发强制报告。

工具不会把 EPSS 当成已经利用证据，也不会把扫描时间自动写成制造商 awareness。

## EUVD、Article 14 与 SRP 的边界

- EUVD 是公开漏洞数据库；工具用它做 CVE 映射和公开利用情报核验。
- CRA `Art.3(42)` 与 `Art.14` 的最终触发需要可靠证据表明恶意行为者已实际利用客户产品中的漏洞。
- CRA `Art.16` Single Reporting Platform（SRP）是报告入口，不是公开查询数据库。
- 漏洞报告触发依据为 CRA `Art.14(1)`。制造商人工确认 awareness 后，
  工具按 `Art.14(2)(a)-(c)` 计算 24h、72h 和
  修正/缓解措施可用后 14 日的最迟期限；界面同时保留 “without undue delay” 提示。
- 工具不覆盖 `Art.14(3)-(5)` 的严重安全事件分阶段报告流程。
- SRP 路由边界对应 `Art.14(7)` 与 `Art.16`。
- 当前工具只生成 SRP 草稿并记录人工提交回执，不自动提交 SRP。ENISA 目前明确
  表示暂不提供 SRP API。
- 公开 KEV/EUVD 信号是调查触发器，不是 `Art.3(42)` 的产品级最终证据。

## 准确性与覆盖率

工具不宣称 100% 准确或 100% 完整。当前规则：

- CVE 优先使用 EUVD 每日 `cve-euvd-mapping` 全量快照本地精确关联。
- 利用情报优先使用 EUVD 每日 EU/CISA KEV 全量快照，保留获取时间和 SHA-256。
- 以 EUVD 产品名精确匹配为第一道门槛。
- 按产品拉取候选记录，在本地校验厂商、厂商缩写和受影响版本。
- 只有产品、版本和厂商同时达到阈值时才标记为 `已匹配`。
- 厂商缺失、名称差异或版本表达式无法可靠解析时标记为 `需复核`。
- 每页拉取 100 条，默认最多 100 页；达到上限会明确标记分页截断。

看板和报告会显示：

- 身份覆盖率
- EUVD 查询成功率
- 完整分页覆盖率
- 查询错误和分页截断组件数

因此 `未发现匹配` 只能解释为本次可用数据中未确认匹配，不能解释为无漏洞。

如果客户使用的产品名与 EUVD 名称不同，可编辑：

```text
config\product-aliases.csv
```

在其中维护客户名称、客户厂商与 EUVD 产品名、EUVD 厂商的映射。修改后重新匹配即可。

## 本地数据

所有持久文件都位于本目录：

```text
data\      EUVD 只读镜像、查询缓存、上传记录、任务状态
outputs\   导出的 Excel 报告
```

`data\workbench.sqlite3` 保存案件、证据、审批、VEX、数据源状态与审计事件。
`data\euvd-readonly.sqlite3` 是由独立正式镜像原子生成的 Web 只读消费者快照。
容器另外以只读文件挂载该快照及
`data\euvd-readonly.sqlite3.sha256`；缺失或哈希失配时 health 返回 503，
且默认不把客户组件/供应商查询发送到 EUVD 网络 API。
原 v2.1 扫描任务 JSON 保持可读，并在启动时幂等登记为 SQLite SBOM 快照。EUVD
查询缓存默认保存 24 小时，用于加快重复组件匹配。

## 迁移到其他电脑

双击：

```text
export-portable.cmd
```

生成的 ZIP 位于：

```text
exports\
```

默认不会打包客户上传文件、缓存和报告。需要连同数据一起迁移时运行：

```powershell
.\scripts\export-portable.ps1 -WithData
```

在新电脑解压后直接双击 `start.cmd`。便携包已包含独立 Python 运行时，
不要求安装 Python 或 Docker。

## 配置

可在启动前设置端口：

```powershell
$env:MATCHER_PORT = '8090'
.\start.cmd
```

服务默认只监听 `127.0.0.1`，局域网其他设备不能直接访问。

EUVD 单个产品默认最多拉取 100 页（每页 100 条）。可调整：

```powershell
$env:EUVD_MAX_PAGES = '100'
.\start.cmd
```

## 测试

```powershell
.\runtime\python.exe -m unittest discover -s tests -v
```

当前 v2.3.1 自动化套件共 40 项，覆盖本地 CVE/KEV/详情/产品查询、外部哈希
fail-closed、上传边界和 CycloneDX PRE-7
字段证据保真；自动化结果不等于符合性或发布批准。

## Docker 运维

Docker Desktop 或 Docker Engine 已启动后，在项目目录运行：

```text
docker compose up -d --build
```

工作台地址：

```text
http://localhost:8090
```

查看状态和停止服务：

```text
docker compose ps
docker compose down
```

默认使用项目内的 `data/` 和 `outputs/` 保存数据与报告，停止或重建容器不会
删除这些文件。需要改端口或持久化位置时，可设置 `MATCHER_PORT`、
`MATCHER_DATA_PATH` 和 `MATCHER_OUTPUT_PATH` 环境变量后再启动。服务仅监听
`127.0.0.1`；如果需要局域网或服务器访问，必须先增加认证、TLS 和访问控制，
不要直接把端口绑定改为 `0.0.0.0`。通过反向代理使用自定义主机名时，还需把
该主机名加入逗号分隔的 `ALLOWED_HOSTS`。

本地审批 PIN 只用于区分案件中的审批账户和阻止同一账户完成两道审批；
它不是企业级登录、SSO、电子签名或现实身份核验。若要多人/局域网使用，必须先
增加完整身份认证、权限、TLS、备份策略和组织授权映射。

## 数据源

- EUVD API: https://euvd.enisa.europa.eu/apidoc
- EUVD: https://euvd.enisa.europa.eu/
- ENISA SRP FAQ（含 Q16 字段矩阵）:
  https://www.enisa.europa.eu/topics/product-security-and-certification/single-reporting-platform-srp
- CRA Regulation (EU) 2024/2847:
  https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng

人工操作、v2.3 实施测试和既有回滚方式见
`docs/HUMAN_OPERATION_GUIDE_v2.3.md`、`docs/V2.3_IMPLEMENTATION_AND_TEST_REPORT.md`
及 `docs/V2.2_ROLLBACK.md`。
