# EUVD Dependency Workbench

当前公开候选版本：`2.4.0-rc.1`。版本号唯一来源为 `app/version.py` 的
`APP_VERSION`；Docker 镜像 tag 与 `/api/health` 必须一致，可用
`python scripts/check_version_consistency.py --no-health` 校验。

## 发布状态

本仓库是 Apache-2.0 的**公开源码预览（unreleased RC）**：
<https://github.com/guanding/euvd-dependency-workbench>。当前不提供 GitHub
Release、官方容器镜像或 Windows portable 下载，也不承诺支持 SLA。依赖名称、
版本、哈希与镜像 digest 是构建声明，不表示仓库捆绑或再授权相应第三方制品。
源码公开不构成客户交付、CRA 符合性、认证或法律意见。

这是一个本地、轻量、可迁移的客户 SBOM 漏洞管理工作台。信息架构参考
Dependency-Track 的项目化工作方式，但只查询 ENISA European Vulnerability
Database (EUVD) 的 CVE 映射、漏洞详情和 EU/CISA KEV 公开数据，不会下载
或展示 NVD、OSV、GitHub Advisory、OSS Index 或商业漏洞库的信息。

该 RC 包含 SQLite 案件库、本地只读 EUVD 消费者快照、CycloneDX/CSAF VEX、
CRA Art.14 人工评估准备、四眼审批、SRP 草稿和证据导出。VEX intake 是实验性
能力：只接受原始 VEX、Workbench intake receipt 与已准入 issuer ID 的绑定组合；
默认 issuer 注册表为空载并 fail-closed。工具不会自动作出法律、符合性、发布或
SRP 提交决定。

## 开源许可证

由 Ding Guan 享有版权的项目源代码、文档、配置数据、合成示例和测试夹具以
[Apache License 2.0](LICENSE) 提供，版权声明见 [NOTICE](NOTICE)。这些项目自有
内容已由 Ding Guan 声明确认为独立创作且不含客户或第三方材料。该授权不自动
覆盖第三方依赖、容器镜像、规范、事实、名称、商标或其他单独治理的输入；这些
项目的当前状态和发布边界见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 适用流程

1. 客户提供 `.xlsx`、`.xlsm`、`.csv`、`.tsv` 或 CycloneDX `.json`。
2. 工具自动识别组件名称、版本、厂商、PURL、CPE、CVE 和 EUVD ID 等列。
3. 用户填写项目、版本、软件 build、客户并确认列映射。
4. 有 CVE/EUVD ID 时优先精确映射；没有漏洞标识符时回退到产品名候选检索。
5. 查询 EU/CISA KEV 公开信号；命中与未命中都进入产品级 CRA Art.14 人工评估。
6. 经 receipt/issuer 信任门导入 VEX，或导出草稿；记录产品适用性、证据、awareness、双人审批和复核期限。
7. 检查 SRP Q16 分阶段字段，一键生成含 JSON/XLSX/HTML、门户核对表、证据索引、
   manifest 与 SHA-256 的完整辅助上报包；人工确认后打开 ENISA 官方页面提交并登记回执。
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

```bash
python3 scripts/bootstrap_demo_snapshot.py --output-dir data
mkdir -p outputs
docker compose up -d --build
```

这条 clean-clone 路径只创建一条显式标记的合成记录，用于启动和本地冒烟测试；
它不是 ENISA 数据、当前漏洞情报或客户证据。生产使用前，必须以受控 Mirror
生成的消费者快照及 SHA-256 sidecar 替换 demo。打开
`http://localhost:8090`；服务仅绑定本机 `127.0.0.1`。

容器镜像内部也带有同一份合成 smoke fixture，使不挂载卷的镜像健康检查能够
运行；Compose 会以 `data/` 中显式生成或 provision 的文件覆盖它。两者都以
`SYNTHETIC_DEMO_NOT_EUVD` 和 degraded 状态显示，不能静默冒充生产 Mirror。

### Windows 便携模式

首次运行先安装运行时并生成合成 demo 快照：

```powershell
.\scripts\setup-runtime.ps1
.\runtime\python.exe .\scripts\bootstrap_demo_snapshot.py --output-dir data
.\start.cmd
```

工具地址：

```text
http://localhost:8090
```

停止时双击：

```text
stop.cmd
```

仓库目前不提供 portable ZIP。未来候选不得包含 Python runtime、客户数据或
EUVD 数据库；运行时由 `setup-runtime.ps1` 在接收机器上单独安装。Windows
portable 在完成实机验证和独立制品放行前不得分发或表述为客户交付放行。

## 客户表格字段

至少需要组件名称、CVE 或 EUVD ID 之一。客户已有漏洞清单时，建议每行提供：

- CVE（一个单元格可包含多个）
- 组件名称
- 版本
- 厂商或供应商
- PURL 或 CPE（有其一即可）

网页右上角可下载空白 SBOM 模板。公开源码候选不包含权利待确认的二进制模板，
而是由 `app/template_builder.py` 生成权利中性的空白模板；示例值只出现在说明列，
不作为组件数据。客户应填写 `01_Metadata_元数据` 和 `02_SBOM_Software`。

使用合成 demo 快照启动后，可运行闭环冒烟测试：

```bash
python3 scripts/demo_template_roundtrip.py \
  --base-url http://127.0.0.1:8090 \
  --output-dir outputs/template-demo
```

该脚本执行“下载空白模板 → 填入一条合成记录 → 上传 → 本地匹配 → 下载报告”。
PASS 只证明本地软件链路，不证明数据时效性、SBOM 完整性、CRA Art.14
可报告性、SRP 提交、符合性、客户交付或发布批准。

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
- 严重安全事件依据 `Art.14(3)-(5)` 建立独立案件类型：人工确认两项严重性准则、
  24h/72h 阶段字段（包括检测时间、发生时间、初步评估与应对措施），
  并以实际 72h notification 回执时间为锚计算一个日历月后的
  final report 最迟期限；`Art.14(6)` 中间报告仍按主管 CSIRT 的具体请求人工处理。
- SRP 路由边界对应 `Art.14(7)` 与 `Art.16`。
- SRP 辅助上报绑定 `enisa-cra-srp-q16-2026-08-03` 字段配置；每个阶段可生成
  ZIP 包，内含 JSON、XLSX、HTML、Q16 门户逐项核对表、人工提交说明、证据元数据索引、
  package manifest 与 SHA-256。
- ENISA FAQ Q15 明确现阶段不提供 API。因此操作链固定为“生成材料 → 授权人员逐项确认
  → 打开官方 SRP → 在门户点击 Submit → 保存官方通知 ID/状态/邮件或告警 → 回填手工回执”。
  工具不保存 EU Login 凭据、不做浏览器填表自动化，也不实现或声称自动 SRP 提交。
- 截至字段配置核对日，ENISA 尚未公布正式门户 URL；前端会打开官方 SRP 信息页。正式
  URL 发布后，仅可在核验域名、流程与字段配置后更新 `config/srp-q16-2026-08-03.json`。
- Workbench handoff 1.1 receipt 只启用周期重扫候选模式；即使规则原本命中，
  Web 也强制改为“需复核”，不自动确认漏洞、版本适用性或 Art.14 结论。
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
`data\euvd-readonly.sqlite3` 应由独立受控 Mirror 原子生成；Mirror 本身不属于
本仓库的同步实现。接口与 demo 边界见 `mirror/README.md`。
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

导出器采用代码/配置 allowlist；`.git`、`data`、`backups`、`self-test`、
`runtime`、`outputs`、`.serena` 及其他运行状态绝不会进入 ZIP。`-WithData`
已被永久禁用并在写入任何 staging 文件前失败。数据迁移必须使用组织批准的
独立备份流程，不得借用源码发布包。

权利待确认的 `app/assets/` 二进制文件同样不进入 portable；模板下载由公开源码
中的 `app/template_builder.py` 生成空白替代件。

在新电脑解压后，先运行 `scripts\setup-runtime.ps1`，再按“Windows 便携模式”
显式 provision 合成 demo 或获批的生产快照；不要把 demo 快照用于客户判断。

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

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

套件覆盖本地 CVE/KEV/详情/产品查询、外部哈希 fail-closed、上传边界、
CycloneDX PRE-7、portable allowlist、合成 bootstrap、VEX UI/API 契约和 XLSX
公式注入。测试数量会随版本变化，不以固定数字作为放行证据；通过测试也不等于
符合性、客户交付或发布批准。

`requirements.txt` 是直接依赖输入；`requirements.lock` 固定 Python 3.13/3.14
的跨平台传递依赖并记录分发包 SHA-256。Docker、CI 和 Windows runtime
都使用 `--require-hashes` 安装。开发工具传递锁、离线 wheelhouse、底层镜像
可复现性和第三方权利审核仍是独立发布门。

## Docker 运维

Docker Desktop 或 Docker Engine 已启动后，在项目目录运行：

```bash
python3 scripts/bootstrap_demo_snapshot.py --output-dir data
mkdir -p outputs
docker compose up -d --build
```

这条首次启动路径使用明确标记的合成快照；它只用于 clean-clone 冒烟测试，
不是实时 EUVD、客户证据或生产数据。生产运行必须按
[`mirror/README.md`](mirror/README.md) 提供经批准的 Mirror 派生快照，并保留匹配的
外部 SHA-256 sidecar。

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
  https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions
- ENISA SRP AR 操作指引:
  https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-guidance-ar-notification-submission-and-update
- CRA Regulation (EU) 2024/2847:
  https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng

本 README 记录公开候选的当前操作边界。工作区内历史 v2.2/v2.3 报告仅说明
当时快照，不能作为本 RC 的测试、发布或客户交付证据；公共候选不会携带这些
含本机运行记录的历史文档。
