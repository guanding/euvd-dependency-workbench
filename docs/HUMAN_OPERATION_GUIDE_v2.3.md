# EUVD Dependency Workbench v2.3 人工操作指南

适用对象：在本机使用 Docker Desktop 的 SBOM 分析人员。本文只描述内部调查和
CRA Article 14 报告准备；不授权自动符合性判定、自动 SRP 提交或产品发布。

## 1. 每次如何打开平台

1. 启动 Docker Desktop，等待 Docker Engine 变为可用。
2. 打开“终端”，逐行运行：

   ```bash
   cd '/Users/mac/Documents/AI-Cybersecurity/CRA/解读文件/SBOM工具/euvd-sbom-matcher'
   docker compose up -d
   docker compose ps
   ```

3. `docker compose ps` 应显示 `matcher` 为 `healthy`。
4. 浏览器打开：<http://localhost:8090>。

若页面打不开：

```bash
docker compose logs --tail=100 matcher
curl http://127.0.0.1:8090/api/health
```

正常 health 响应应包含 `version: 2.3.1`。服务只绑定 `127.0.0.1`；不要为了
“方便访问”直接改成 `0.0.0.0`。

## 2. 先看 EUVD 数据状态

页面左上角有数据源状态。也可运行：

```bash
curl http://127.0.0.1:8090/api/euvd/status
```

状态解释：

| 状态 | 人工解释 |
| --- | --- |
| `local_ready` | 查询使用本地只读镜像，参考数据被记录为 fresh |
| `local_degraded` | 本地镜像可查询，但漏洞截止日期或映射/KEV 不是当天成功刷新 |
| `local_unavailable` | 本地快照损坏、外部 SHA-256 缺失/失配或无法打开；停止评估 |
| `local_required_unavailable` | 本地快照缺失且默认禁止网络回退；结果必须视为 Unknown |
| `online` | 仅当操作者显式设置 `EUVD_NETWORK_FALLBACK=true` 时才可出现；使用客户数据前需单独隐私批准 |
| `unavailable` | 显式网络模式也无法访问；结果必须视为 Unknown |

截至 2026-08-04，本机状态是 `local_degraded`：

- 漏洞记录：370,723；截止 2026-07-28；
- CVE→EUVD 映射：353,633；LKG 文件日期 2026-07-30；
- KEV：1,660；LKG 文件日期 2026-07-28；
- ENISA 从当前公网出口返回 403。

因此，当前“未命中”只能表示在这份本地快照中未命中，不能写成“当前 EUVD
不存在”或“该漏洞没有被积极利用”。

## 3. 导入客户 SBOM 并评估

### 3.1 准备文件

支持 `.xlsx`、`.xlsm`、`.csv`、`.tsv` 和 CycloneDX `.json`。至少提供以下
身份之一：组件名称、CVE 或 EUVD ID。客户已有 CVE 清单时，建议同时提供：

- 组件名称和版本；
- 厂商/供应商；
- PURL 或 CPE；
- CVE；
- 产品版本/build 和 SBOM 的来源/生成日期。

### 3.2 网页操作

1. 点击“导入”。
2. 选择客户 SBOM。
3. 检查预览和自动列映射，尤其是组件名、版本、厂商、PURL/CPE、CVE、EUVD ID。
4. 填写项目名称、产品版本、software build 和客户。
5. 启动匹配，等待状态变为“完成”。
6. 在“组件”查看每个查询是否成功、是否截断、采用的查询方式。
7. 在“漏洞”检查 CVE→EUVD、受影响版本、厂商、KEV 信号和证据时间。
8. 下载 Excel 报告并与原 SBOM、产品 build、VEX 和人工复核记录一起保存。

结果含义：

- `KEV已知利用信号`：公开 KEV 快照命中，是调查触发器；不是客户产品已被实际
  恶意利用的自动证明。
- `未列入当前KEV快照`：不能解释为“未被利用”。
- `已匹配`：机器规则确认了当前记录中的身份/版本候选，不代表最终产品适用性。
- `需复核`：厂商、版本表达式或产品适用性需要人工证据。
- `CRA Art.14 待评估`：需要建立人工案件，不等于已触发报告义务。

### 3.3 Article 14 / SRP 工作流

1. 对相关 finding 建立 Art.14 案件。
2. 追加产品包含性、配置/可达性、VEX、恶意行为者、未经许可和实际利用证据。
3. 由授权人员人工确认 manufacturer awareness；平台随后计算 24h、72h 和最终
   报告最迟期限。
4. 技术评审和合规评审必须使用两个不同本地审批身份。
5. 只有两道评审一致后才形成平台内最终决定候选。
6. 导出 SRP JSON/XLSX/HTML 草稿；由授权人员登录 ENISA SRP 人工提交并回填回执。

平台不会连接或代替 SRP。CRA Art.14 的产品级“actively exploited vulnerability”
判断不能只靠 EUVD/KEV 命中。

### 3.4 输入要求与结论解读（非模板 / 内容不全时如何处理）

平台对"客户没用模板"或"内容不全"的 SBOM 是**宽容到报错、严格不误导**——能给的部分如实给并标置信度，给不了的部分明确报错或标"需复核"，绝不静默产出错误结论。

**输入路径鲁棒性（从高到低）**：

| 输入 | 能否识别 | 说明 |
|---|---|---|
| CycloneDX JSON（`.json`，标准格式） | ✅ 最鲁棒 | 不依赖模板；`purl`/`cpe`/`vulnerabilities` 自动提取，PRE-7 元数据证据保留。**客户能提供 CycloneDX 时优先用它** |
| 模板 xlsx（PRO-03B v1.4 兼容版） | ✅ | 组件匹配 + 元数据页自动绑定产品身份（D1） |
| 任意 xlsx/csv（不用模板但结构化） | ✅ 组件可识别 | 产品身份（名称/版本/构建/客户）需手填；组件匹配不受影响 |
| 随意表格（无组件列） | ❌ 报错 | 平台提示"必须选择组件名称、CVE 或 EUVD ID 列之一"，不会假装扫描完成 |

**内容不全时的行为**：

- 缺组件名但有 CVE/EUVD 列 → 用 CVE/EUVD 精确匹配（高置信）
- 缺组件名也缺 CVE/EUVD → **报错**（不静默）
- 缺版本/厂商 → 产品名候选匹配仍跑，但标 **"需复核"**（不冒充精确）
- 列名不规范（不匹配中英文别名）→ 列映射失败，操作员在前端下拉手动指定列

**结论的语义分层**（报告如实标注，不混淆）：

| 报告状态 | 含义 | 置信 |
|---|---|---|
| EUVD 精确匹配 | CVE/EUVD 直接映射到 EUVD 记录 | 高 |
| 产品候选匹配 | 按产品名/版本模糊匹配 | 低，标"需复核" |
| 未发现 EUVD 记录 | 本次查询无记录 | **不是无漏洞声明** |
| 积极利用（KEV / exploitedSince） | EU/CISA KEV 公开利用信号 | 信号，不自动 reportable |

**硬边界（无论输入多完整都不变）**：

- 平台是证据与工作流工具，**不是自动法律判定器**。
- "积极利用"只是公开信号；产品适用性 + CRA Art.14 可报告性需 awareness 人工确认 + 产品级证据 + 四眼审批。
- 未列入 KEV ≠ 未被利用；未发现 ≠ 无漏洞（EUVD 在线数据会变化，SRP 可能存在不公开报告）。

## 4. 平台自身源代码如何生成 SBOM

v2.3 增加了独立 Syft sidecar。它默认断网、只读挂载输入、不挂载 Docker Socket，
固定为 Syft 1.50.0 和镜像摘要。生成结果是内部候选，不是符合性证书。

### 4.1 扫描源代码

每次使用新的 `identity` 和输出目录；工具会拒绝覆盖旧证据：

```bash
cd '/Users/mac/Documents/AI-Cybersecurity/CRA/解读文件/SBOM工具/euvd-sbom-matcher'
python3 scripts/generate_sbom.py \
  --kind source \
  --input . \
  --output-dir self-test/manual-source-20260804 \
  --identity euvd-workbench-source-manual-20260804 \
  --source-version 2.3.1-candidate
```

输出包括：

- `*.cdx.json`：可导入本平台的 CycloneDX 1.6；
- `*.syft.json`：保留更多生成器原生信息；
- `*.input-manifest.jsonl`：输入文件哈希清单；
- `*.scanner-control.json`：唯一 Compose 文件、渲染服务与实际扫描容器的安全控制证据；
- `*.generation.json`：工具版本、镜像摘要、输出 SHA-256 和边界。

把 `*.cdx.json` 当作普通 SBOM 上传即可完成实例评估。

### 4.2 扫描 Docker 镜像

扫描器没有 Docker Socket。先由受信任操作员导出明确镜像，再扫描 archive：

```bash
mkdir -p self-test/manual-image-20260804
docker save -o self-test/manual-image-20260804/workbench.tar \
  euvd-dependency-workbench:2.3.1
image_id="$(docker image inspect euvd-dependency-workbench:2.3.1 --format '{{.Id}}')"
python3 scripts/generate_sbom.py \
  --kind docker-archive \
  --input self-test/manual-image-20260804/workbench.tar \
  --output-dir self-test/manual-image-20260804/sbom \
  --identity euvd-workbench-image-manual-20260804 \
  --expected-image-id "$image_id" \
  --source-version 2.3.1-candidate
```

源码 SBOM 和镜像 SBOM 不是同一个制品身份。镜像还会发现传递依赖、操作系统包和
实际安装内容。

### 4.3 Windows 便携候选

当前 P3 测试发现 Windows runtime 同时残留 5 组旧/新直接依赖版本。因此便携包
状态是 `REVIEW`，不要把 v2.3 便携候选交付客户。Docker 是当前可用的受控本机候选
运行路径。重新构建干净 Windows runtime 并复核之前，不得把 source/image PASS
推定到 portable。

## 5. 如何更新 EUVD 本地镜像

Web 项目不直接写正式镜像。只在没有进行中任务时操作。

### 5.1 正式镜像增量同步

```bash
cd /Users/mac/EUVD-Local-Mirror
docker compose run --rm euvd-sync incremental \
  --db data/euvd-mirror.sqlite3 \
  --requests-per-minute 20 \
  --output-json logs/incremental-<YYYYMMDD>.json
```

脚本依据 `fromUpdatedDate/toUpdatedDate` 和重叠窗口更新，不按 EUVD ID 的年份分区；
因此 `EUVD-2024-*` 在 2026 年更新仍会被 upsert。HTTP 403/429/5xx 不得推进
`last_successful_to_date`。

网络恢复后再刷新映射和 KEV：

```bash
docker compose run --rm euvd-sync reference-data \
  --db data/euvd-mirror.sqlite3 \
  --output-json logs/reference-data-<YYYYMMDD>.json
```

### 5.2 生成 Web 只读快照

确认正式镜像的同步结果和 `integrity_check=ok` 后：

```bash
cd '/Users/mac/Documents/AI-Cybersecurity/CRA/解读文件/SBOM工具/euvd-sbom-matcher'
python3 scripts/build_local_euvd_snapshot.py \
  --source /Users/mac/EUVD-Local-Mirror/data/euvd-mirror.sqlite3 \
  --output data/euvd-readonly.sqlite3 \
  --output-json outputs/euvd-readonly-snapshot-<YYYYMMDD>.json
docker compose up -d --build --force-recreate matcher
```

构建器只读源库，将源库主文件与 WAL 的变化纳入漂移检查，并以 SQLite
backup 的逻辑哈希绑定一致性快照。它同时生成
`data/euvd-readonly.sqlite3.sha256`；发布失败会回滚原数据库/哈希对。
Web 将数据库与外部哈希文件分别挂载为文件系统只读，并以 SQLite
`immutable=1` + `query_only` 打开；缺失/哈希失配时禁止查询且 health=503。

## 6. 停止、备份与恢复

停止：

```bash
docker compose down
```

停止不会删除 `data/`、`outputs/`。备份前先停止容器，然后复制：

- `data/workbench.sqlite3`；
- `data/jobs/` 和 `data/uploads/`；
- `outputs/`；
- `data/euvd-readonly.sqlite3`；
- `data/euvd-readonly.sqlite3.sha256`；
- `/Users/mac/EUVD-Local-Mirror/data/euvd-mirror.sqlite3`。

恢复时先保留损坏/旧文件，再把已验证备份复制到原位置；不要删除失败运行记录。

## 7. 法规和标准依据边界

- CRA Annex I Part II(1)：识别并记录产品中的漏洞和组件，SBOM 至少覆盖顶层依赖，
  使用常用机器可读格式。
- CRA Art.14(1)：actively exploited vulnerability 的报告触发。
- CRA Art.14(2)(a)-(c)：漏洞的 24h、72h 和最终报告阶段；工具不覆盖
  Art.14(3)-(5) 严重安全事件流程。
- CRA Art.14(7) 与 Art.16：Single Reporting Platform 路由和平台边界。
- prEN 40000-1-3 Clause 5.3.8 `[PRE-7-RQ-03]`、`[PRE-7-RQ-04]`、
  `[PRE-7-RQ-06]`、`[PRE-7-RQ-07]`：覆盖、机读格式、Author/Version/Timestamp、
  逐组件身份和依赖关系。

prEN 40000 仍是 CEN Enquiry draft；它是本工具的评估设计依据，不得描述为已正式
协调标准或自动产生 CRA 符合性推定。
