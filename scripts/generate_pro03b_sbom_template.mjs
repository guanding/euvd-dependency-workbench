import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const artifactToolModule =
  process.env.ARTIFACT_TOOL_MODULE ||
  "/Users/mac/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs";
const { SpreadsheetFile, Workbook } = await import(artifactToolModule);

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.resolve(scriptDirectory, "..");
const outputPath = path.resolve(
  process.argv[2] ||
    path.join(
      projectDirectory,
      "app",
      "assets",
      "客户SBOM导入模板_PRO-03B_v1.4兼容版.xlsx",
    ),
);
const renderDirectory = process.env.TEMPLATE_RENDER_DIR
  ? path.resolve(process.env.TEMPLATE_RENDER_DIR)
  : "";

const workbook = Workbook.create();
const metadataSheet = workbook.worksheets.add("01_Metadata_元数据");
const sbomSheet = workbook.worksheets.add("02_SBOM_Software");
const instructionsSheet = workbook.worksheets.add("04_Instructions_说明");

const border = { preset: "all", style: "thin", color: "#B7C9D6" };
const headerFormat = {
  fill: "#BFBFBF",
  font: { name: "Arial", size: 10, bold: true, color: "#FFFFFF" },
  verticalAlignment: "top",
  wrapText: true,
  borders: border,
};
const bodyFormat = {
  font: { name: "Arial", size: 10, color: "#000000" },
  verticalAlignment: "top",
  wrapText: true,
  borders: border,
};

metadataSheet.showGridLines = false;
metadataSheet.getRange("A1:D12").values = [
  ["Field 字段", "Customer entry 客户填写", "Example 示例", "Notes 说明"],
  [
    "Template source 模板来源",
    "",
    "PRO-03B v1.4 compatible web template",
    "Web import profile derived from the SBOM content of PRO-03B_SBOM_HBOM最低字段客户填写模板_v1.4.xlsx; this web template covers SBOM only.",
  ],
  [
    "Product name 产品名称",
    "",
    "SGW-200",
    "Product name/model to which this SBOM belongs / SBOM 所属产品名称或型号",
  ],
  [
    "Product version 产品版本",
    "",
    "FW 3.2.0",
    "Delivered software/firmware version / 交付的软件或固件版本",
  ],
  [
    "Hardware revision 硬件修订",
    "",
    "HW Rev B",
    "Hardware revision or board/module revision / 硬件或板卡/模块修订",
  ],
  [
    "Build ID 构建号",
    "",
    "build-sgw200-3.2.0+20260804.1",
    "Unique build identifier / 唯一构建标识",
  ],
  [
    "Release date 发布日期",
    "",
    "2026-08-04",
    "Release date of this inventory version / 本清单版本对应发布日期",
  ],
  [
    "SBOM author 编制者",
    "",
    "Product configuration owner",
    "Authoring role or organization; avoid personal data where role-based identification is sufficient / 编制角色或组织",
  ],
  [
    "Contact 联系方式",
    "",
    "security@example.com",
    "Contact for clarification / 用于补充说明的联系方式",
  ],
  [
    "Inventory scope 清单范围",
    "",
    "Release SBOM",
    "Define whether this workbook represents the release, internal, or regulatory-request view / 说明清单视图",
  ],
  [
    "SBOM version SBOM版本",
    "",
    "1",
    "Version of this SBOM document, distinct from product version / SBOM 文档版本，区别于产品版本",
  ],
  [
    "SBOM timestamp SBOM时间戳",
    "",
    "ISO 8601, e.g. 2026-08-04T08:00:00+08:00",
    "ISO 8601 creation timestamp / ISO 8601 编制时间戳",
  ],
];
metadataSheet.getRange("A1:D1").format = headerFormat;
metadataSheet.getRange("A2:D12").format = bodyFormat;
metadataSheet.getRange("A1:D1").format.rowHeight = 28;
metadataSheet.getRange("A2:D12").format.rowHeight = 54;
metadataSheet.getRange("A1:A12").format.columnWidth = 30;
metadataSheet.getRange("B1:B12").format.columnWidth = 34;
metadataSheet.getRange("C1:C12").format.columnWidth = 34;
metadataSheet.getRange("D1:D12").format.columnWidth = 72;
metadataSheet.freezePanes.freezeRows(1);
const metadataTable = metadataSheet.tables.add("A1:D12", true, "SbomMetadataInput");
metadataTable.style = "TableStyleMedium2";

const sbomHeaders = [
  "Row ID 行号",
  "Component category 组件类别",
  "Component producer 组件生产者",
  "Component name 组件名称",
  "Component version 组件版本",
  "PURL Package URL",
  "CPE",
  "Internal ID 内部标识",
  "Dependency relationship 依赖关系",
  "Source / Evidence 来源/证据",
  "Used in product build 是否进入目标构建",
  "Security relevance 安全相关性",
  "Known uncertainty / gap 已知不确定性/缺口",
  "License 许可证",
  "CVE 漏洞编号",
  "EUVD ID EUVD编号",
  "Customer notes 客户备注",
];
sbomSheet.showGridLines = false;
sbomSheet.getRange("A1:Q2").values = [sbomHeaders, Array(sbomHeaders.length).fill("")];
sbomSheet.getRange("A1:Q1").format = headerFormat;
sbomSheet.getRange("A2:Q2").format = {
  ...bodyFormat,
  fill: "#D9E5F3",
};
sbomSheet.getRange("A1:Q1").format.rowHeight = 42;
sbomSheet.getRange("A2:Q20").format.rowHeight = 34;
const sbomWidths = [
  12, 24, 24, 24, 18, 40, 38, 24, 32, 30, 22, 24, 34, 18, 24, 24, 30,
];
for (let index = 0; index < sbomWidths.length; index += 1) {
  sbomSheet.getRangeByIndexes(0, index, 20, 1).format.columnWidth = sbomWidths[index];
}
sbomSheet.getRange("F2:H200").format.numberFormat = "@";
sbomSheet.getRange("O2:P200").format.numberFormat = "@";
sbomSheet.getRange("B2:B200").dataValidation = {
  rule: {
    type: "list",
    values: [
      "System kernel 系统内核",
      "RTOS / BSP 系统软件",
      "Third-party component 第三方组件",
      "Self-developed code 自研代码",
      "Supplier package 供应商封装组件",
    ],
  },
};
sbomSheet.getRange("K2:K200").dataValidation = {
  rule: { type: "list", values: ["Yes 是", "No 否", "Unknown 待确认"] },
};
sbomSheet.freezePanes.freezeRows(1);
const sbomTable = sbomSheet.tables.add("A1:Q2", true, "SbomSoftwareInput");
sbomTable.style = "TableStyleMedium2";

instructionsSheet.showGridLines = false;
instructionsSheet.getRange("A1:C9").values = [
  ["Topic 主题", "Guidance 指引", "Why it matters 重要性"],
  [
    "Start here 开始填写",
    "Complete 01_Metadata_元数据 and add one row per software component in 02_SBOM_Software. The customer download is intentionally blank; use the separate Demo only for platform verification.\n填写元数据，并在 SBOM 页每个组件填写一行。客户模板有意保持空白；平台验证请使用独立 Demo。",
    "Prevents demonstration data from being mistaken for delivered-product evidence.\n避免把演示数据误当成交付产品证据。",
  ],
  [
    "Do not guess versions 不要猜测版本",
    "If a version is unknown, write UNKNOWN and document the gap, owner, and next action.\n如果版本未知，请填写 UNKNOWN，并说明缺口、责任人和下一步。",
    "Guessed versions can create incorrect vulnerability matching and audit evidence.\n猜测版本会导致错误的漏洞匹配和审核证据。",
  ],
  [
    "Use product/build binding 使用产品/构建绑定",
    "Bind every SBOM to the product version, hardware revision, software build, and release package in the Metadata sheet.\n在元数据页将 SBOM 与产品版本、硬件修订、软件构建和发布包绑定。",
    "Binding shows what was actually delivered.\n绑定关系证明实际交付对象。",
  ],
  [
    "Use stable identifiers 使用稳定标识",
    "Fill PURL and/or CPE where available; use Internal ID for self-developed modules. Do not combine them in one cell.\n可用时填写 PURL 和/或 CPE；自研模块使用 Internal ID。不要混填在一个单元格。",
    "Separate identifiers support deterministic mapping and reduce false matches.\n分列标识便于确定性映射并降低误匹配。",
  ],
  [
    "CVE and EUVD CVE与EUVD",
    "Enter one or more CVE/EUVD identifiers when already known. The platform prioritizes exact CVE→EUVD mapping.\n已知时填写一个或多个 CVE/EUVD 标识；平台优先进行 CVE→EUVD 精确映射。",
    "An EUVD/KEV hit is a candidate signal only; it does not by itself prove product applicability or CRA Art.14 reportability.\nEUVD/KEV 命中只是候选信号，不单独证明产品适用性或 CRA 第14条可报告性。",
  ],
  [
    "Dependency relationship 依赖关系",
    "Describe direct/indirect dependency and the parent component or build relationship.\n说明直接/间接依赖及父组件或构建关系。",
    "Dependency context supports impact analysis and traceability.\n依赖上下文支持影响分析与可追溯性。",
  ],
  [
    "New build or release 新构建或发布",
    "Create a new SBOM version when software dependencies change for a new build or release.\n新构建或发布的软件依赖发生变化时，建立新的 SBOM 版本。",
    "Avoids silently reusing evidence from a different delivered configuration.\n避免静默复用其他交付配置的证据。",
  ],
  [
    "Assessment boundary 评估边界",
    "This template and automated output support evidence collection and vulnerability triage. Human review remains necessary for completeness, applicability, exploitation evidence, CRA/SRP decisions, conformity, and release.\n模板和自动输出用于证据收集与漏洞分诊；完整性、适用性、利用证据、CRA/SRP 决策、符合性及发布仍需人工复核。",
    "A successful import or match is not an automatic conformity or reporting decision.\n成功导入或匹配不等于自动符合性或上报决定。",
  ],
];
instructionsSheet.getRange("A1:C1").format = headerFormat;
instructionsSheet.getRange("A2:C9").format = bodyFormat;
instructionsSheet.getRange("A1:C1").format.rowHeight = 28;
instructionsSheet.getRange("A2:C9").format.rowHeight = 72;
instructionsSheet.getRange("A1:A9").format.columnWidth = 34;
instructionsSheet.getRange("B1:B9").format.columnWidth = 88;
instructionsSheet.getRange("C1:C9").format.columnWidth = 72;
instructionsSheet.freezePanes.freezeRows(1);
const instructionsTable = instructionsSheet.tables.add(
  "A1:C9",
  true,
  "SbomInstructions",
);
instructionsTable.style = "TableStyleMedium2";

const inspection = await workbook.inspect({
  kind: "workbook,sheet",
  maxChars: 6000,
});
process.stdout.write(`${inspection.ndjson}\n`);

for (const sheetName of [
  "01_Metadata_元数据",
  "02_SBOM_Software",
  "04_Instructions_说明",
]) {
  const formulas = await workbook.inspect({
    kind: "formula",
    sheetId: sheetName,
    range: "A1:Q250",
    maxChars: 5000,
    options: { maxResults: 100 },
  });
  if (/"formula"\s*:\s*"/.test(formulas.ndjson)) {
    throw new Error(`Unexpected formula found in ${sheetName}: ${formulas.ndjson}`);
  }
  if (renderDirectory) {
    await fs.mkdir(renderDirectory, { recursive: true });
    const preview = await workbook.render({
      sheetName,
      range: sheetName === "02_SBOM_Software" ? "A1:Q8" : undefined,
      autoCrop: "all",
      scale: 1,
      format: "png",
    });
    await fs.writeFile(
      path.join(renderDirectory, `${sheetName}.png`),
      new Uint8Array(await preview.arrayBuffer()),
    );
  }
}

await fs.mkdir(path.dirname(outputPath), { recursive: true });
const xlsx = await SpreadsheetFile.exportXlsx(workbook);
await xlsx.save(outputPath);
await fs.rm(`${outputPath}.inspect.ndjson`, { force: true });
process.stdout.write(`WROTE ${outputPath}\n`);
