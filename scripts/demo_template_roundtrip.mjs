import fs from "node:fs/promises";
import path from "node:path";

const artifactToolModule =
  process.env.ARTIFACT_TOOL_MODULE ||
  "/Users/mac/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs";
const { FileBlob, SpreadsheetFile } = await import(artifactToolModule);

const baseUrl = (process.argv[2] || "http://127.0.0.1:8090").replace(/\/$/, "");
const outputDirectory = path.resolve(
  process.argv[3] || "outputs/019fa756-edb7-7a12-98d5-aadf084adba2/template-demo",
);
await fs.mkdir(outputDirectory, { recursive: true });

function assert(condition, message) {
  if (!condition) {
    throw new Error(`DEMO ASSERTION FAILED: ${message}`);
  }
}

async function jsonResponse(response, label) {
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${label} failed (${response.status}): ${text}`);
  }
  return JSON.parse(text);
}

const templateResponse = await fetch(`${baseUrl}/api/template`);
assert(templateResponse.ok, `template download HTTP ${templateResponse.status}`);
assert(
  (templateResponse.headers.get("content-type") || "").includes(
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ),
  "template MIME type",
);
assert(
  (templateResponse.headers.get("content-disposition") || "").includes("filename"),
  "template Content-Disposition filename",
);
const downloadedBytes = new Uint8Array(await templateResponse.arrayBuffer());
const downloadedPath = path.join(outputDirectory, "01-downloaded-customer-template.xlsx");
await fs.writeFile(downloadedPath, downloadedBytes);

const templateBlob = await FileBlob.load(downloadedPath);
const workbook = await SpreadsheetFile.importXlsx(templateBlob);
const metadataSheet = workbook.worksheets.getItem("01_Metadata_元数据");
const sbomSheet = workbook.worksheets.getItem("02_SBOM_Software");

metadataSheet.getRange("B3:B12").format.numberFormat = "@";
metadataSheet.getRange("B3:B12").values = [
  ["Template Roundtrip Demo"],
  ["2.3.1-demo"],
  ["N/A"],
  ["demo-build-20260804"],
  ["2026-08-04"],
  ["Local verification script"],
  ["local-only@example.test"],
  ["Deterministic EUVD mapping demo"],
  ["1"],
  ["ISO 8601: 2026-08-04T16:00:00+08:00"],
];

const demoRows = [
  [
    "S-001",
    "Third-party component 第三方组件",
    "Apache Software Foundation",
    "log4j-core",
    "2.14.1",
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    "",
    "",
    "Direct runtime dependency of demo application",
    "Demo fixture / dependency manifest",
    "Yes 是",
    "Logging and runtime code execution surface",
    "Demo only; confirm delivered build and reachability",
    "Apache-2.0",
    "CVE-2021-44228",
    "",
    "Deterministic known-exploited mapping test",
  ],
  [
    "S-002",
    "Third-party component 第三方组件",
    "Python Software Foundation",
    "requests",
    "2.31.0",
    "pkg:pypi/requests@2.31.0",
    "",
    "",
    "Direct test dependency",
    "Demo fixture / requirements lock",
    "Yes 是",
    "Outbound HTTP client",
    "Demo only; confirm delivered build and affected behavior",
    "Apache-2.0",
    "CVE-2024-35195",
    "",
    "Deterministic non-KEV comparison test",
  ],
];
sbomSheet.getRange("A2:Q3").values = demoRows;
sbomSheet.getRange("A2:Q3").format = {
  font: { name: "Arial", size: 10, color: "#000000" },
  verticalAlignment: "top",
  wrapText: true,
  borders: { preset: "all", style: "thin", color: "#B7C9D6" },
};
sbomSheet.getRange("A2:Q3").format.rowHeight = 54;

const demoPath = path.join(outputDirectory, "02-filled-demo-sbom.xlsx");
const demoXlsx = await SpreadsheetFile.exportXlsx(workbook);
await demoXlsx.save(demoPath);
await fs.rm(`${demoPath}.inspect.ndjson`, { force: true });

const demoWorkbookCheck = await SpreadsheetFile.importXlsx(await FileBlob.load(demoPath));
const demoRegion = await demoWorkbookCheck.inspect({
  kind: "region",
  sheetId: "02_SBOM_Software",
  range: "A1:Q3",
  maxChars: 12000,
  tableMaxRows: 5,
  tableMaxCols: 17,
  tableMaxCellChars: 180,
});
await fs.writeFile(
  path.join(outputDirectory, "02-filled-demo-sbom.inspect.ndjson"),
  `${demoRegion.ndjson}\n`,
  "utf8",
);
for (const [sheetName, outputName, range] of [
  ["01_Metadata_元数据", "02-filled-demo-metadata.png", "A1:D12"],
  ["02_SBOM_Software", "02-filled-demo-sbom.png", "A1:Q4"],
  ["04_Instructions_说明", "02-filled-demo-instructions.png", "A1:C9"],
]) {
  const previewImage = await demoWorkbookCheck.render({
    sheetName,
    range,
    autoCrop: "all",
    scale: 1,
    format: "png",
  });
  await fs.writeFile(
    path.join(outputDirectory, outputName),
    new Uint8Array(await previewImage.arrayBuffer()),
  );
}

const form = new FormData();
form.append(
  "file",
  new Blob([await fs.readFile(demoPath)], {
    type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  }),
  path.basename(demoPath),
);
const preview = await jsonResponse(
  await fetch(`${baseUrl}/api/uploads/preview`, { method: "POST", body: form }),
  "upload preview",
);
assert(preview.sheet === "02_SBOM_Software", "selected SBOM worksheet");
assert(preview.row_count === 2, `row_count expected 2, got ${preview.row_count}`);
for (const field of ["name", "version", "vendor", "purl", "scope", "license", "cve", "euvd"]) {
  assert(Boolean(preview.mapping[field]), `automatic mapping for ${field}`);
}
assert(
  preview.pre7_evidence_artifact?.contains_item_level_observations === false,
  "XLSX upload must not claim item-level PRE-7 observations",
);
await fs.writeFile(
  path.join(outputDirectory, "03-upload-preview.json"),
  `${JSON.stringify(preview, null, 2)}\n`,
  "utf8",
);

const job = await jsonResponse(
  await fetch(`${baseUrl}/api/jobs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      upload_id: preview.upload_id,
      mapping: preview.mapping,
      project_name: "Template Roundtrip Demo",
      project_version: "2.3.1-demo",
      software_build: "demo-build-20260804",
      customer: "Local deterministic test",
    }),
  }),
  "create job",
);

let completedJob = job;
const deadline = Date.now() + 180_000;
while (!["completed", "failed"].includes(completedJob.status) && Date.now() < deadline) {
  await new Promise((resolve) => setTimeout(resolve, 500));
  completedJob = await jsonResponse(
    await fetch(`${baseUrl}/api/jobs/${job.id}`),
    "poll job",
  );
}
assert(completedJob.status === "completed", `job status ${completedJob.status}`);
const summary = completedJob.result?.summary || {};
assert(summary.component_count === 2, "component_count=2");
assert(summary.confirmed_findings === 2, "confirmed_findings=2");
assert(summary.known_exploited_findings === 1, "known_exploited_findings=1");
assert(summary.error_count === 0, "error_count=0");

const matches = completedJob.result?.matches || [];
const matchByCve = Object.fromEntries(matches.map((item) => [item.source_identifier, item]));
assert(
  matchByCve["CVE-2021-44228"]?.euvd_id === "EUVD-2021-34768",
  "Log4Shell CVE→EUVD exact mapping",
);
assert(
  matchByCve["CVE-2024-35195"]?.euvd_id === "EUVD-2024-1565",
  "requests CVE→EUVD exact mapping",
);
assert(
  matchByCve["CVE-2021-44228"]?.exploitation_status === "KEV已知利用信号",
  "Log4Shell KEV signal",
);
assert(
  String(matchByCve["CVE-2024-35195"]?.exploitation_status || "").includes(
    "不代表未被利用",
  ),
  "not-listed-in-KEV boundary",
);
assert(
  matches.every((item) => item.mapping_status === "EUVD精确匹配"),
  "all findings use exact identifier mapping",
);
assert(
  matches.every((item) => item.art14_readiness !== "reportable"),
  "no automatic CRA Art.14 reportability decision",
);

const reportResponse = await fetch(`${baseUrl}${completedJob.report_url}`);
assert(reportResponse.ok, `report download HTTP ${reportResponse.status}`);
const reportBytes = new Uint8Array(await reportResponse.arrayBuffer());
const reportPath = path.join(outputDirectory, "04-euvd-match-report.xlsx");
await fs.writeFile(reportPath, reportBytes);

const reportWorkbook = await SpreadsheetFile.importXlsx(await FileBlob.load(reportPath));
const summarySheet = reportWorkbook.worksheets.getItem("汇总");
assert(summarySheet.getRange("E4").values[0][0] === 2, "report E4 component count");
assert(summarySheet.getRange("E5").values[0][0] === 2, "report E5 matched count");
assert(summarySheet.getRange("E6").values[0][0] === 1, "report E6 KEV count");
assert(summarySheet.getRange("E11").values[0][0] === 0, "report E11 error count");
assert(
  summarySheet.getRange("B9").values[0][0] === "2026-07-28",
  "report EUVD data cutoff",
);
const inputSheet = reportWorkbook.worksheets.getItem("输入SBOM快照");
const inputValues = inputSheet.getRange("A1:Q3").values;
assert(inputValues[1][3] === "log4j-core", "report preserves first input component");
assert(inputValues[1][14] === "CVE-2021-44228", "report preserves first CVE");
assert(inputValues[2][3] === "requests", "report preserves second input component");
assert(inputValues[2][14] === "CVE-2024-35195", "report preserves second CVE");

for (const sheetName of [
  "汇总",
  "EUVD匹配结果",
  "待人工确认",
  "Art14待评估",
  "组件清单",
  "输入SBOM快照",
  "查询错误",
  "说明",
]) {
  const formulas = await reportWorkbook.inspect({
    kind: "formula",
    sheetId: sheetName,
    range: "A1:AZ2500",
    maxChars: 6000,
    options: { maxResults: 100 },
  });
  assert(!/[#](REF|DIV\/0|VALUE|NAME\?|N\/A)/.test(formulas.ndjson), `${sheetName} formula errors`);
}

for (const [sheetName, outputName] of [
  ["汇总", "04-euvd-match-report-summary.png"],
  ["EUVD匹配结果", "04-euvd-match-report-matches.png"],
  ["待人工确认", "04-euvd-match-report-review.png"],
  ["Art14待评估", "04-euvd-match-report-art14.png"],
  ["组件清单", "04-euvd-match-report-components.png"],
  ["输入SBOM快照", "04-euvd-match-report-input-snapshot.png"],
  ["查询错误", "04-euvd-match-report-errors.png"],
  ["说明", "04-euvd-match-report-notes.png"],
]) {
  const previewImage = await reportWorkbook.render({
    sheetName,
    autoCrop: "all",
    scale: 1,
    format: "png",
  });
  await fs.writeFile(
    path.join(outputDirectory, outputName),
    new Uint8Array(await previewImage.arrayBuffer()),
  );
}

const result = {
  status: "PASS",
  base_url: baseUrl,
  generated_at: new Date().toISOString(),
  template_file: path.basename(downloadedPath),
  demo_file: path.basename(demoPath),
  report_file: path.basename(reportPath),
  upload_id: preview.upload_id,
  job_id: completedJob.id,
  selected_sheet: preview.sheet,
  row_count: preview.row_count,
  mapping: preview.mapping,
  source_sha256: preview.source_sha256,
  pre7_item_level_observations_claimed: false,
  summary,
  expected_matches: {
    "CVE-2021-44228": "EUVD-2021-34768",
    "CVE-2024-35195": "EUVD-2024-1565",
  },
  data_provenance: matches[0]
    ? {
        status: matches[0].euvd_data_status,
        query_source: matches[0].euvd_query_source,
        last_successful_to_date: matches[0].euvd_last_successful_to_date,
        freshness: matches[0].euvd_reference_freshness,
        source_db_sha256: matches[0].euvd_source_db_sha256,
      }
    : {},
  compliance_boundary:
    "PASS proves the local template import/match/report chain only; it is not an SBOM completeness, CRA Art.14 reportability, SRP submission, conformity, or release decision.",
};
await fs.writeFile(
  path.join(outputDirectory, "DEMO_RESULT.json"),
  `${JSON.stringify(result, null, 2)}\n`,
  "utf8",
);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
