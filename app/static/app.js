const state = {
  currentView: "dashboardView",
  dashboard: null,
  projects: [],
  components: [],
  vulnerabilities: [],
  upload: null,
  mapping: {},
  job: null,
  detailTab: "vulnerabilities",
  projectSearch: "",
  componentSearch: "",
  vulnerabilitySearch: "",
  vulnerabilityFilter: "all",
  art14Cases: [],
  reviewers: [],
  snapshots: [],
  euvdCatalog: { records: [], total: 0, page: 1, page_size: 50, sort: "euvd_id_desc", q: "", actively_exploited_only: false, loaded: false },
  currentCase: null,
  projectDetailSearch: "",
  pollTimer: null,
};

const fields = [
  ["name", "组件名称", false],
  ["version", "版本", false],
  ["vendor", "厂商", false],
  ["purl", "PURL", false],
  ["cpe", "CPE", false],
  ["scope", "类型/范围", false],
  ["license", "许可证", false],
  ["cve", "CVE（优先精确映射）", false],
  ["euvd", "EUVD ID", false],
];

const commonSrpFields = [
  ["reporter", "Reporter / 提交代表", "text"],
  ["manufacturer_name", "制造商名称 *", "text"],
  ["manufacturer_contact", "制造商联系方式（本地辅助，非 Q16 门户字段）", "text"],
  ["title", "通知标题 *", "text"],
  ["product_type", "产品类型（Default / Important / Critical）", "text"],
  ["product_category", "产品类别（Important/Critical 时填写）", "text"],
  ["member_states_where_available", "产品可用成员国（如信息可用必填）", "textarea"],
  ["csirt_coordinator", "CSIRT 协调员（本地辅助）", "text"],
  ["user_notification", "用户通知记录（本地辅助）", "textarea"],
  ["sensitivity", "信息敏感性", "textarea"],
];

const vulnerabilitySrpFields = [
  ["general_information", "漏洞一般信息（72h）", "textarea"],
  ["vulnerability_nature", "漏洞一般性质（72h）", "textarea"],
  ["exploit_nature", "利用一般性质（72h）", "textarea"],
  ["corrective_measures_taken", "已采取修正/缓解措施（72h）", "textarea"],
  ["user_measures", "用户可采取措施（72h）", "textarea"],
  ["full_vulnerability_description", "完整漏洞说明（Final）", "textarea"],
  ["vulnerability_severity", "漏洞严重性（Final）", "text"],
  ["vulnerability_impact", "漏洞影响（Final）", "textarea"],
  ["malicious_actor", "恶意行为者（如已知）", "textarea"],
  ["security_update_details", "安全更新/修正措施详情（Final）", "textarea"],
  ["remediation_monitoring", "修复后监测（本地辅助，非 Q16 门户字段）", "textarea"],
];

const incidentSrpFields = [
  ["incident_suspected_unlawful_or_malicious", "疑似非法/恶意原因（yes / no / unknown，24h）", "text"],
  ["incident_general_nature", "事件一般性质（72h）", "textarea"],
  ["incident_detected_at", "事件检测日期时间（72h，含时区）", "text"],
  ["incident_occurred_at", "事件发生日期时间（72h，含时区）", "text"],
  ["incident_initial_assessment", "事件初步评估（72h）", "textarea"],
  ["incident_corrective_measures_taken", "已采取修正/缓解措施（72h）", "textarea"],
  ["incident_user_measures", "用户可采取措施（72h）", "textarea"],
  ["incident_detailed_description", "事件详细说明（Final）", "textarea"],
  ["incident_severity", "事件严重性（Final）", "text"],
  ["incident_impact", "事件影响（Final）", "textarea"],
  ["incident_likely_threat_or_root_cause", "可能威胁/根因（Final）", "textarea"],
  ["incident_applied_and_ongoing_mitigation_measures", "已应用及进行中的缓解措施（Final）", "textarea"],
];

const elements = {
  views: [...document.querySelectorAll(".app-view")],
  navItems: [...document.querySelectorAll(".nav-item")],
  sourceDot: document.getElementById("sourceDot"),
  sourceText: document.getElementById("sourceText"),
  sourceMeta: document.getElementById("sourceMeta"),
  alertBadges: document.getElementById("alertBadges"),
  projectNavCount: document.getElementById("projectNavCount"),
  dashboardTimestamp: document.getElementById("dashboardTimestamp"),
  dashboardMetrics: document.getElementById("dashboardMetrics"),
  severityChart: document.getElementById("severityChart"),
  qualityChart: document.getElementById("qualityChart"),
  recentProjectsBody: document.getElementById("recentProjectsBody"),
  projectSearch: document.getElementById("projectSearch"),
  projectListMeta: document.getElementById("projectListMeta"),
  projectsBody: document.getElementById("projectsBody"),
  componentSearch: document.getElementById("componentSearch"),
  componentListMeta: document.getElementById("componentListMeta"),
  componentsBody: document.getElementById("componentsBody"),
  vulnerabilitySearch: document.getElementById("vulnerabilitySearch"),
  vulnerabilityListMeta: document.getElementById("vulnerabilityListMeta"),
  vulnerabilitiesBody: document.getElementById("vulnerabilitiesBody"),
  art14NavCount: document.getElementById("art14NavCount"),
  feedSnapshotStatus: document.getElementById("feedSnapshotStatus"),
  refreshFeedsButton: document.getElementById("refreshFeedsButton"),
  euvdCatalogSearch: document.getElementById("euvdCatalogSearch"),
  euvdCatalogSort: document.getElementById("euvdCatalogSort"),
  euvdCatalogMeta: document.getElementById("euvdCatalogMeta"),
  euvdCatalogBody: document.getElementById("euvdCatalogBody"),
  euvdCatalogPrev: document.getElementById("euvdCatalogPrev"),
  euvdCatalogNext: document.getElementById("euvdCatalogNext"),
  euvdCatalogPageInfo: document.getElementById("euvdCatalogPageInfo"),
  euvdCatalogFreshness: document.getElementById("euvdCatalogFreshness"),
  euvdCatalogActivelyExploited: document.getElementById("euvdCatalogActivelyExploited"),
  art14ListMeta: document.getElementById("art14ListMeta"),
  art14CasesBody: document.getElementById("art14CasesBody"),
  art14CaseDetail: document.getElementById("art14CaseDetail"),
  caseDetailTitle: document.getElementById("caseDetailTitle"),
  caseDetailSubtitle: document.getElementById("caseDetailSubtitle"),
  caseDeadlineStrip: document.getElementById("caseDeadlineStrip"),
  manualCaseType: document.getElementById("manualCaseType"),
  manualProductName: document.getElementById("manualProductName"),
  manualProductVersion: document.getElementById("manualProductVersion"),
  manualComponentName: document.getElementById("manualComponentName"),
  manualCveId: document.getElementById("manualCveId"),
  manualEuvdId: document.getElementById("manualEuvdId"),
  manualSummary: document.getElementById("manualSummary"),
  createManualCaseButton: document.getElementById("createManualCaseButton"),
  vexFileInput: document.getElementById("vexFileInput"),
  vexReceiptInput: document.getElementById("vexReceiptInput"),
  vexIssuerId: document.getElementById("vexIssuerId"),
  vexActor: document.getElementById("vexActor"),
  importVexButton: document.getElementById("importVexButton"),
  vexImportResult: document.getElementById("vexImportResult"),
  reviewerName: document.getElementById("reviewerName"),
  reviewerRole: document.getElementById("reviewerRole"),
  reviewerPin: document.getElementById("reviewerPin"),
  createReviewerButton: document.getElementById("createReviewerButton"),
  reviewerList: document.getElementById("reviewerList"),
  closeCaseDetailButton: document.getElementById("closeCaseDetailButton"),
  caseApplicability: document.getElementById("caseApplicability"),
  caseApplicabilityReason: document.getElementById("caseApplicabilityReason"),
  caseEvidenceStatus: document.getElementById("caseEvidenceStatus"),
  caseEvidenceSummary: document.getElementById("caseEvidenceSummary"),
  severeIncidentCriteria: document.getElementById("severeIncidentCriteria"),
  incidentDataFunctionImpact: document.getElementById("incidentDataFunctionImpact"),
  incidentMaliciousCode: document.getElementById("incidentMaliciousCode"),
  incidentCriteriaRationale: document.getElementById("incidentCriteriaRationale"),
  caseRiskSummary: document.getElementById("caseRiskSummary"),
  caseMitigation: document.getElementById("caseMitigation"),
  caseInitialAssessment: document.getElementById("caseInitialAssessment"),
  caseCorrectiveAt: document.getElementById("caseCorrectiveAt"),
  caseNextReview: document.getElementById("caseNextReview"),
  caseUpdateActor: document.getElementById("caseUpdateActor"),
  saveCaseAnalysisButton: document.getElementById("saveCaseAnalysisButton"),
  evidenceSourceType: document.getElementById("evidenceSourceType"),
  evidenceSourceRef: document.getElementById("evidenceSourceRef"),
  evidenceSourceUrl: document.getElementById("evidenceSourceUrl"),
  evidenceSha256: document.getElementById("evidenceSha256"),
  evidenceDescription: document.getElementById("evidenceDescription"),
  evidenceProductRelevance: document.getElementById("evidenceProductRelevance"),
  evidenceReliable: document.getElementById("evidenceReliable"),
  evidenceMaliciousActor: document.getElementById("evidenceMaliciousActor"),
  evidenceWithoutPermission: document.getElementById("evidenceWithoutPermission"),
  evidenceActualExploit: document.getElementById("evidenceActualExploit"),
  evidenceActor: document.getElementById("evidenceActor"),
  addEvidenceButton: document.getElementById("addEvidenceButton"),
  caseEvidenceList: document.getElementById("caseEvidenceList"),
  awarenessReviewer: document.getElementById("awarenessReviewer"),
  awarenessPin: document.getElementById("awarenessPin"),
  awarenessAt: document.getElementById("awarenessAt"),
  awarenessBasis: document.getElementById("awarenessBasis"),
  awarenessEvidence: document.getElementById("awarenessEvidence"),
  awarenessConfirmation: document.getElementById("awarenessConfirmation"),
  confirmAwarenessButton: document.getElementById("confirmAwarenessButton"),
  reviewStage: document.getElementById("reviewStage"),
  reviewIdentity: document.getElementById("reviewIdentity"),
  reviewPin: document.getElementById("reviewPin"),
  reviewDecision: document.getElementById("reviewDecision"),
  reviewRationale: document.getElementById("reviewRationale"),
  recordReviewButton: document.getElementById("recordReviewButton"),
  caseApprovals: document.getElementById("caseApprovals"),
  srpFieldsGrid: document.getElementById("srpFieldsGrid"),
  saveSrpFieldsButton: document.getElementById("saveSrpFieldsButton"),
  srpReadinessPanel: document.getElementById("srpReadinessPanel"),
  caseExports: document.getElementById("caseExports"),
  srpPackageStage: document.getElementById("srpPackageStage"),
  downloadSrpPackageButton: document.getElementById("downloadSrpPackageButton"),
  srpHumanConfirmation: document.getElementById("srpHumanConfirmation"),
  openSrpPortalButton: document.getElementById("openSrpPortalButton"),
  srpPortalStatus: document.getElementById("srpPortalStatus"),
  submissionStage: document.getElementById("submissionStage"),
  submissionReviewer: document.getElementById("submissionReviewer"),
  submissionPin: document.getElementById("submissionPin"),
  submissionAt: document.getElementById("submissionAt"),
  submissionReceipt: document.getElementById("submissionReceipt"),
  recordSubmissionButton: document.getElementById("recordSubmissionButton"),
  submissionList: document.getElementById("submissionList"),
  projectName: document.getElementById("projectName"),
  projectVersion: document.getElementById("projectVersion"),
  softwareBuild: document.getElementById("softwareBuild"),
  customerName: document.getElementById("customerName"),
  fileInput: document.getElementById("fileInput"),
  dropZone: document.getElementById("dropZone"),
  receiptInput: document.getElementById("receiptInput"),
  receiptZone: document.getElementById("receiptZone"),
  uploadState: document.getElementById("uploadState"),
  uploadStateText: document.getElementById("uploadStateText"),
  mappingArea: document.getElementById("mappingArea"),
  mappingGrid: document.getElementById("mappingGrid"),
  previewTable: document.getElementById("previewTable"),
  fileMeta: document.getElementById("fileMeta"),
  previewMeta: document.getElementById("previewMeta"),
  replaceFileButton: document.getElementById("replaceFileButton"),
  startMatchButton: document.getElementById("startMatchButton"),
  backToProjectsButton: document.getElementById("backToProjectsButton"),
  rescanButton: document.getElementById("rescanButton"),
  projectTitle: document.getElementById("projectTitle"),
  projectSubtitle: document.getElementById("projectSubtitle"),
  downloadReportButton: document.getElementById("downloadReportButton"),
  downloadEvidenceButton: document.getElementById("downloadEvidenceButton"),
  progressPanel: document.getElementById("progressPanel"),
  progressStage: document.getElementById("progressStage"),
  progressPercent: document.getElementById("progressPercent"),
  progressBar: document.getElementById("progressBar"),
  progressDetail: document.getElementById("progressDetail"),
  progressAction: document.getElementById("progressAction"),
  sbomSourceDeclarations: document.getElementById("sbomSourceDeclarations"),
  declarationChips: document.getElementById("declarationChips"),
  projectMetrics: document.getElementById("projectMetrics"),
  projectQualityPanel: document.getElementById("projectQualityPanel"),
  projectQuality: document.getElementById("projectQuality"),
  projectDetailSearch: document.getElementById("projectDetailSearch"),
  projectDetailMeta: document.getElementById("projectDetailMeta"),
  projectDetailTable: document.getElementById("projectDetailTable"),
  toast: document.getElementById("toast"),
};

function initIcons() {
  if (window.lucide) {
    window.lucide.createIcons({ attrs: { "stroke-width": 1.8 } });
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

function formatDate(value) {
  if (!value) return "未完成";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function showToast(message, type = "normal") {
  elements.toast.textContent = message;
  elements.toast.classList.remove("hidden", "error");
  if (type === "error") elements.toast.classList.add("error");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => elements.toast.classList.add("hidden"), 5200);
}

async function api(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const payload = await response.json();
      detail = payload.detail || detail;
    } catch {
      // Keep the HTTP status when the response is not JSON.
    }
    throw new Error(detail);
  }
  return response.json();
}

function showView(viewId) {
  state.currentView = viewId;
  elements.views.forEach((view) => view.classList.toggle("hidden", view.id !== viewId));
  elements.navItems.forEach((item) => {
    const activeView = viewId === "projectView" ? "projectsView" : viewId;
    item.classList.toggle("active", item.dataset.view === activeView);
  });
  if (viewId === "dashboardView") loadDashboard();
  if (viewId === "projectsView") loadProjects();
  if (viewId === "componentsView") loadComponents();
  if (viewId === "vulnerabilitiesView") loadVulnerabilities();
  if (viewId === "euvdCatalogView") loadEuvdCatalog();
  if (viewId === "art14View") loadArt14Workspace();
  window.scrollTo({ top: 0, behavior: "instant" });
}

async function checkEuvd() {
  try {
    const result = await api("/api/euvd/status");
    const available = ["online", "local_ready", "local_degraded"].includes(result.status);
    elements.sourceDot.className = `status-dot ${available ? "online" : "offline"}`;
    elements.sourceText.textContent =
      result.status === "local_degraded"
        ? "EUVD 本地镜像（数据降级）"
        : result.status === "local_ready"
          ? "EUVD 本地镜像"
          : result.status === "online"
            ? "EUVD 在线"
            : "EUVD 暂不可用";
    renderEuvdMeta(result);
  } catch {
    elements.sourceDot.className = "status-dot offline";
    elements.sourceText.textContent = "EUVD 暂不可用";
    renderEuvdMeta(null);
  }
}

// 把 /api/euvd/status 的数据日期/计数/新鲜度渲染到头部 source-meta 徽章。
// 区分"上游截止日"(last_successful_to_date) 与本地构建日(snapshot_created_at)：
// 前者是 ENISA 数据高水位，后者是消费者快照构建时间，两者之差即同步滞后。
function renderEuvdMeta(status) {
  const meta = elements.sourceMeta;
  if (!meta) return;
  if (!status || !status.last_successful_to_date) {
    meta.textContent = "";
    meta.className = "source-meta";
    return;
  }
  const freshness = status.reference_data_freshness || "";
  const parts = [`数据截止 ${status.last_successful_to_date}`];
  if (status.vulnerability_count) {
    parts.push(`${formatNumber(status.vulnerability_count)} 漏洞`);
  }
  if (freshness && freshness !== "fresh" && freshness !== "unknown") {
    parts.push(freshnessLabel(freshness));
  }
  meta.textContent = parts.join(" · ");
  meta.className = "source-meta";
  if (status.status === "local_unavailable") {
    meta.classList.add("danger");
  } else if (freshness !== "fresh" && status.status !== "online") {
    meta.classList.add("warning");
  }
  // tooltip 补充本地快照构建日与计数详情
  const detail = [];
  if (status.snapshot_created_at) detail.push(`本地快照构建：${formatDate(status.snapshot_created_at)}`);
  if (status.mapping_count) detail.push(`CVE↔EUVD 映射：${formatNumber(status.mapping_count)}`);
  if (status.known_exploited_count) detail.push(`KEV：${formatNumber(status.known_exploited_count)}`);
  const pill = document.getElementById("sourcePill");
  if (pill) pill.title = `公开情报来源：ENISA EUVD 与 EU/CISA KEV\n${detail.join("\n")}`;
}

// Phase A: ops alert badges (orchestrator / data freshness / ENISA egress).
// pollOpsAlerts() fetches /api/euvd/sync-status every 60s and renders up to 3
// always-visible header badges so degradation is not buried inside the Art.14 view.
function renderAlertBadges(status) {
  const root = elements.alertBadges;
  if (!root) return;
  const badges = [];
  if (status && status.orchestrator_available === false) {
    badges.push({ cls: "alert-badge danger", icon: "server-off", text: "编排器未运行" });
  }
  const age = status && typeof status.data_age_days === "number" ? status.data_age_days : null;
  if (age !== null) {
    if (age >= 7) {
      badges.push({ cls: "alert-badge danger", icon: "alert-triangle", text: `数据过期 ${age} 天` });
    } else if (age >= 3) {
      badges.push({ cls: "alert-badge warning", icon: "clock", text: `数据滞后 ${age} 天` });
    }
  }
  const egress = status ? status.enisa_egress_status : null;
  if (egress === "blocked") {
    badges.push({
      cls: "alert-badge danger",
      icon: "shield-alert",
      text: `ENISA 被封（连续 ${status.enisa_consecutive_failures ?? "?"} 次）`,
    });
  } else if (egress === "degraded") {
    badges.push({ cls: "alert-badge warning", icon: "shield-alert", text: "ENISA 出口受限" });
  }
  root.innerHTML = badges
    .map((b) => `<span class="${b.cls}"><i data-lucide="${b.icon}" aria-hidden="true"></i>${escapeHtml(b.text)}</span>`)
    .join("");
  if (window.lucide) lucide.createIcons();
}

async function pollOpsAlerts() {
  try {
    renderAlertBadges(await api("/api/euvd/sync-status"));
  } catch {
    /* silent — alert badges are best-effort */
  }
}

// freshness 枚举实际值（Mirror sync_state）：fresh / degraded_local_snapshot /
// stale / unavailable / unknown —— 不只是 simple degraded，用前缀判断更稳健。
function freshnessLabel(f) {
  if (f === "fresh") return "新鲜";
  if (f.startsWith("degraded")) return "降级";
  if (f === "stale") return "过期";
  if (f === "unavailable") return "不可用";
  return f;
}

function metricCard(label, value, tone = "", note = "") {
  return `
    <div class="metric ${tone}">
      <div class="metric-label">${escapeHtml(label)}</div>
      <div class="metric-value">${escapeHtml(value)}</div>
      <div class="metric-note">${escapeHtml(note)}</div>
    </div>
  `;
}

function qualityTone(value) {
  if (value === null || value === undefined) return "unknown";
  if (value >= 95) return "good";
  if (value >= 80) return "medium";
  return "low";
}

function qualityRow(label, value) {
  const known = value !== null && value !== undefined;
  const display = known ? `${value}%` : "未知";
  const width = known ? Math.max(0, Math.min(100, value)) : 100;
  return `
    <div class="quality-row">
      <div class="quality-label">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(display)}</strong>
      </div>
      <div class="quality-track">
        <div class="quality-fill ${qualityTone(value)}" style="width:${width}%"></div>
      </div>
    </div>
  `;
}

function severityClass(value) {
  return {
    严重: "severe",
    高: "high",
    中: "medium",
    低: "low",
  }[value] || "unrated";
}

function emptyRow(columns, text = "暂无数据") {
  return `<tr class="empty-row"><td colspan="${columns}">${escapeHtml(text)}</td></tr>`;
}

function projectNameCell(project) {
  const version = project.version ? `版本 ${project.version}` : "未标注版本";
  return `
    <button class="project-link link-button" data-open-project="${escapeHtml(project.id)}" type="button">
      ${escapeHtml(project.name)}
    </button>
    <div class="cell-sub">${escapeHtml(version)}</div>
  `;
}

function bindProjectLinks(container) {
  container.querySelectorAll("[data-open-project]").forEach((button) => {
    button.addEventListener("click", () => openProject(button.dataset.openProject));
  });
}

async function loadDashboard(force = false) {
  if (state.dashboard && !force) {
    renderDashboard();
    return;
  }
  try {
    state.dashboard = await api("/api/dashboard");
    renderDashboard();
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderDashboard() {
  const data = state.dashboard;
  if (!data) return;
  const metrics = data.metrics;
  elements.dashboardTimestamp.textContent = `统计更新：${formatDate(data.generated_at)}`;
  elements.projectNavCount.textContent = metrics.project_count;
  elements.dashboardMetrics.innerHTML = [
    metricCard("项目", formatNumber(metrics.project_count), "cyan", `${metrics.version_count} 个版本`),
    metricCard("组件", formatNumber(metrics.component_count), "", "跨全部项目版本"),
    metricCard("EUVD记录", formatNumber(metrics.confirmed_findings), "cyan", "CVE/EUVD映射或产品候选"),
    metricCard("KEV已知利用", formatNumber(metrics.known_exploited_findings), "danger", "外部公开利用信号"),
    metricCard("Art.14待评估", formatNumber(metrics.art14_review_findings), "warning", "不等于已触发强制报告"),
    metricCard("查询错误", formatNumber(metrics.query_errors), metrics.query_errors ? "danger" : "success", "EUVD 请求失败"),
  ].join("");

  const severities = [
    ["严重", data.severity_counts["严重"] || 0, "severe"],
    ["高", data.severity_counts["高"] || 0, "high"],
    ["中", data.severity_counts["中"] || 0, "medium"],
    ["低", data.severity_counts["低"] || 0, "low"],
    ["未评级", data.severity_counts["未评级"] || 0, "unrated"],
  ];
  const maximum = Math.max(1, ...severities.map((row) => row[1]));
  elements.severityChart.innerHTML = severities
    .map(
      ([label, value, tone]) => `
        <div class="bar-row">
          <span class="bar-label">${escapeHtml(label)}</span>
          <div class="bar-track">
            <div class="bar-fill ${tone}" style="width:${(value * 100) / maximum}%"></div>
          </div>
          <span class="bar-value">${formatNumber(value)}</span>
        </div>
      `,
    )
    .join("");
  elements.qualityChart.innerHTML = [
    qualityRow("SBOM 身份覆盖", metrics.identity_coverage_percent),
    qualityRow("EUVD 查询成功", metrics.query_coverage_percent),
    qualityRow("完整分页拉取", metrics.retrieval_coverage_percent),
  ].join("");

  const projects = data.recent_projects || [];
  elements.recentProjectsBody.innerHTML =
    projects
      .map((project) => {
        const summary = project.summary || {};
        return `
          <tr>
            <td>${projectNameCell(project)}</td>
            <td>${escapeHtml(project.customer || "未标注")}</td>
            <td>${formatNumber(summary.component_count)}</td>
            <td><strong>${formatNumber(summary.confirmed_findings)}</strong></td>
            <td>${formatNumber(summary.review_findings)}</td>
            <td>${project.highest_cvss === null ? "—" : escapeHtml(project.highest_cvss)}</td>
            <td>${escapeHtml(formatDate(project.finished_at))}</td>
            <td>
              <button class="icon-button" data-open-project="${escapeHtml(project.id)}" type="button" title="打开项目">
                <i data-lucide="chevron-right" aria-hidden="true"></i>
              </button>
            </td>
          </tr>
        `;
      })
      .join("") || emptyRow(8, "尚未完成项目扫描");
  bindProjectLinks(elements.recentProjectsBody);
  initIcons();
}

async function loadProjects(force = false) {
  if (state.projects.length && !force) {
    renderProjects();
    return;
  }
  try {
    const result = await api("/api/projects");
    state.projects = result.projects || [];
    elements.projectNavCount.textContent = new Set(
      state.projects.filter((row) => row.status === "completed").map((row) => row.name),
    ).size;
    renderProjects();
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderProjects() {
  const search = state.projectSearch.trim().toLowerCase();
  const filtered = state.projects.filter((project) =>
    [project.name, project.version, project.customer, project.file_name]
      .join(" ")
      .toLowerCase()
      .includes(search),
  );
  elements.projectListMeta.textContent = `${filtered.length} 个项目版本`;
  elements.projectsBody.innerHTML =
    filtered
      .map((project) => {
        const summary = project.summary || {};
        const statusMap = {
          completed: ["已完成", "confirmed"],
          failed: ["失败", "error"],
          running: ["扫描中", "review"],
          queued: ["排队中", "neutral"],
        };
        const [statusLabel, statusTone] = statusMap[project.status] || ["未知", "neutral"];
        const coverage = summary.identity_coverage_percent;
        return `
          <tr>
            <td>${projectNameCell(project)}</td>
            <td>${escapeHtml(project.version || "—")}</td>
            <td>${escapeHtml(project.customer || "未标注")}</td>
            <td><span class="status-badge ${statusTone}">${statusLabel}</span></td>
            <td>${formatNumber(summary.component_count)}</td>
            <td>${formatNumber(summary.confirmed_findings)}</td>
            <td>${formatNumber(summary.review_findings)}</td>
            <td><span class="coverage-badge ${qualityTone(coverage)}">${coverage ?? "—"}${coverage === null || coverage === undefined ? "" : "%"}</span></td>
            <td>${escapeHtml(formatDate(project.finished_at || project.created_at))}</td>
            <td>
              <button class="icon-button" data-open-project="${escapeHtml(project.id)}" type="button" title="打开项目">
                <i data-lucide="eye" aria-hidden="true"></i>
              </button>
            </td>
          </tr>
        `;
      })
      .join("") || emptyRow(10);
  bindProjectLinks(elements.projectsBody);
  initIcons();
}

async function loadComponents(force = false) {
  if (state.components.length && !force) {
    renderComponents();
    return;
  }
  try {
    const result = await api("/api/catalog/components");
    state.components = result.components || [];
    renderComponents();
    if (result.truncated) showToast("组件视图显示前 5000 条");
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderComponents() {
  const search = state.componentSearch.trim().toLowerCase();
  const filtered = state.components.filter((row) =>
    [row.name, row.version, row.vendor, row.project_name, row.purl, row.cpe, row.cve_ids, row.euvd_ids]
      .join(" ")
      .toLowerCase()
      .includes(search),
  );
  elements.componentListMeta.textContent = `${filtered.length} 个组件记录`;
  elements.componentsBody.innerHTML =
    filtered
      .slice(0, 2000)
      .map((row) => {
        const identifier = row.cve_ids || row.euvd_ids || row.purl || row.cpe || "名称 / 版本";
        const queryTone = row.query_status === "错误" ? "error" : "confirmed";
        return `
          <tr>
            <td><strong>${escapeHtml(row.name)}</strong></td>
            <td>${escapeHtml(row.version || "未提供")}</td>
            <td>${escapeHtml(row.vendor || "未提供")}</td>
            <td>
              <button class="project-link link-button" data-open-project="${escapeHtml(row.job_id)}" type="button">
                ${escapeHtml(row.project_name)}
              </button>
              <div class="cell-sub">${escapeHtml(row.project_version || "未标注版本")}</div>
            </td>
            <td title="${escapeHtml(identifier)}">${escapeHtml(identifier)}</td>
            <td>${formatNumber(row.confirmed_count)}</td>
            <td>${formatNumber(row.review_count)}</td>
            <td><span class="status-badge ${queryTone}">${escapeHtml(row.query_status || "历史记录")}</span></td>
            <td>${escapeHtml(row.result)}</td>
          </tr>
        `;
      })
      .join("") || emptyRow(9);
  bindProjectLinks(elements.componentsBody);
}

async function loadVulnerabilities(force = false) {
  if (state.vulnerabilities.length && !force) {
    renderVulnerabilities();
    return;
  }
  try {
    const result = await api("/api/catalog/vulnerabilities");
    state.vulnerabilities = result.vulnerabilities || [];
    renderVulnerabilities();
    if (result.truncated) showToast("漏洞视图显示前 5000 条");
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderVulnerabilities() {
  const search = state.vulnerabilitySearch.trim().toLowerCase();
  const filtered = state.vulnerabilities.filter((row) => {
    if (state.vulnerabilityFilter !== "all" && row.match_status !== state.vulnerabilityFilter) {
      return false;
    }
    return [row.euvd_id, row.source_identifier, row.component_name, row.project_name, row.affected_vendor, row.exploitation_status]
      .join(" ")
      .toLowerCase()
      .includes(search);
  });
  elements.vulnerabilityListMeta.textContent = `${filtered.length} 条匹配记录`;
  elements.vulnerabilitiesBody.innerHTML =
    filtered
      .slice(0, 2000)
      .map(
        (row) => `
          <tr>
            <td><span class="status-badge ${row.mapping_status === "EUVD精确匹配" ? "confirmed" : "review"}">${escapeHtml(row.mapping_status || row.match_status)}</span></td>
            <td>${escapeHtml(row.source_identifier || "产品名检索")}</td>
            <td><a class="euvd-link" href="${escapeHtml(row.euvd_url)}" target="_blank" rel="noreferrer">${escapeHtml(row.euvd_id)}</a></td>
            <td><strong>${escapeHtml(row.exploitation_status || "历史记录")}</strong><div class="cell-sub">${escapeHtml(row.kev_sources || row.evidence_confidence || "")}</div></td>
            <td><strong>${escapeHtml(row.component_name)}</strong><div class="cell-sub">${escapeHtml(row.component_version)}</div></td>
            <td>
              <button class="project-link link-button" data-open-project="${escapeHtml(row.job_id)}" type="button">
                ${escapeHtml(row.project_name)}
              </button>
              <div class="cell-sub">${escapeHtml(row.project_version || "未标注版本")}</div>
            </td>
            <td>${escapeHtml(row.component_applicability || "待人工核验")}</td>
            <td>${escapeHtml(row.art14_readiness || "待人工核验")}</td>
            <td><button class="text-button" data-create-art14="${escapeHtml(row.job_id)}" data-finding-index="${escapeHtml(row.finding_index)}" type="button">建立案件</button></td>
          </tr>
        `,
      )
      .join("") || emptyRow(9);
  bindProjectLinks(elements.vulnerabilitiesBody);
  elements.vulnerabilitiesBody.querySelectorAll("[data-create-art14]").forEach((button) => {
    button.addEventListener("click", () =>
      createCaseFromFinding(button.dataset.createArt14, Number(button.dataset.findingIndex)),
    );
  });
}

async function uploadFile(file) {
  if (!file) return;
  elements.uploadState.classList.remove("hidden");
  elements.uploadStateText.textContent = `正在读取 ${file.name}`;
  elements.dropZone.classList.add("hidden");
  elements.receiptZone.classList.add("hidden");
  const form = new FormData();
  form.append("file", file);
  const receiptFile = elements.receiptInput.files[0];
  if (receiptFile) form.append("receipt", receiptFile);
  try {
    const result = await api("/api/uploads/preview", { method: "POST", body: form });
    state.upload = result;
    state.mapping = { ...result.mapping };
    // D1: prefilled product identity from the customer Metadata sheet (editable).
    const binding = result.metadata_binding;
    const bound = [];
    if (binding && binding.fields) {
      const f = binding.fields;
      if (f.product_name && !elements.projectName.value.trim()) {
        elements.projectName.value = f.product_name;
        bound.push("产品名称");
      }
      if (f.product_version) {
        elements.projectVersion.value = f.product_version;
        bound.push("产品版本");
      }
      if (f.software_build) {
        elements.softwareBuild.value = f.software_build;
        bound.push("构建号");
      }
    } else if (!elements.projectName.value.trim()) {
      elements.projectName.value = result.file_name.replace(/\.[^.]+$/, "");
    }
    renderMapping();
    renderPreview();
    elements.fileMeta.textContent = `${result.file_name} · ${result.sheet}`;
    const boundHint = bound.length
      ? ` · 已从${binding.source_sheet || "元数据页"}绑定 ${bound.join("、")}（可修改）`
      : "";
    const decl = binding?.evidence || {};
    const declHint = decl.classification
      ? ` · 来源声明 ${decl.classification}`
      : "";
    elements.previewMeta.textContent = `${result.row_count} 行 · 表头位于第 ${result.header_row} 行${boundHint}${declHint}`;
    elements.mappingArea.classList.remove("hidden");
  } catch (error) {
    showToast(error.message, "error");
    elements.dropZone.classList.remove("hidden");
    elements.receiptZone.classList.remove("hidden");
  } finally {
    elements.uploadState.classList.add("hidden");
    elements.fileInput.value = "";
    elements.receiptInput.value = "";
  }
}

function renderMapping() {
  const options = [
    '<option value="">不使用</option>',
    ...state.upload.headers.map(
      (header) => `<option value="${escapeHtml(header)}">${escapeHtml(header)}</option>`,
    ),
  ].join("");
  elements.mappingGrid.innerHTML = fields
    .map(
      ([key, label, required]) => `
        <div class="field">
          <label for="mapping-${key}">
            ${escapeHtml(label)}${required ? '<span class="required"> *</span>' : ""}
          </label>
          <select id="mapping-${key}" data-field="${key}">${options}</select>
        </div>
      `,
    )
    .join("");
  elements.mappingGrid.querySelectorAll("select").forEach((select) => {
    const key = select.dataset.field;
    select.value = state.mapping[key] || "";
    select.addEventListener("change", () => {
      state.mapping[key] = select.value;
    });
  });
}

function renderPreview() {
  const headers = state.upload.headers;
  elements.previewTable.innerHTML = `
    <thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>
    <tbody>
      ${state.upload.preview_rows
        .map(
          (row) =>
            `<tr>${headers.map((header) => `<td>${escapeHtml(row[header])}</td>`).join("")}</tr>`,
        )
        .join("")}
    </tbody>
  `;
}

function resetImport({ keepMetadata = false } = {}) {
  state.upload = null;
  state.mapping = {};
  elements.dropZone.classList.remove("hidden");
  elements.receiptZone.classList.remove("hidden");
  elements.mappingArea.classList.add("hidden");
  elements.fileInput.value = "";
  elements.receiptInput.value = "";
  if (!keepMetadata) {
    elements.projectName.value = "";
    elements.projectVersion.value = "";
    elements.softwareBuild.value = "";
    elements.customerName.value = "";
  }
}

async function startMatch() {
  if (!state.upload) {
    showToast("请先选择 SBOM 文件", "error");
    return;
  }
  if (!elements.projectName.value.trim()) {
    showToast("请输入项目名称", "error");
    elements.projectName.focus();
    return;
  }
  if (!state.mapping.name && !state.mapping.cve && !state.mapping.euvd) {
    showToast("请选择组件名称、CVE 或 EUVD ID 列之一", "error");
    return;
  }
  elements.startMatchButton.disabled = true;
  try {
    const job = await api("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        upload_id: state.upload.upload_id,
        mapping: state.mapping,
        project_name: elements.projectName.value.trim(),
        project_version: elements.projectVersion.value.trim(),
        software_build: elements.softwareBuild.value.trim(),
        customer: elements.customerName.value.trim(),
      }),
    });
    state.job = job;
    state.detailTab = "vulnerabilities";
    state.projectDetailSearch = "";
    elements.projectDetailSearch.value = "";
    showView("projectView");
    renderProject(job);
    pollJob();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    elements.startMatchButton.disabled = false;
  }
}

function renderProgress(job) {
  const progress = Number(job.progress || 0);
  elements.progressPanel.classList.toggle("hidden", job.status === "completed");
  elements.progressPanel.setAttribute("aria-valuenow", String(Math.max(0, Math.min(100, progress))));
  elements.progressStage.textContent = job.stage || "处理中";
  elements.progressPercent.textContent = `${progress}%`;
  elements.progressBar.style.width = `${progress}%`;
  elements.progressDetail.textContent =
    job.total > 0
      ? `${job.completed || 0} / ${job.total}${job.current_component ? ` · ${job.current_component}` : ""}`
      : "正在准备组件清单";
  const action = elements.progressAction;
  if (!action) return;
  if (job.status === "queued" || job.status === "running") {
    action.innerHTML = `<button class="btn" id="cancelJobBtn">取消任务</button>`;
    document.getElementById("cancelJobBtn")?.addEventListener("click", () => cancelJob(job.id));
  } else if (job.status === "canceling") {
    action.innerHTML = `<span class="muted">正在取消…</span>`;
  } else if (job.status === "failed" || job.status === "cancelled") {
    action.innerHTML = `<button class="btn" id="retryJobBtn">重新扫描</button>`;
    document.getElementById("retryJobBtn")?.addEventListener("click", () => retryJob(job.id));
  } else {
    action.innerHTML = "";
  }
}

async function cancelJob(jobId) {
  try {
    await api(`/api/jobs/${jobId}/cancel`, { method: "POST" });
    showToast("正在取消任务", "info");
    pollJob();
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function retryJob(jobId) {
  try {
    await api(`/api/jobs/${jobId}/retry`, { method: "POST" });
    showToast("已重新排队", "info");
    pollJob();
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function pollJob() {
  window.clearTimeout(state.pollTimer);
  if (!state.job) return;
  try {
    const job = await api(`/api/jobs/${state.job.id}`);
    state.job = job;
    renderProject(job);
    if (job.status === "completed") {
      state.dashboard = null;
      state.projects = [];
      state.components = [];
      state.vulnerabilities = [];
      await Promise.all([loadDashboard(true), loadProjects(true)]);
      return;
    }
    if (job.status === "failed") {
      showToast(job.error || "匹配任务失败", "error");
      return;
    }
    if (job.status === "cancelled") {
      showToast("匹配任务已取消", "info");
      return;
    }
    state.pollTimer = window.setTimeout(pollJob, 900);
  } catch (error) {
    showToast(error.message, "error");
    state.pollTimer = window.setTimeout(pollJob, 2400);
  }
}

async function openProject(jobId) {
  try {
    const job = await api(`/api/jobs/${jobId}`);
    state.job = job;
    state.detailTab = "vulnerabilities";
    state.projectDetailSearch = "";
    elements.projectDetailSearch.value = "";
    showView("projectView");
    renderProject(job);
    if (!["completed", "failed", "cancelled"].includes(job.status)) pollJob();
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderProject(job) {
  document.querySelectorAll("[data-detail-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.detailTab === state.detailTab);
  });
  elements.projectTitle.textContent = job.project_name || job.file_name || "项目详情";
  elements.projectSubtitle.textContent = [
    job.project_version ? `版本 ${job.project_version}` : "未标注版本",
    job.customer || "未标注客户",
    job.file_name,
    formatDate(job.finished_at || job.created_at),
  ].join(" · ");
  renderProgress(job);
  renderSourceDeclarations(job);
  const result = job.result;
  if (!result) {
    elements.projectMetrics.innerHTML = [
      metricCard("状态", job.stage || "排队中", "cyan"),
      metricCard("进度", `${job.progress || 0}%`, ""),
      metricCard("已处理组件", job.completed || 0, ""),
    ].join("");
    elements.projectQualityPanel.classList.add("hidden");
    elements.downloadReportButton.classList.add("hidden");
    elements.projectDetailTable.innerHTML = `<tbody>${emptyRow(1, "扫描完成后显示结果")}</tbody>`;
    return;
  }

  const summary = result.summary;
  elements.projectMetrics.innerHTML = [
    metricCard("组件", formatNumber(summary.component_count), "cyan"),
    metricCard("EUVD记录", formatNumber(summary.confirmed_findings), "cyan"),
    metricCard("KEV已知利用", formatNumber(summary.known_exploited_findings), "danger"),
    metricCard("Art.14待评估", formatNumber(summary.art14_review_findings), "warning"),
    metricCard("未映射标识符", formatNumber(summary.unmapped_identifier_count), ""),
    metricCard("查询错误", formatNumber(summary.error_count), summary.error_count ? "danger" : "success"),
  ].join("");
  elements.projectQualityPanel.classList.remove("hidden");
  elements.projectQuality.innerHTML = [
    qualityRow("身份覆盖", summary.identity_coverage_percent),
    qualityRow("查询成功", summary.query_coverage_percent),
    qualityRow("完整分页", summary.retrieval_coverage_percent),
  ].join("");
  elements.downloadReportButton.classList.toggle("hidden", !job.report_url);
  elements.downloadReportButton.href = job.report_url || "#";
  elements.downloadEvidenceButton.classList.toggle("hidden", job.status !== "completed");
  elements.downloadEvidenceButton.href = job.id
    ? `/api/jobs/${encodeURIComponent(job.id)}/evidence-package`
    : "#";
  renderProjectDetail();
}

function renderSourceDeclarations(job) {
  const decl = job.sbom_source_declarations;
  if (!decl || !Object.keys(decl).length) {
    elements.sbomSourceDeclarations.classList.add("hidden");
    return;
  }
  elements.sbomSourceDeclarations.classList.remove("hidden");
  const chip = (label, value, tone = "") =>
    value
      ? `<span class="decl-chip ${tone}"><strong>${escapeHtml(label)}</strong>${escapeHtml(String(value))}</span>`
      : "";
  const status = decl.source_binding_status;
  const provenance =
    status === "DERIVED_FROM_VERIFIED_M3A_ROOT"
      ? decl.source_reverification_status === "VERIFIED_AGAINST_M3A_ROOT"
        ? "三面 VERIFIED"
        : "Workbench 派生；EUVD 未重验源根"
      : status === "CALLER_DECLARED_NOT_INDEPENDENTLY_VERIFIED"
        ? "单面 DECLARED"
        : status || "";
  elements.declarationChips.innerHTML = [
    chip("分类", decl.classification, "decl-warning"),
    chip("provenance", provenance, provenance === "三面 VERIFIED" ? "decl-success" : "decl-warning"),
    chip("单向契约", decl.direction, ""),
    chip("组件数", decl.component_record_count, ""),
  ].join("");
}

function renderProjectDetail() {
  if (!state.job?.result) return;
  const search = state.projectDetailSearch.trim().toLowerCase();
  const result = state.job.result;
  let headers = [];
  let rows = [];
  if (state.detailTab === "vulnerabilities") {
    headers = ["映射", "输入标识", "EUVD ID", "外部利用情报", "组件", "产品适用性", "CRA Art.14", "SRP准备度", "证据依据"];
    rows = (result.matches || [])
      .filter((row) =>
        [row.euvd_id, row.source_identifier, row.component_name, row.affected_vendor, row.affected_product, row.exploitation_status]
          .join(" ")
          .toLowerCase()
          .includes(search),
      )
      .map(
        (row) => `
          <tr>
            <td><span class="status-badge ${row.mapping_status === "EUVD精确匹配" ? "confirmed" : "review"}">${escapeHtml(row.mapping_status || row.match_status)}</span></td>
            <td>${escapeHtml(row.source_identifier || "产品名检索")}</td>
            <td><a class="euvd-link" href="${escapeHtml(row.euvd_url)}" target="_blank" rel="noreferrer">${escapeHtml(row.euvd_id)}</a></td>
            <td><strong>${escapeHtml(row.exploitation_status || "历史记录")}</strong><div class="cell-sub">${escapeHtml(row.kev_sources || row.evidence_confidence || "")}</div></td>
            <td><strong>${escapeHtml(row.component_name)}</strong><div class="cell-sub">${escapeHtml(row.component_version)}</div></td>
            <td>${escapeHtml(row.component_applicability || "待人工核验")}</td>
            <td>${escapeHtml(row.art14_readiness || "待人工核验")}</td>
            <td>${escapeHtml(row.srp_readiness || "未准备")}</td>
            <td>${escapeHtml(row.match_reason)}</td>
          </tr>
        `,
      );
  } else if (state.detailTab === "components") {
    headers = ["组件", "版本", "厂商", "CVE / EUVD / PURL / CPE", "身份状态", "EUVD 返回", "EUVD记录", "需复核", "结果"];
    rows = (result.components || [])
      .filter((row) =>
        [row.name, row.version, row.vendor, row.purl, row.cpe, row.cve_ids, row.euvd_ids]
          .join(" ")
          .toLowerCase()
          .includes(search),
      )
      .map(
        (row) => `
          <tr>
            <td><strong>${escapeHtml(row.name)}</strong></td>
            <td>${escapeHtml(row.version || "未提供")}</td>
            <td>${escapeHtml(row.vendor || "未提供")}</td>
            <td>${escapeHtml(row.cve_ids || row.euvd_ids || row.purl || row.cpe || "未提供")}</td>
            <td><span class="coverage-badge ${row.identity_ready ? "good" : "low"}">${row.identity_ready ? "可匹配" : "信息不足"}</span></td>
            <td>${formatNumber(row.query_result_count)}</td>
            <td>${formatNumber(row.confirmed_count)}</td>
            <td>${formatNumber(row.review_count)}</td>
            <td>${escapeHtml(row.result)}</td>
          </tr>
        `,
      );
  } else {
    headers = ["SBOM 行", "组件", "错误"];
    rows = (result.errors || [])
      .filter((row) =>
        [row.component_name, row.error].join(" ").toLowerCase().includes(search),
      )
      .map(
        (row) => `
          <tr>
            <td>${escapeHtml(row.component_row)}</td>
            <td><strong>${escapeHtml(row.component_name)}</strong></td>
            <td>${escapeHtml(row.error)}</td>
          </tr>
        `,
      );
  }
  elements.projectDetailMeta.textContent = `${rows.length} 条记录`;
  elements.projectDetailTable.innerHTML = `
    <thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>
    <tbody>${rows.join("") || emptyRow(headers.length)}</tbody>
  `;
}

function toDateTimeLocal(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (part) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function toIsoOrNull(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function caseTone(value) {
  if (["approved", "submitted", "known_not_affected", "fixed"].includes(value)) return "confirmed";
  if (["reportable", "overdue", "stale"].includes(value)) return "error";
  if (["technical_review", "compliance_review", "under_investigation"].includes(value)) return "review";
  return "neutral";
}

function renderReviewerOptions() {
  const allOptions = state.reviewers
    .map((row) => `<option value="${escapeHtml(row.id)}">${escapeHtml(row.display_name)} · ${escapeHtml(row.role)}</option>`)
    .join("");
  const awarenessOptions = state.reviewers
    .filter((row) => ["manufacturer_authorized", "compliance"].includes(row.role))
    .map((row) => `<option value="${escapeHtml(row.id)}">${escapeHtml(row.display_name)} · ${escapeHtml(row.role)}</option>`)
    .join("");
  const submissionOptions = state.reviewers
    .filter((row) => row.role === "manufacturer_authorized")
    .map((row) => `<option value="${escapeHtml(row.id)}">${escapeHtml(row.display_name)}</option>`)
    .join("");
  elements.reviewIdentity.innerHTML = allOptions || '<option value="">请先创建审批身份</option>';
  elements.awarenessReviewer.innerHTML = awarenessOptions || '<option value="">请先创建合规/制造商授权身份</option>';
  elements.submissionReviewer.innerHTML = submissionOptions || '<option value="">请先创建制造商授权身份</option>';
  elements.reviewerList.textContent = state.reviewers.length
    ? state.reviewers.map((row) => `${row.display_name}（${row.role}）`).join("、")
    : "尚未创建审批身份";
}

function renderFeedSnapshots() {
  elements.feedSnapshotStatus.innerHTML =
    state.snapshots
      .map((row) => {
        const tone = row.status === "fresh" ? "good" : row.status === "unavailable" ? "danger" : "warning";
        return `<span class="status-chip ${tone}"><strong>${escapeHtml(row.feed_name)}</strong><span>${escapeHtml(row.status)}</span><span>${escapeHtml(formatDate(row.retrieved_at))}</span></span>`;
      })
      .join("") || '<span class="status-chip warning">尚无快照状态；首次扫描或手工更新后生成</span>';
}

// 改进1：EUVD 目录（只读快照全库浏览）。搜索/排序/分页均通过 /api/euvd/records
// 服务端处理，前端不一次性加载 37 万条。
async function loadEuvdCatalog(force = false) {
  if (state.euvdCatalog.loaded && !force) {
    renderEuvdCatalog();
    return;
  }
  try {
    const cat = state.euvdCatalog;
    const params = new URLSearchParams({
      page: String(cat.page),
      page_size: String(cat.page_size),
      sort: cat.sort,
    });
    if (cat.q) params.set("q", cat.q);
    if (cat.actively_exploited_only) params.set("actively_exploited_only", "true");
    const result = await api(`/api/euvd/records?${params}`);
    state.euvdCatalog.records = result.records || [];
    state.euvdCatalog.total = result.total || 0;
    state.euvdCatalog.loaded = true;
    renderEuvdCatalog(result.freshness);
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderEuvdCatalog(freshness) {
  const cat = state.euvdCatalog;
  elements.euvdCatalogBody.innerHTML =
    cat.records
      .map((row) => {
        const sevTone =
          row.severity === "严重" ? "danger"
          : row.severity === "高" ? "warning"
          : "review";
        const products =
          (row.products || [])
            .map((p) => {
              const name = escapeHtml(p.name || "");
              const vendor = p.vendor ? ` <span class="muted">· ${escapeHtml(p.vendor)}</span>` : "";
              return name ? `${name}${vendor}` : "";
            })
            .filter(Boolean)
            .join("<br>") || '<span class="muted">—</span>';
        const exploited = row.actively_exploited
          ? `<span class="status-badge danger">积极利用</span>${
              row.exploited_since
                ? `<div class="cell-sub">自 ${escapeHtml(formatDate(row.exploited_since))}</div>`
                : ""
            }${
              row.kev_sources && row.kev_sources.length
                ? `<div class="cell-sub">${escapeHtml(
                    row.kev_sources
                      .map((s) => (s === "cisa_kev" ? "CISA KEV" : s === "eukev_kev" ? "EU KEV" : s))
                      .join(" · "),
                  )}</div>`
                : ""
            }`
          : '<span class="muted">—</span>';
        return `
          <tr class="${row.actively_exploited ? "row-actively-exploited" : ""}">
            <td><a class="euvd-link" href="https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(row.euvd_id)}" target="_blank" rel="noreferrer">${escapeHtml(row.euvd_id)}</a></td>
            <td>${row.cve_id ? escapeHtml(row.cve_id) : '<span class="muted">—</span>'}</td>
            <td><span class="status-badge ${sevTone}">${escapeHtml(row.severity)}</span></td>
            <td>${row.base_score != null ? escapeHtml(String(row.base_score)) : '<span class="muted">—</span>'}</td>
            <td>${products}</td>
            <td>${exploited}</td>
            <td>${escapeHtml(formatDate(row.date_published))}</td>
            <td>${escapeHtml(formatDate(row.date_updated))}</td>
          </tr>`;
      })
      .join("") || emptyRow(8);
  const start = cat.total === 0 ? 0 : (cat.page - 1) * cat.page_size + 1;
  const end = Math.min(cat.page * cat.page_size, cat.total);
  elements.euvdCatalogMeta.textContent = `共 ${formatNumber(cat.total)} 条`;
  elements.euvdCatalogPageInfo.textContent = `第 ${cat.page} 页 · 显示 ${start}-${end}`;
  elements.euvdCatalogPrev.disabled = cat.page <= 1;
  elements.euvdCatalogNext.disabled = cat.page * cat.page_size >= cat.total;
  if (freshness) {
    elements.euvdCatalogFreshness.textContent =
      `数据截止 ${freshness.last_successful_to_date || "未知"} · ${formatNumber(freshness.vulnerability_count || 0)} 漏洞 · ${freshnessLabel(freshness.reference_data_freshness || "")}`;
  }
}

let euvdCatalogSearchTimer = null;
function onEuvdCatalogSearchInput() {
  clearTimeout(euvdCatalogSearchTimer);
  euvdCatalogSearchTimer = setTimeout(() => {
    state.euvdCatalog.q = elements.euvdCatalogSearch.value.trim();
    state.euvdCatalog.page = 1;
    state.euvdCatalog.loaded = false;
    loadEuvdCatalog(true);
  }, 400);
}

function nextCaseDeadline(row) {
  const deadlines = row.deadlines || {};
  const stage = row.reporting_stage || "not_started";
  let candidate = deadlines.early_warning_24h;
  if (["early_warning_submitted", "notification_submitted"].includes(stage)) {
    candidate = deadlines.notification_72h;
  }
  if (stage === "notification_submitted") candidate = deadlines.final_report;
  if (stage === "final_submitted") return "已完成三阶段回执";
  if (!candidate?.due_at) return "尚未启动";
  return `${candidate.status === "overdue" ? "已逾期 · " : ""}${formatDate(candidate.due_at)}`;
}

async function loadArt14Workspace(force = false) {
  if (state.art14Cases.length && !force) {
    renderArt14Cases();
    renderReviewerOptions();
    renderFeedSnapshots();
    return;
  }
  try {
    const [casesResult, reviewersResult, snapshotsResult] = await Promise.all([
      api("/api/art14/cases"),
      api("/api/reviewers"),
      api("/api/euvd/snapshots"),
    ]);
    state.art14Cases = casesResult.cases || [];
    state.reviewers = reviewersResult.reviewers || [];
    state.snapshots = snapshotsResult.snapshots || [];
    renderArt14Cases();
    renderReviewerOptions();
    renderFeedSnapshots();
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderArt14Cases() {
  elements.art14NavCount.textContent = state.art14Cases.length;
  elements.art14ListMeta.textContent = `${state.art14Cases.length} 个案件；只有两名不同本地审批账户一致时才形成最终决定`;
  elements.art14CasesBody.innerHTML =
    state.art14Cases
      .map(
        (row) => `
          <tr>
            <td><strong>${escapeHtml(row.project_name)}</strong><div class="cell-sub">${escapeHtml(row.case_type === "severe_incident" ? "严重安全事件" : "积极利用漏洞")} · ${escapeHtml(row.project_version || "未标注版本")} · ${escapeHtml(row.cve_id || row.euvd_id || "无公开ID")}</div></td>
            <td>${escapeHtml(row.case_type === "severe_incident" ? "事件信号" : (row.public_exploitation_status || "人工信号"))}</td>
            <td><span class="status-badge ${caseTone(row.applicability_status)}">${escapeHtml(row.applicability_status)}</span></td>
            <td><span class="status-badge ${caseTone(row.art14_decision)}">${escapeHtml(row.art14_decision)}</span></td>
            <td><span class="status-badge ${caseTone(row.workflow_status)}">${escapeHtml(row.workflow_status)}</span>${row.stale_reason ? `<div class="cell-sub">${escapeHtml(row.stale_reason)}</div>` : ""}</td>
            <td>${escapeHtml(formatDate(row.awareness_at))}</td>
            <td>${escapeHtml(nextCaseDeadline(row))}</td>
            <td><button class="text-button" data-open-case="${escapeHtml(row.id)}" type="button">打开</button></td>
          </tr>
        `,
      )
      .join("") || emptyRow(8, "尚无案件；可从漏洞清单、VEX 或人工信号建立");
  elements.art14CasesBody.querySelectorAll("[data-open-case]").forEach((button) => {
    button.addEventListener("click", () => openArt14Case(button.dataset.openCase));
  });
}

async function openArt14Case(caseId) {
  try {
    state.currentCase = await api(`/api/art14/cases/${caseId}`);
    renderArt14Case();
    elements.art14CaseDetail.classList.remove("hidden");
    elements.art14CaseDetail.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    showToast(error.message, "error");
  }
}

function renderSrpFields(caseItem) {
  const values = caseItem.srp_fields || {};
  const fieldsForCase = [
    ...commonSrpFields,
    ...(caseItem.case_type === "severe_incident" ? incidentSrpFields : vulnerabilitySrpFields),
  ];
  elements.srpFieldsGrid.innerHTML = fieldsForCase
    .map(([key, label, kind]) => {
      const control =
        kind === "textarea"
          ? `<textarea id="srp-${key}" data-srp-field="${key}" rows="3">${escapeHtml(values[key] || "")}</textarea>`
          : `<input id="srp-${key}" data-srp-field="${key}" type="text" value="${escapeHtml(values[key] || "")}" />`;
      return `<label class="field ${kind === "textarea" ? "field-wide" : ""}"><span>${escapeHtml(label)}</span>${control}</label>`;
    })
    .join("");
}

function updateSrpAssistanceControls() {
  const row = state.currentCase;
  if (!row) {
    elements.downloadSrpPackageButton.disabled = true;
    elements.openSrpPortalButton.disabled = true;
    return;
  }
  const stage = elements.srpPackageStage.value;
  const readiness = (row.srp_readiness || {})[stage] || {};
  const profile = readiness.schema_profile || {};
  elements.downloadSrpPackageButton.disabled = !readiness.ready;
  elements.openSrpPortalButton.disabled = !(
    readiness.portal_submission_ready && elements.srpHumanConfirmation.checked
  );
  const missingPrevious = readiness.missing_prerequisite_receipts || [];
  if (missingPrevious.length) {
    elements.srpPortalStatus.textContent = `须先登记前序官方回执：${missingPrevious.join(", ")}。可提前生成材料，但尚不可进入本阶段提交。`;
  } else {
    elements.srpPortalStatus.textContent = profile.portal_url
      ? "将打开 ENISA 已配置的官方 SRP 入口；本工具不会代替您在门户点击 Submit。"
      : "ENISA 尚未公布正式门户 URL；将打开官方 SRP 信息页。本工具不会代替您在门户点击 Submit。";
  }
}

function renderArt14Case() {
  const row = state.currentCase;
  if (!row) return;
  const isIncident = row.case_type === "severe_incident";
  elements.caseDetailTitle.textContent = `${row.project_name} · ${isIncident ? "严重安全事件" : (row.cve_id || row.euvd_id || "无公开ID")}`;
  elements.caseDetailSubtitle.textContent = `${isIncident ? "CRA Art.14(3)-(5)" : "CRA Art.14(1)-(2)"} · ${row.component_name || "未标注组件"} ${row.component_version || ""} · 案件 ${row.id}`;
  elements.caseApplicability.value = row.applicability_status;
  elements.caseApplicabilityReason.value = row.applicability_justification || "";
  elements.caseEvidenceStatus.value = row.exploitation_evidence_status;
  elements.caseEvidenceSummary.value = row.exploitation_evidence_summary || "";
  const criteria = row.severe_incident_criteria || {};
  elements.incidentDataFunctionImpact.checked = Boolean(criteria.availability_authenticity_integrity_confidentiality_impact);
  elements.incidentMaliciousCode.checked = Boolean(criteria.malicious_code_introduction);
  elements.incidentCriteriaRationale.value = criteria.rationale || "";
  elements.severeIncidentCriteria.classList.toggle("hidden", !isIncident);
  document.querySelectorAll(".vulnerability-only").forEach((item) => item.classList.toggle("hidden", isIncident));
  elements.caseRiskSummary.value = row.product_risk_summary || "";
  elements.caseMitigation.value = row.mitigation_summary || "";
  elements.caseInitialAssessment.value = toDateTimeLocal(row.initial_assessment_completed_at);
  elements.caseCorrectiveAt.value = toDateTimeLocal(row.corrective_measure_available_at);
  elements.caseNextReview.value = toDateTimeLocal(row.next_review_at);
  elements.awarenessAt.value = toDateTimeLocal(row.awareness_at);
  elements.awarenessBasis.value = row.awareness_basis || "";

  const deadlines = row.deadlines || {};
  elements.caseDeadlineStrip.innerHTML = [
    ["24h最迟期限", deadlines.early_warning_24h],
    ["72h最迟期限", deadlines.notification_72h],
    [isIncident ? "Final最迟期限（72h提交后1个月）" : "Final最迟期限（措施可用后14日）", deadlines.final_report],
  ]
    .map(([label, item]) => {
      const tone = item?.status === "overdue" ? "danger" : item?.status === "open" ? "warning" : "";
      return `<span class="status-chip ${tone}"><strong>${label}</strong><span>${escapeHtml(item?.due_at ? formatDate(item.due_at) : "尚未启动")}</span></span>`;
    })
    .join("");

  elements.caseEvidenceList.innerHTML =
    (row.evidence || [])
      .map(
        (item) => `<div class="evidence-item"><strong>${escapeHtml(item.source_type)} · ${escapeHtml(item.reliable_malicious_exploitation)}</strong><div>${escapeHtml(item.description)}</div><div class="muted">${escapeHtml(item.product_relevance || "未填写产品相关性")} · ${escapeHtml(item.sha256 || "未提供hash")}</div></div>`,
      )
      .join("") || '<div class="evidence-item">尚无结构化证据</div>';
  elements.awarenessEvidence.innerHTML = (row.evidence || [])
    .map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.source_type)} · ${escapeHtml(item.description.slice(0, 70))}</option>`)
    .join("");
  const selectedEvidence = new Set(row.awareness_evidence_refs || []);
  [...elements.awarenessEvidence.options].forEach((option) => {
    option.selected = selectedEvidence.has(option.value);
  });

  elements.caseApprovals.innerHTML =
    (row.approvals || [])
      .map((item) => `<div class="evidence-item"><strong>${escapeHtml(item.stage)} · ${escapeHtml(item.decision)}</strong><div>${escapeHtml(item.reviewer)}</div><div>${escapeHtml(item.rationale)}</div></div>`)
      .join("") || '<div class="evidence-item">尚无审批记录</div>';
  elements.submissionList.innerHTML =
    (row.submission_receipts || [])
      .map((item) => `<div class="evidence-item"><strong>${escapeHtml(item.stage)}</strong><div>${escapeHtml(item.receipt)}</div><div class="muted">${escapeHtml(formatDate(item.submitted_at))}</div></div>`)
      .join("") || '<div class="evidence-item">尚无 SRP 手工提交回执</div>';

  renderSrpFields(row);
  const readiness = row.srp_readiness || {};
  elements.srpReadinessPanel.innerHTML = ["early-warning", "notification", "final-report"]
    .map((stage) => {
      const item = readiness[stage] || {};
      return `<span class="status-chip ${item.ready ? "good" : "warning"}"><strong>${stage}</strong><span>${item.ready ? "Ready" : `缺少 ${(item.missing_fields || []).join(", ") || "审批门"}`}</span></span>`;
    })
    .join("");
  elements.caseExports.innerHTML = [
    ...(isIncident ? [] : [
      `<a href="/api/art14/cases/${row.id}/vex/cyclonedx">CycloneDX 1.7 VEX</a>`,
      `<a href="/api/art14/cases/${row.id}/vex/csaf">CSAF 2.0 VEX</a>`,
    ]),
    ...["early-warning", "notification", "final-report"].flatMap((stage) =>
      ["json", "xlsx", "html"].map(
        (format) => `<a href="/api/art14/cases/${row.id}/srp/${stage}/export/${format}">${stage} ${format.toUpperCase()}</a>`,
      ),
    ),
  ].join("");
  elements.srpHumanConfirmation.checked = false;
  updateSrpAssistanceControls();
  renderReviewerOptions();
}

async function createCaseFromFinding(jobId, findingIndex) {
  try {
    const caseItem = await api("/api/art14/cases/from-finding", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ job_id: jobId, finding_index: findingIndex, actor: "local analyst" }),
    });
    state.art14Cases = [];
    showView("art14View");
    await loadArt14Workspace(true);
    await openArt14Case(caseItem.id);
    showToast("已建立 Art.14 人工评估案件");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function createManualCase() {
  try {
    const caseItem = await api("/api/art14/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_type: elements.manualCaseType.value,
        project_name: elements.manualProductName.value.trim(),
        project_version: elements.manualProductVersion.value.trim(),
        component_name: elements.manualComponentName.value.trim(),
        cve_id: elements.manualCveId.value.trim(),
        euvd_id: elements.manualEuvdId.value.trim(),
        vulnerability_summary: elements.manualSummary.value.trim(),
        actor: "local analyst",
      }),
    });
    await loadArt14Workspace(true);
    await openArt14Case(caseItem.id);
    showToast("人工案件已建立");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function importVex() {
  if (!elements.vexFileInput.files[0]) {
    showToast("请选择 VEX JSON 文件", "error");
    return;
  }
  if (!elements.vexReceiptInput.files[0]) {
    showToast("请选择与 VEX 字节绑定的 intake receipt JSON", "error");
    return;
  }
  const issuerId = elements.vexIssuerId.value.trim();
  if (!issuerId) {
    showToast("请输入已由运维加入 allowlist 的签发者 ID", "error");
    return;
  }
  const form = new FormData();
  form.append("file", elements.vexFileInput.files[0]);
  form.append("receipt", elements.vexReceiptInput.files[0]);
  form.append("issuer_id", issuerId);
  form.append("actor", elements.vexActor.value.trim() || "local analyst");
  try {
    const result = await api("/api/vex/import", { method: "POST", body: form });
    elements.vexImportResult.textContent = `${result.format} · ${result.cases.length} 个案件 · SHA-256 ${result.source_sha256}`;
    await loadArt14Workspace(true);
    if (result.cases[0]) await openArt14Case(result.cases[0].id);
    showToast("VEX receipt 绑定验证通过并已导入");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function createReviewer() {
  try {
    await api("/api/reviewers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        display_name: elements.reviewerName.value.trim(),
        role: elements.reviewerRole.value,
        pin: elements.reviewerPin.value,
      }),
    });
    elements.reviewerPin.value = "";
    await loadArt14Workspace(true);
    if (state.currentCase) await openArt14Case(state.currentCase.id);
    showToast("本地审批身份已创建");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function saveCaseAnalysis() {
  if (!state.currentCase) return;
  try {
    state.currentCase = await api(`/api/art14/cases/${state.currentCase.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actor: elements.caseUpdateActor.value.trim() || "local analyst",
        updates: {
          applicability_status: elements.caseApplicability.value,
          applicability_justification: elements.caseApplicabilityReason.value.trim(),
          exploitation_evidence_status: elements.caseEvidenceStatus.value,
          exploitation_evidence_summary: elements.caseEvidenceSummary.value.trim(),
          severe_incident_criteria: {
            availability_authenticity_integrity_confidentiality_impact: elements.incidentDataFunctionImpact.checked,
            malicious_code_introduction: elements.incidentMaliciousCode.checked,
            rationale: elements.incidentCriteriaRationale.value.trim(),
          },
          product_risk_summary: elements.caseRiskSummary.value.trim(),
          mitigation_summary: elements.caseMitigation.value.trim(),
          initial_assessment_completed_at: toIsoOrNull(elements.caseInitialAssessment.value),
          corrective_measure_available_at: toIsoOrNull(elements.caseCorrectiveAt.value),
          next_review_at: toIsoOrNull(elements.caseNextReview.value),
        },
      }),
    });
    await loadArt14Workspace(true);
    renderArt14Case();
    showToast("案件分析已保存；关键字段变更会使旧审批失效");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function addCaseEvidence() {
  if (!state.currentCase) return;
  try {
    state.currentCase = await api(`/api/art14/cases/${state.currentCase.id}/evidence`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source_type: elements.evidenceSourceType.value.trim() || "other",
        source_ref: elements.evidenceSourceRef.value.trim(),
        source_url: elements.evidenceSourceUrl.value.trim(),
        sha256: elements.evidenceSha256.value.trim(),
        description: elements.evidenceDescription.value.trim(),
        product_relevance: elements.evidenceProductRelevance.value.trim(),
        reliable_malicious_exploitation: elements.evidenceReliable.value,
        malicious_actor_confirmed: elements.evidenceMaliciousActor.checked,
        without_permission_confirmed: elements.evidenceWithoutPermission.checked,
        actual_exploitation_confirmed: elements.evidenceActualExploit.checked,
        actor: elements.evidenceActor.value.trim() || "local analyst",
      }),
    });
    renderArt14Case();
    showToast("证据已追加并写入审计记录");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function confirmCaseAwareness() {
  if (!state.currentCase) return;
  try {
    state.currentCase = await api(`/api/art14/cases/${state.currentCase.id}/awareness`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        reviewer_id: elements.awarenessReviewer.value,
        pin: elements.awarenessPin.value,
        awareness_at: toIsoOrNull(elements.awarenessAt.value),
        basis: elements.awarenessBasis.value.trim(),
        evidence_refs: [...elements.awarenessEvidence.selectedOptions].map((option) => option.value),
        confirmation: elements.awarenessConfirmation.checked,
      }),
    });
    elements.awarenessPin.value = "";
    await loadArt14Workspace(true);
    renderArt14Case();
    showToast("awareness 已人工确认，24h/72h 最迟期限已立即计算");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function recordCaseReview() {
  if (!state.currentCase) return;
  try {
    state.currentCase = await api(`/api/art14/cases/${state.currentCase.id}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        reviewer_id: elements.reviewIdentity.value,
        pin: elements.reviewPin.value,
        stage: elements.reviewStage.value,
        decision: elements.reviewDecision.value,
        rationale: elements.reviewRationale.value.trim(),
      }),
    });
    elements.reviewPin.value = "";
    await loadArt14Workspace(true);
    renderArt14Case();
    showToast(elements.reviewStage.value === "technical" ? "技术提议已记录，尚未形成最终决定" : "合规复核已记录");
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function saveSrpFields() {
  if (!state.currentCase) return;
  const srp_fields = {};
  elements.srpFieldsGrid.querySelectorAll("[data-srp-field]").forEach((control) => {
    srp_fields[control.dataset.srpField] = control.value.trim();
  });
  try {
    state.currentCase = await api(`/api/art14/cases/${state.currentCase.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actor: "SRP draft editor", updates: { srp_fields } }),
    });
    renderArt14Case();
    showToast("SRP Q16 2026-08-03 字段草稿已保存；提交前请核对当前门户");
  } catch (error) {
    showToast(error.message, "error");
  }
}

function downloadSrpSubmissionPackage() {
  if (!state.currentCase) return;
  const stage = elements.srpPackageStage.value;
  const readiness = (state.currentCase.srp_readiness || {})[stage] || {};
  if (!readiness.ready) {
    const missing = (readiness.missing_fields || []).join(", ") || "审批门未满足";
    showToast(`完整上报包尚未就绪：${missing}`, "error");
    return;
  }
  const url = `/api/art14/cases/${state.currentCase.id}/srp/${stage}/package.zip`;
  window.location.assign(url);
  showToast("正在生成完整辅助上报包；下载后请先逐项人工核对");
}

function openOfficialSrp() {
  if (!state.currentCase) return;
  const stage = elements.srpPackageStage.value;
  const readiness = (state.currentCase.srp_readiness || {})[stage] || {};
  if (!readiness.portal_submission_ready || !elements.srpHumanConfirmation.checked) {
    const missingPrevious = readiness.missing_prerequisite_receipts || [];
    showToast(
      missingPrevious.length
        ? `请先登记前序官方回执：${missingPrevious.join(", ")}`
        : "请先完成本阶段材料并勾选人工确认",
      "error",
    );
    return;
  }
  const profile = readiness.schema_profile || {};
  const target = profile.portal_url || profile.srp_information_url;
  if (!target) {
    showToast("尚无 ENISA 官方 SRP 页面地址", "error");
    return;
  }
  window.open(target, "_blank", "noopener,noreferrer");
  showToast(
    profile.portal_url
      ? "已打开官方 SRP；请在门户内最终确认并点击 Submit"
      : "正式门户 URL 尚未公布，已打开 ENISA SRP 官方信息页",
  );
}

async function recordSubmission() {
  if (!state.currentCase) return;
  try {
    state.currentCase = await api(`/api/art14/cases/${state.currentCase.id}/submission`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        reviewer_id: elements.submissionReviewer.value,
        pin: elements.submissionPin.value,
        stage: elements.submissionStage.value,
        submitted_at: toIsoOrNull(elements.submissionAt.value),
        receipt: elements.submissionReceipt.value.trim(),
      }),
    });
    elements.submissionPin.value = "";
    await loadArt14Workspace(true);
    renderArt14Case();
    showToast("SRP 手工提交回执已登记");
  } catch (error) {
    showToast(error.message, "error");
  }
}

const SYNC_STAGE_LABELS = {
  acquire_lock: "获取同步锁",
  sync_incremental: "增量同步漏洞数据",
  sync_reference: "刷新 CVE/KEV 参考数据",
  build_snapshot: "重建消费者快照",
  done: "完成",
  watch_loop: "编排器循环",
};

function renderSyncProgress(status) {
  const strip = elements.feedSnapshotStatus;
  if (!strip) return;
  const state = status.state || "idle";
  const stageLabel = SYNC_STAGE_LABELS[status.stage] || status.stage || "";
  if (state === "idle" && !status.orchestrator_available) {
    strip.innerHTML = `<div class="muted">编排器未运行（需启动 mirror_ops.py watch）。点击“一键更新 EUVD”会写入请求，待编排器启动后自动执行。</div>`;
    return;
  }
  if (state === "idle") {
    strip.innerHTML = `<div class="muted">空闲。点击“一键更新 EUVD”请求同步。</div>`;
    return;
  }
  if (state === "running") {
    strip.innerHTML = `<div><span class="status-dot online"></span> 同步中：${escapeHtml(stageLabel)}…</div>`;
    return;
  }
  if (state === "completed") {
    strip.innerHTML = `<div><span class="status-dot online"></span> 已更新到 ${escapeHtml(status.last_successful_to_date || "最新")}（${formatNumber(status.vulnerability_count || 0)} 漏洞）</div>`;
    return;
  }
  if (state === "failed") {
    strip.innerHTML = `<div><span class="status-dot offline"></span> 同步失败：${escapeHtml(status.error || "未知错误")}</div>`;
  }
}

function sleep(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function pollSyncStatus() {
  while (true) {
    let status;
    try {
      status = await api("/api/euvd/sync-status");
    } catch {
      await sleep(2000);
      continue;
    }
    renderSyncProgress(status);
    if (status.state === "completed") return status;
    if (status.state === "failed") {
      throw new Error(status.error || "同步失败");
    }
    await sleep(1500);
  }
}

async function refreshFeeds() {
  elements.refreshFeedsButton.disabled = true;
  try {
    await api("/api/euvd/sync-request", { method: "POST" });
    showToast("已请求一键更新，等待编排器执行…", "info");
    const status = await pollSyncStatus();
    await checkEuvd();
    await loadArt14Workspace(true);
    showToast(
      `EUVD 已更新到 ${status.last_successful_to_date || "最新"}（${formatNumber(status.vulnerability_count || 0)} 漏洞）`,
      "success",
    );
  } catch (error) {
    showToast(error.message, "error");
    try {
      renderSyncProgress(await api("/api/euvd/sync-status"));
    } catch {
      /* ignore */
    }
  } finally {
    elements.refreshFeedsButton.disabled = false;
  }
}

elements.navItems.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});
document.querySelectorAll(".view-import-button").forEach((button) => {
  button.addEventListener("click", () => showView("importView"));
});
document.getElementById("headerImportButton").addEventListener("click", () => showView("importView"));
document.querySelectorAll("[data-view-link]").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.viewLink));
});

elements.projectSearch.addEventListener("input", (event) => {
  state.projectSearch = event.target.value;
  renderProjects();
});
elements.componentSearch.addEventListener("input", (event) => {
  state.componentSearch = event.target.value;
  renderComponents();
});
elements.vulnerabilitySearch.addEventListener("input", (event) => {
  state.vulnerabilitySearch = event.target.value;
  renderVulnerabilities();
});
document.querySelectorAll("[data-catalog-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    state.vulnerabilityFilter = button.dataset.catalogFilter;
    document.querySelectorAll("[data-catalog-filter]").forEach((item) => {
      item.classList.toggle("active", item === button);
      item.setAttribute("aria-pressed", String(item === button));
    });
    renderVulnerabilities();
  });
});

elements.fileInput.addEventListener("change", (event) => uploadFile(event.target.files[0]));
[
  [elements.dropZone, elements.fileInput],
  [elements.receiptZone, elements.receiptInput],
].forEach(
  ([zone, input]) => {
    zone.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        input.click();
      }
    });
  },
);
elements.dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  elements.dropZone.classList.add("dragging");
});
elements.dropZone.addEventListener("dragleave", () => {
  elements.dropZone.classList.remove("dragging");
});
elements.dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  elements.dropZone.classList.remove("dragging");
  uploadFile(event.dataTransfer.files[0]);
});
elements.replaceFileButton.addEventListener("click", () => resetImport({ keepMetadata: true }));
elements.startMatchButton.addEventListener("click", startMatch);
elements.backToProjectsButton.addEventListener("click", () => showView("projectsView"));
elements.rescanButton.addEventListener("click", () => {
  if (state.job) {
    elements.projectName.value = state.job.project_name || "";
    elements.projectVersion.value = state.job.project_version || "";
    elements.softwareBuild.value = state.job.software_build || "";
    elements.customerName.value = state.job.customer || "";
  }
  resetImport({ keepMetadata: true });
  showView("importView");
});
elements.projectDetailSearch.addEventListener("input", (event) => {
  state.projectDetailSearch = event.target.value;
  renderProjectDetail();
});
document.querySelectorAll("[data-detail-tab]").forEach((button) => {
  button.addEventListener("click", () => {
    state.detailTab = button.dataset.detailTab;
    document.querySelectorAll("[data-detail-tab]").forEach((item) => {
      item.classList.toggle("active", item === button);
      item.setAttribute("aria-pressed", String(item === button));
    });
    renderProjectDetail();
  });
});

elements.createManualCaseButton.addEventListener("click", createManualCase);
elements.importVexButton.addEventListener("click", importVex);
elements.createReviewerButton.addEventListener("click", createReviewer);
elements.refreshFeedsButton.addEventListener("click", refreshFeeds);
elements.euvdCatalogSearch.addEventListener("input", onEuvdCatalogSearchInput);
elements.euvdCatalogSort.addEventListener("change", () => {
  state.euvdCatalog.sort = elements.euvdCatalogSort.value;
  state.euvdCatalog.page = 1;
  state.euvdCatalog.loaded = false;
  loadEuvdCatalog(true);
});
elements.euvdCatalogActivelyExploited.addEventListener("change", () => {
  state.euvdCatalog.actively_exploited_only = elements.euvdCatalogActivelyExploited.checked;
  state.euvdCatalog.page = 1;
  state.euvdCatalog.loaded = false;
  loadEuvdCatalog(true);
});
elements.euvdCatalogPrev.addEventListener("click", () => {
  if (state.euvdCatalog.page > 1) {
    state.euvdCatalog.page -= 1;
    state.euvdCatalog.loaded = false;
    loadEuvdCatalog(true);
  }
});
elements.euvdCatalogNext.addEventListener("click", () => {
  state.euvdCatalog.page += 1;
  state.euvdCatalog.loaded = false;
  loadEuvdCatalog(true);
});
elements.closeCaseDetailButton.addEventListener("click", () => {
  state.currentCase = null;
  elements.art14CaseDetail.classList.add("hidden");
});
elements.saveCaseAnalysisButton.addEventListener("click", saveCaseAnalysis);
elements.addEvidenceButton.addEventListener("click", addCaseEvidence);
elements.confirmAwarenessButton.addEventListener("click", confirmCaseAwareness);
elements.recordReviewButton.addEventListener("click", recordCaseReview);
elements.saveSrpFieldsButton.addEventListener("click", saveSrpFields);
elements.downloadSrpPackageButton.addEventListener("click", downloadSrpSubmissionPackage);
elements.srpPackageStage.addEventListener("change", () => {
  elements.srpHumanConfirmation.checked = false;
  updateSrpAssistanceControls();
});
elements.srpHumanConfirmation.addEventListener("change", updateSrpAssistanceControls);
elements.openSrpPortalButton.addEventListener("click", openOfficialSrp);
elements.recordSubmissionButton.addEventListener("click", recordSubmission);
elements.reviewStage.addEventListener("change", () => {
  const role = elements.reviewStage.value;
  const eligible = state.reviewers.filter((item) =>
    role === "technical"
      ? ["technical", "manufacturer_authorized"].includes(item.role)
      : ["compliance", "manufacturer_authorized"].includes(item.role),
  );
  elements.reviewIdentity.innerHTML =
    eligible
      .map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.display_name)} · ${escapeHtml(item.role)}</option>`)
      .join("") || '<option value="">无合适审批身份</option>';
});

initIcons();
pollOpsAlerts();
window.setInterval(pollOpsAlerts, 60000);
Promise.all([checkEuvd(), loadDashboard(), loadProjects()]);
