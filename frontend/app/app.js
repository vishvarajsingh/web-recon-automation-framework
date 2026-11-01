const apiBase = "/web-api";
const state = { investigationId: null, timer: null, copyTimer: null, lastTarget: "" };
const scanWords = ["SCANNING TARGET", "ANALYZING", "RECON", "COLLECTING DATA"];
const awarenessLines = [
  "Public evidence only. No intrusive requests.",
  "Passive collection keeps the target untouched.",
  "Headers and certificates reveal the public surface.",
  "DNS is evidence. Context turns it into insight.",
];
const $ = (id) => document.getElementById(id);

function request(path, options = {}) {
  return fetch(`${apiBase}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  }).then(async (response) => {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
    return body;
  });
}

function openReport(path, mimeType) {
  const url = `${apiBase}${path}`;
  if (mimeType === "text/html") {
    window.open(url, "_blank", "noopener");
    return;
  }
  window.location.assign(url);
}

function setMessage(message, isError = true) {
  const formMessage = $("form-message");
  formMessage.textContent = message || "";
  formMessage.classList.toggle("is-error", isError && Boolean(message));
}

function showError(message) {
  $("progress-panel").classList.add("hidden");
  $("dashboard").classList.add("hidden");
  $("error-state").classList.remove("hidden");
  $("error-message").textContent = message || "The scan could not be completed.";
  $("scan-button").disabled = false;
}

function setProgress(investigation) {
  const progress = Math.max(0, Math.min(100, Number(investigation.progress) || 0));
  $("progress-status").textContent = normalizeText(investigation.status, "queued").toUpperCase();
  $("progress-percent").textContent = `${progress}%`;
  $("progress-bar").style.width = `${progress}%`;
  $("progress-message").textContent = investigation.progress_message || awarenessLines[0];
}

function startScanCopy() {
  stopScanCopy();
  let index = 0;
  state.copyTimer = setInterval(() => {
    $("scan-word").textContent = scanWords[index % scanWords.length];
    $("progress-message").textContent = awarenessLines[index % awarenessLines.length];
    index += 1;
  }, 1800);
}

function stopScanCopy() {
  if (state.copyTimer) clearInterval(state.copyTimer);
  state.copyTimer = null;
}

function makeFile(label, tag, data, icon) {
  return { label, tag, data, icon, available: data !== undefined && data !== null };
}

function escapeHtml(input) {
  return String(input ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function displayValue(input) {
  if (input === null || input === undefined || input === "") return "Not reported";
  if (Array.isArray(input)) return input.length ? input.join(", ") : "None reported";
  if (typeof input === "object") return JSON.stringify(input, null, 2);
  return String(input);
}

function formatDate(value) {
  if (!value) return "Not reported";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-US", { year: "numeric", month: "short", day: "numeric" }).format(parsed);
}

function normalizeText(value, fallback = "Not reported") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function severityClass(value) {
  const label = String(value || "Informational").toLowerCase();
  if (label.includes("critical")) return "severity-critical";
  if (label.includes("high")) return "severity-high";
  if (label.includes("medium")) return "severity-medium";
  if (label.includes("low")) return "severity-low";
  return "severity-informational";
}

function safeArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null || value === "") return [];
  return [value];
}

function renderSummaryBadge(label, tone = "neutral") {
  return `<span class="summary-badge ${tone}">${escapeHtml(label)}</span>`;
}

function copyToClipboard(text, trigger) {
  if (!text || !navigator.clipboard) {
    if (trigger) trigger.textContent = "Copy unavailable";
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    if (trigger) {
      const original = trigger.textContent;
      trigger.textContent = "Copied";
      setTimeout(() => { trigger.textContent = original; }, 1200);
    }
  }).catch(() => {
    if (trigger) trigger.textContent = "Copy failed";
  });
}

function summarizeFile(file) {
  const data = file.data;
  const label = file.label;

  if (label === "DNS / IP") {
    const dnsData = data?.dns || {};
    const ipData = data?.ip || {};
    const dnsRecords = Object.keys(dnsData.records || {}).length || 0;
    const resolvedIps = Array.isArray(ipData.ipv4) ? ipData.ipv4.length : 0;
    return `DNS records: ${dnsRecords} · Resolved IPs: ${resolvedIps}`;
  }

  if (label === "HTTP") {
    const statusCode = data?.status_code ?? "n/a";
    const redirected = Array.isArray(data?.redirect_chain) ? data.redirect_chain.length : 0;
    return `Response: ${statusCode} · Redirects: ${redirected}`;
  }

  if (label === "SSL / TLS") {
    return `Certificate: ${data?.status === "ok" ? "Valid" : "Unavailable"}`;
  }

  if (label === "TECHNOLOGIES") {
    const list = Array.isArray(data?.technologies) ? data.technologies : (Array.isArray(data) ? data : []);
    return `Detected: ${list.length}`;
  }

  if (label === "SECURITY HEADERS") {
    const headers = data?.headers || {};
    const present = Object.values(headers).filter((value) => String(value || "").trim()).length;
    const missing = Object.keys(headers).length - present;
    return `Present: ${present} · Missing: ${missing}`;
  }

  if (label === "EXPOSURES") {
    const findings = Array.isArray(data?.findings) ? data.findings : [];
    const highest = findings.reduce((best, finding) => {
      const current = ["Critical", "High", "Medium", "Low", "Informational"].indexOf(finding.severity || "Informational");
      return current > best ? current : best;
    }, -1);
    const labelValue = highest >= 0 ? ["Critical", "High", "Medium", "Low", "Informational"][highest] : "None";
    return `Resources: ${findings.length} · Highest: ${labelValue}`;
  }

  if (label === "RISK / SEVERITY") {
    const score = Number(data?.risk?.overall_score ?? data?.summary?.overall_score ?? 0);
    const rating = data?.risk?.overall_rating || data?.summary?.overall_score || "Unknown";
    return `Score: ${score}/100 · ${rating}`;
  }

  if (label === "REPORTS") {
    const paths = data || {};
    const jsonStatus = paths.json ? "JSON ready" : "Unavailable";
    const htmlStatus = paths.html ? "HTML ready" : "Unavailable";
    return `${jsonStatus} · ${htmlStatus}`;
  }

  return "Details available";
}

function renderKeyValueList(rows) {
  return `<dl class="detail-list">${rows.map(([label, value]) => {
    const rawValue = String(value ?? "");
    const shouldCopy = ["Final URL", "Resource", "Evidence", "Resolved IPv4", "Resolved IPv6", "Reverse DNS", "Value", "URL"].includes(label) || /https?:\/\//.test(rawValue) || /\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(rawValue);
    const copyMarkup = shouldCopy ? `<button class="copy-inline" type="button" data-copy="${escapeHtml(rawValue)}">Copy</button>` : "";
    return `<div class="detail-row"><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(rawValue)}${copyMarkup}</dd></div>`;
  }).join("")}</dl>`;
}

function attachCopyControls() {
  document.querySelectorAll(".copy-inline").forEach((button) => {
    button.addEventListener("click", () => {
      const value = button.dataset.copy || "";
      copyToClipboard(value, button);
    });
  });
}

function renderDetailBody(fileLabel, data, investigation) {
  if (fileLabel === "EXPOSURES") {
    const findings = Array.isArray(data?.findings) ? data.findings : [];
    const summary = data?.summary || {};
    const totalResources = summary.total_exposed_resources ?? findings.length ?? 0;
    const counts = summary.severity_counts || {};

    if (!findings.length) {
      return `
        <div class="detail-section">
          <div class="detail-header-row">
            <div class="detail-kicker">Exposure Analysis</div>
            <span class="detail-status positive">Status: No exposed resources identified</span>
          </div>
          <div class="empty-state">
            <div class="empty-state-icon">◎</div>
            <h4>Exposure Analysis</h4>
            <p class="empty-state-primary">Status: No exposed resources identified</p>
            <div class="empty-metrics">
              <div><span>Resources discovered</span><strong>${totalResources}</strong></div>
              <div><span>Critical findings</span><strong>${counts.Critical ?? 0}</strong></div>
              <div><span>High findings</span><strong>${counts.High ?? 0}</strong></div>
              <div><span>Medium findings</span><strong>${counts.Medium ?? 0}</strong></div>
              <div><span>Low findings</span><strong>${counts.Low ?? 0}</strong></div>
              <div><span>Informational findings</span><strong>${counts.Informational ?? 0}</strong></div>
            </div>
            <p class="empty-state-note">No potentially exposed resources were identified by the current reconnaissance checks. This does not guarantee that the target is free of security vulnerabilities.</p>
          </div>
        </div>
      `;
    }

    const findingCards = findings.map((finding) => {
      const severity = normalizeText(finding.severity || "Informational");
      const resource = normalizeText(finding.resource || finding.url || finding.path || "Not reported");
      const source = normalizeText(finding.source || finding.category || "Passive evidence");
      const evidence = normalizeText(finding.evidence || "No specific evidence was recorded.");
      const reason = normalizeText(finding.reason || "This observation may warrant manual verification and review.");
      const recommendation = normalizeText(finding.recommendation || "Review the exposed resource and confirm the appropriate access controls are in place.");
      const statusCode = finding.status_code ? `HTTP Status: ${finding.status_code}` : "HTTP Status: Not reported";

      return `
        <article class="finding-card">
          <div class="finding-header">
            <div>
              <p class="detail-kicker">Exposure Finding</p>
              <h4>${escapeHtml(finding.title || "Exposure Finding")}</h4>
            </div>
            <span class="severity-badge ${severityClass(severity)}">${escapeHtml(severity)}</span>
          </div>
          <div class="finding-meta">
            <div><span>Resource</span><strong>${escapeHtml(resource)}</strong>${resource !== "Not reported" ? `<button class="copy-inline" type="button" data-copy="${escapeHtml(resource)}">Copy</button>` : ""}</div>
            <div><span>Discovered through</span><strong>${escapeHtml(source)}</strong></div>
            <div><span>HTTP Status</span><strong>${escapeHtml(statusCode.replace("HTTP Status: ", ""))}</strong></div>
          </div>
          <div class="finding-section">
            <h5>Evidence</h5>
            <p>${escapeHtml(evidence)}</p>
            ${evidence !== "No specific evidence was recorded." ? `<button class="copy-inline evidence-copy" type="button" data-copy="${escapeHtml(evidence)}">Copy evidence</button>` : ""}
          </div>
          <div class="finding-section">
            <h5>Why it matters</h5>
            <p>${escapeHtml(reason)}</p>
          </div>
          <div class="finding-section">
            <h5>Recommended action</h5>
            <p>${escapeHtml(recommendation)}</p>
          </div>
        </article>
      `;
    }).join("");

    return `
      <div class="detail-section">
        <div class="detail-header-row">
          <div class="detail-kicker">Exposure Findings</div>
          <span class="detail-status warning">Resources discovered: ${totalResources}</span>
        </div>
        <div class="finding-stack">${findingCards}</div>
      </div>
    `;
  }

  if (fileLabel === "SECURITY HEADERS") {
    const headers = data?.headers || {};
    const headerDefs = {
      "Content-Security-Policy": { help: "Reduces injection and code execution risks by constraining where scripts, styles, and assets may load from." },
      "Strict-Transport-Security": { help: "Forces HTTPS and prevents downgrade or cookie hijacking on insecure connections." },
      "X-Frame-Options": { help: "Protects against clickjacking by restricting embedding in frames or iframes." },
      "X-Content-Type-Options": { help: "Prevents browsers from sniffing MIME types and interpreting files incorrectly." },
      "Referrer-Policy": { help: "Controls how much referrer information is exposed to other sites." },
    };

    const rows = Object.entries(headerDefs).map(([header, meta]) => {
      const key = header.toLowerCase().replace(/[^a-z]/g, "_");
      const value = headers[key] || headers[header.toLowerCase().replace(/-/g, "_")] || "";
      const status = value && String(value).trim() ? "Present" : "Missing";
      return `<tr><td>${escapeHtml(header)}</td><td><span class="status-pill ${status === "Present" ? "present" : "missing"}">${escapeHtml(status)}</span></td><td>${escapeHtml(meta.help)}</td></tr>`;
    });

    return `
      <div class="detail-section">
        <div class="detail-header-row">
          <div class="detail-kicker">Security Headers</div>
          <span class="detail-status ${Object.values(headers).some((value) => String(value || "").trim()) ? "positive" : "neutral"}">${Object.keys(headers).length ? "Headers checked" : "No header data collected"}</span>
        </div>
        <div class="table-wrap">
          <table class="detail-table">
            <thead><tr><th>Header</th><th>Status</th><th>Explanation</th></tr></thead>
            <tbody>${rows.join("")}</tbody>
          </table>
        </div>
      </div>
    `;
  }

  if (fileLabel === "DNS / IP") {
    const dns = data?.dns || {};
    const ip = data?.ip || {};
    const dnsRows = Object.entries(dns.records || {}).map(([recordType, record]) => {
      const normalized = record && typeof record === "object" ? record : {};
      const value = Array.isArray(normalized.values) ? normalized.values.join(", ") : (
        normalized.status === "nxdomain" ? "No record returned" : (
          normalized.status === "no_answer" ? "No answer" : normalizeText(normalized.error || normalized.status || "Not checked")
        )
      );
      return `<tr><td>${escapeHtml(recordType)}</td><td>${escapeHtml(value)}</td><td>${escapeHtml(normalized.ttl ?? "Not available")}</td></tr>`;
    }).join("");

    const ipv4 = safeArray(ip.ipv4).map((item) => escapeHtml(String(item))).join(", ") || "No IPv4 addresses returned";
    const ipv6 = safeArray(ip.ipv6).map((item) => escapeHtml(String(item))).join(", ") || "No IPv6 addresses returned";
    const reverseDns = safeArray(ip.reverse_dns).map((item) => escapeHtml(String(item))).join(", ") || "No reverse DNS result";

    return `
      <div class="detail-section">
        <div class="detail-header-row"><div class="detail-kicker">DNS and IP Overview</div><span class="detail-status ${dns.status === "failed" ? "negative" : "positive"}">${escapeHtml(normalizeText(dns.status, "Not checked"))}</span></div>
        <div class="table-wrap"><table class="detail-table"><thead><tr><th>Record Type</th><th>Value</th><th>TTL</th></tr></thead><tbody>${dnsRows || `<tr><td colspan="3">DNS lookup failed: no result was returned.</td></tr>`}</tbody></table></div>
        <div class="detail-grid two-up">
          <div class="detail-box"><h5>Resolved IPv4</h5><p>${ipv4}</p></div>
          <div class="detail-box"><h5>Resolved IPv6</h5><p>${ipv6}</p></div>
          <div class="detail-box full"><h5>Reverse DNS</h5><p>${reverseDns}</p></div>
        </div>
      </div>
    `;
  }

  if (fileLabel === "HTTP") {
    const http = data || {};
    const issue = http.status === "error" || http.status === "failed" ? "negative" : "positive";
    const rows = [
      ["HTTP status", http.status_code ?? "Not reported"],
      ["Final URL", http.final_url || "Not reported"],
      ["Server header", http.server || "Not reported"],
      ["Content type", http.content_type || "Not reported"],
      ["Redirect chain", Array.isArray(http.redirect_chain) && http.redirect_chain.length ? http.redirect_chain.join(" → ") : "No redirects detected"],
    ];
    return `
      <div class="detail-section">
        <div class="detail-header-row"><div class="detail-kicker">HTTP Response</div><span class="detail-status ${issue}">${escapeHtml(normalizeText(http.status, "Not checked"))}</span></div>
        ${renderKeyValueList(rows)}
      </div>
    `;
  }

  if (fileLabel === "SSL / TLS") {
    const ssl = data || {};
    const status = ssl.status === "ok" ? "Certificate valid" : (ssl.status === "not_https" ? "Not HTTPS" : "Certificate details unavailable");
    if (ssl.status !== "ok") {
      return `
        <div class="detail-section">
          <div class="detail-header-row"><div class="detail-kicker">SSL / TLS</div><span class="detail-status negative">${escapeHtml(status)}</span></div>
          <p class="empty-state-note">Certificate details could not be retrieved. Check connectivity and try again.</p>
          <p class="empty-state-note">${escapeHtml(normalizeText(ssl.error || "No certificate data was returned.", "No certificate data was returned."))}</p>
        </div>
      `;
    }
    return `
      <div class="detail-section">
        <div class="detail-header-row"><div class="detail-kicker">SSL / TLS Certificate</div><span class="detail-status ${ssl.expired ? "negative" : "positive"}">${ssl.expired ? "Expired" : "Valid"}</span></div>
        ${renderKeyValueList([
          ["Issuer", ssl.issuer || "Not reported"],
          ["Subject", ssl.subject || "Not reported"],
          ["Valid from", formatDate(ssl.valid_from)],
          ["Expiry date", formatDate(ssl.valid_until)],
          ["Days remaining", ssl.days_remaining ?? "Not calculated"],
          ["SANs", Array.isArray(ssl.san_entries) && ssl.san_entries.length ? ssl.san_entries.join(", ") : "No SAN entries returned"],
        ])}
      </div>
    `;
  }

  if (fileLabel === "TECHNOLOGIES") {
    const list = Array.isArray(data?.technologies) ? data.technologies : (Array.isArray(data) ? data : []);
    return `
      <div class="detail-section">
        <div class="detail-header-row"><div class="detail-kicker">Technology Fingerprint</div><span class="detail-status ${list.length ? "positive" : "neutral"}">${list.length ? `${list.length} technologies detected` : "No technologies identified"}</span></div>
        <div class="tag-list">${list.length ? list.map((item) => `<span class="tag">${escapeHtml(String(item))}</span>`).join("") : `<span class="tag neutral">No technology fingerprints were collected.</span>`}</div>
      </div>
    `;
  }

  if (fileLabel === "RISK / SEVERITY") {
    const risk = data?.risk || {};
    const summary = data?.summary || {};
    const score = Number(risk.overall_score ?? summary.overall_score ?? 0);
    const rating = risk.overall_rating || summary.overall_score || "Unknown";
    const exposureRisk = summary.overall_score || "Informational";
    return `
      <div class="detail-section">
        <div class="detail-header-row"><div class="detail-kicker">Risk and Severity</div><span class="detail-status ${score >= 70 ? "negative" : score >= 40 ? "warning" : "positive"}">${escapeHtml(rating)}</span></div>
        <div class="score-panel">
          <div class="score-block">
            <p>Security score</p>
            <strong>${score} / 100</strong>
          </div>
          <div class="progress-track compact"><div style="width:${Math.min(score, 100)}%"></div></div>
          <div class="score-meta">
            <span>Risk level: ${escapeHtml(rating)}</span>
            <span>Exposure risk: ${escapeHtml(exposureRisk)}</span>
          </div>
        </div>
        <p class="empty-state-note">This score is based on passive evidence and should be treated as a risk indicator, not a guarantee of exploitability. Low scores do not mean the site is secure; they simply indicate less public evidence of risk from the current checks.</p>
      </div>
    `;
  }

  if (fileLabel === "REPORTS") {
    const reportSummary = investigation.raw_output || {};
    const summaryLines = [
      ["HTML report", reportSummary.report_paths?.html ? "Available" : "Unavailable"],
      ["JSON report", reportSummary.report_paths?.json ? "Available" : "Unavailable"],
      ["Target", investigation.target || "Not reported"],
      ["Status", investigation.status || "Unknown"],
    ];
    return `
      <div class="detail-section">
        <div class="detail-header-row"><div class="detail-kicker">Reports</div><span class="detail-status positive">Available for review</span></div>
        ${renderKeyValueList(summaryLines)}
        <div class="report-actions"><button id="open-json" type="button">Open JSON report</button><button id="open-html" type="button">Open HTML report</button></div>
      </div>
    `;
  }

  return `
    <div class="detail-section">
      <div class="detail-header-row"><div class="detail-kicker">Result Overview</div></div>
      ${renderKeyValueList(Object.entries(data || {}).slice(0, 10).map(([key, value]) => [key, displayValue(value)]))}
    </div>
  `;
}

function renderDetail(file, investigation) {
  if (!file) return;
  $("detail-panel").classList.remove("hidden");
  $("detail-title").textContent = file.label;
  const rawData = JSON.stringify(file.data, null, 2);
  let content = renderDetailBody(file.label, file.data, investigation);
  if (file.label === "REPORTS") {
    $("detail-content").innerHTML = content;
    setTimeout(() => {
      $("open-json").onclick = () => openReport(`/investigations/${investigation.id}/report/download`, "application/json");
      $("open-html").onclick = () => openReport(`/investigations/${investigation.id}/report/html`, "text/html");
    }, 0);
  } else {
    $("detail-content").innerHTML = `${content}<details class="raw-data"><summary>View Raw Data</summary><pre class="detail-body">${escapeHtml(rawData)}</pre></details>`;
    attachCopyControls();
  }
  document.querySelectorAll(".file-card").forEach((card) => card.classList.toggle("active", card.dataset.label === file.label));
  $("detail-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderResults(investigation) {
  const report = investigation.raw_output || {};
  const modules = report.modules || {};
  const exposure = report.exposure || {};
  const summary = exposure.summary || {};
  const risk = report.risk || {};
  const files = [
    makeFile("DNS / IP", "NETWORK", { dns: modules.dns || {}, ip: modules.ip || {} }, "⌁"),
    makeFile("HTTP", "RESPONSE", modules.http, "↗"),
    makeFile("SSL / TLS", "CERTIFICATE", modules.ssl, "◇"),
    makeFile("TECHNOLOGIES", "FINGERPRINT", modules.technology, "#"),
    makeFile("SECURITY HEADERS", "HARDENING", modules.security_headers, "//"),
    makeFile("EXPOSURES", "FINDINGS", exposure, "!"),
    makeFile("RISK / SEVERITY", "ANALYSIS", { risk, summary }, "△"),
    makeFile("REPORTS", "GENERATED", report.report_paths || investigation, "▤"),
  ].filter((file) => file.available);

  const score = Number(risk.overall_score ?? report.risk_summary?.security_score?.split("/")[0] ?? 0);
  const rating = risk.overall_rating || report.risk_summary?.security_risk || "Unknown";
  const exposureRisk = summary.overall_score || report.risk_summary?.exposure_risk || "Informational";
  const htmlReportAvailable = Boolean(investigation.html_report_location || report.report_paths?.html);

  $("dashboard").classList.remove("hidden");
  $("progress-panel").classList.add("hidden");
  $("result-target").textContent = investigation.target;
  $("result-time").textContent = `${report.normalized_target?.hostname || ""} · ${investigation.status}`;
  $("risk-chip").textContent = `${rating} RISK · ${score}/100`;
  $("view-html-report").classList.toggle("hidden", !htmlReportAvailable);
  $("view-html-report").onclick = () => openReport(`/investigations/${investigation.id}/report/html`, "text/html");
  $("file-count").textContent = `${files.length} evidence files`;
  $("result-metrics").innerHTML = `
    <div class="metric-card"><span>Security score</span><strong>${score} / 100</strong><small>${rating}</small></div>
    <div class="metric-card"><span>Exposure risk</span><strong>${escapeHtml(exposureRisk)}</strong><small>${summary.total_exposed_resources ?? 0} resources</small></div>
    <div class="metric-card"><span>Findings</span><strong>${summary.total_exposed_resources ?? 0}</strong><small>${summary.medium_findings ?? 0} medium</small></div>
  `;
  $("file-grid").innerHTML = files.map((file) => `<button class="file-card" type="button" data-label="${escapeHtml(file.label)}"><span class="file-icon">${escapeHtml(file.icon)}</span><strong>${escapeHtml(file.label)}</strong><small>${escapeHtml(file.tag)}</small><span class="file-summary">${escapeHtml(summarizeFile(file))}</span></button>`).join("");
  document.querySelectorAll(".file-card").forEach((card) => card.addEventListener("click", () => renderDetail(files.find((file) => file.label === card.dataset.label), investigation)));
  $("folder-files").classList.add("hidden");
  $("folder-toggle").setAttribute("aria-expanded", "false");
  $("folder-toggle").querySelector("i").textContent = "OPEN";
  $("detail-panel").classList.add("hidden");
}

async function pollInvestigation() {
  try {
    const investigation = await request(`/investigations/${state.investigationId}`);
    setProgress(investigation);
    if (["completed", "failed"].includes(investigation.status)) {
      clearInterval(state.timer);
      stopScanCopy();
      if (investigation.status === "completed" && investigation.raw_output) {
        if (investigation.html_report_location || investigation.raw_output.report_paths?.html) {
          window.location.assign(`${apiBase}/investigations/${investigation.id}/report/html`);
          return;
        }
        renderResults(investigation);
        setMessage("Recon complete. HTML report is unavailable; review the results below.", false);
      } else {
        showError(investigation.progress_message || "The passive scan failed without a result.");
      }
    }
  } catch (error) {
    clearInterval(state.timer);
    showError(error.message);
  }
}

$("folder-toggle").addEventListener("click", () => {
  const open = !$("folder-files").classList.contains("hidden");
  $("folder-files").classList.toggle("hidden", open);
  $("folder-toggle").setAttribute("aria-expanded", String(!open));
  $("folder-toggle").querySelector("i").textContent = open ? "OPEN" : "CLOSE";
});
$("detail-close").addEventListener("click", () => $("detail-panel").classList.add("hidden"));

async function submitScan() {
  const target = $("target").value.trim();
  if (!target) return;
  if (state.timer) clearInterval(state.timer);
  $("scan-button").disabled = true;
  $("dashboard").classList.add("hidden");
  $("error-state").classList.add("hidden");
  setMessage("Submitting target for passive analysis...", false);
  $("progress-panel").classList.remove("hidden");
  startScanCopy();
  try {
    const investigation = await request("/investigations/", { method: "POST", body: JSON.stringify({ target }) });
    state.lastTarget = target;
    state.investigationId = investigation.id;
    setProgress(investigation);
    state.timer = setInterval(pollInvestigation, 1200);
    await pollInvestigation();
  } catch (error) {
    showError(error.message);
    setMessage(error.message);
  }
}

$("scan-form").addEventListener("submit", (event) => { event.preventDefault(); submitScan(); });
$("retry-button").addEventListener("click", () => { $("target").value = state.lastTarget || $("target").value; submitScan(); });
fetch("/health/db").then((response) => response.json()).then((health) => { $("health").textContent = health.status === "ok" ? "SERVICE ONLINE" : "DATABASE UNAVAILABLE"; }).catch(() => { $("health").textContent = "SERVICE OFFLINE"; });
