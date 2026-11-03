const apiBase = "/web-api";
const state = { investigationId: null, timer: null, copyTimer: null, lastTarget: "", assetId: null, assetSkip: 0, assetTotal: 0, assetLimit: 50, historySkip: 0, historyTotal: 0, historyLimit: 10, availableScans: new Map() };
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

function prettyValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

async function loadAssets(preferredId = state.assetId, skip = state.assetSkip) {
  const stateNode = $("asset-state");
  try {
    state.assetSkip = Math.max(0, skip);
    const result = await request(`/assets?skip=${state.assetSkip}&limit=${state.assetLimit}`);
    const items = Array.isArray(result.items) ? result.items : [];
    state.assetTotal = result.total;
    if (!items.length) {
      $("asset-controls").classList.add("hidden");
      stateNode.textContent = "No scans have been recorded yet. Run an authorized assessment to create the first asset history entry.";
      return;
    }
    $("asset-controls").classList.remove("hidden");
    stateNode.textContent = `${result.total} normalized asset${result.total === 1 ? "" : "s"} in inventory.`;
    $("asset-select").innerHTML = items.map((asset) => `<option value="${asset.id}">${escapeHtml(asset.canonical_target)} · ${asset.scan_count} scan${asset.scan_count === 1 ? "" : "s"}</option>`).join("");
    const chosen = items.some((asset) => asset.id === preferredId) ? preferredId : items[0].id;
    $("asset-select").value = String(chosen);
    state.assetId = Number(chosen);
    $("asset-page-label").textContent = `Assets ${state.assetSkip + 1}–${Math.min(state.assetSkip + items.length, state.assetTotal)} of ${state.assetTotal}`;
    $("asset-prev").disabled = state.assetSkip === 0;
    $("asset-next").disabled = state.assetSkip + state.assetLimit >= state.assetTotal;
    await loadAssetHistory(state.assetId, 0);
  } catch (error) {
    $("asset-controls").classList.add("hidden");
    stateNode.textContent = `Asset history unavailable: ${error.message}`;
  }
}

async function loadAssetHistory(assetId, skip = state.historySkip) {
  state.assetId = Number(assetId);
  state.historySkip = Math.max(0, skip);
  const output = await request(`/assets/${state.assetId}/investigations?skip=${state.historySkip}&limit=${state.historyLimit}`);
  state.historyTotal = output.total;
  $("asset-observation").innerHTML = `<span>FIRST SEEN<strong>${escapeHtml(formatDate(output.asset.first_seen_at))}</strong></span><span>LAST SEEN<strong>${escapeHtml(formatDate(output.asset.last_seen_at))}</strong></span><span>RECORDED SCANS<strong>${output.total}</strong></span>`;
  const scans = output.items || [];
  $("history-body").innerHTML = scans.length ? scans.map((scan) => {
    const points = scan.observed_risk_points ?? scan.risk_score;
    const interpretation = scan.risk_interpretation || "Unknown";
    return `<tr><td>#${scan.id}</td><td>${escapeHtml(scan.target)}</td><td>${escapeHtml(scan.status)}</td><td>${escapeHtml(interpretation)} ${points === null || points === undefined ? "" : `(${points} observed risk points)`} · ${escapeHtml(scan.risk_evidence_status || "unknown evidence")}</td><td>${escapeHtml(formatDate(scan.created_at))}</td><td>${scan.status === "completed" ? `<button type="button" class="history-detail" data-id="${scan.id}">View</button>` : "Not complete"}</td></tr>`;
  }).join("") : `<tr><td colspan="6">No investigations recorded for this asset.</td></tr>`;
  const completed = scans.filter((scan) => scan.status === "completed");
  completed.forEach((scan) => state.availableScans.set(scan.id, scan));
  const selectable = [...state.availableScans.values()].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const previousSelected = Number($("previous-scan").value);
  const currentSelected = Number($("current-scan").value);
  const options = selectable.map((scan) => `<option value="${scan.id}">#${scan.id} · ${escapeHtml(formatDate(scan.created_at))} · ${escapeHtml(scan.risk_rating || "Not scored")}</option>`).join("");
  $("previous-scan").innerHTML = options;
  $("current-scan").innerHTML = options;
  if (selectable.length > 1) {
    const ids = new Set(selectable.map((scan) => scan.id));
    $("previous-scan").value = String(ids.has(previousSelected) ? previousSelected : selectable[1].id);
    $("current-scan").value = String(ids.has(currentSelected) ? currentSelected : selectable[0].id);
  }
  $("compare-button").disabled = selectable.length < 2;
  $("compare-status").textContent = selectable.length < 2 ? "Two completed scans of this asset are needed. Browse more history pages to add older scans." : "Select two completed scans to review collected changes.";
  $("history-prev").disabled = state.historySkip === 0;
  $("history-next").disabled = state.historySkip + state.historyLimit >= state.historyTotal;
  document.querySelectorAll(".history-detail").forEach((button) => button.addEventListener("click", () => loadPastInvestigation(Number(button.dataset.id))));
  $("comparison-output").classList.add("hidden");
}

async function loadPastInvestigation(id) {
  try {
    const investigation = await request(`/investigations/${id}`);
    if (investigation.status !== "completed" || !investigation.raw_output) throw new Error("Completed scan evidence is unavailable.");
    renderResults(investigation);
    window.scrollTo({ top: $("dashboard").offsetTop, behavior: "smooth" });
  } catch (error) {
    setMessage(error.message);
  }
}

function renderComparison(result) {
  const summary = result.summary || {};
  const delta = result.risk?.delta;
  const deltaWidth = Number.isInteger(delta) ? Math.min(Math.abs(delta), 100) : 0;
  const groups = {};
  for (const change of result.changes || []) (groups[change.category] ||= []).push(change);
  const groupHtml = Object.entries(groups).map(([category, changes]) => `<section class="change-group"><h4>${escapeHtml(category)}</h4>${changes.map((change) => `<article class="change-card"><div class="change-heading"><span class="change-type ${escapeHtml(change.change_type.toLowerCase())}">${escapeHtml(change.change_type)}</span><strong>${escapeHtml(change.title)}</strong><small>${escapeHtml(change.confidence)} confidence</small></div><div class="change-values"><div><span>PREVIOUS</span><p>${escapeHtml(prettyValue(change.previous))}</p></div><div><span>CURRENT</span><p>${escapeHtml(prettyValue(change.current))}</p></div></div><details><summary>Supporting evidence</summary><pre>${escapeHtml(change.evidence || "No evidence provided")}</pre></details></article>`).join("")}</section>`).join("");
  $("comparison-output").innerHTML = `<div class="comparison-heading"><div><p class="eyebrow">EVIDENCE-BASED SCAN DIFF</p><h3>Comparison for ${escapeHtml(result.target)}</h3></div><button type="button" id="comparison-report">Open HTML comparison report</button></div><div class="diff-metrics">${["new", "changed", "resolved", "removed", "unchanged", "unknown"].map((key) => `<div><span>${key.toUpperCase()}</span><strong>${Number(summary[key] || 0)}</strong></div>`).join("")}</div><div class="risk-delta"><span>Observed risk points (higher = more risk): ${escapeHtml(String(result.risk?.previous_score ?? "—"))} → ${escapeHtml(String(result.risk?.current_score ?? "—"))}</span><strong class="${delta > 0 ? "up" : delta < 0 ? "down" : "flat"}">${Number.isInteger(delta) && delta > 0 ? "+" : ""}${escapeHtml(String(delta ?? "Unknown"))}</strong><div class="delta-track"><i style="width:${deltaWidth}%"></i></div><small>Point change, not a probability. Evidence: ${escapeHtml(result.risk?.evidence_status || "unknown")}.</small></div>${groupHtml || `<p class="empty-state-note">No comparable observations were returned.</p>`}`;
  $("comparison-output").classList.remove("hidden");
  $("comparison-report").onclick = () => window.open(`${apiBase}/investigations/${result.previous.id}/compare/${result.current.id}/report`, "_blank", "noopener");
}

async function compareSelectedScans() {
  const previousId = Number($("previous-scan").value);
  const currentId = Number($("current-scan").value);
  if (!previousId || !currentId || previousId === currentId) {
    $("compare-status").textContent = "Choose two different completed scans.";
    return;
  }
  $("compare-button").disabled = true;
  $("compare-status").textContent = "Comparing stored scan evidence...";
  try {
    const result = await request("/investigations/compare", { method: "POST", body: JSON.stringify({ previous_id: previousId, current_id: currentId }) });
    renderComparison(result);
    $("compare-status").textContent = "Comparison ready. Unknown entries reflect incomplete evidence.";
  } catch (error) {
    $("compare-status").textContent = `Comparison failed: ${error.message}`;
  } finally {
    $("compare-button").disabled = false;
  }
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
    return `Candidate URLs: ${data?.summary?.unique_candidate_urls ?? 0} · Observations: ${data?.summary?.heuristic_observations ?? findings.length} · Highest: ${labelValue}`;
  }

  if (label === "RISK / SEVERITY") {
    const value = data?.risk?.overall_score ?? data?.summary?.observed_risk_points;
    const score = value !== null && value !== undefined && Number.isFinite(Number(value)) ? Number(value) : null;
    const rating = data?.risk?.evidence_status === "complete" ? (data?.risk?.overall_rating || data?.summary?.risk_interpretation || "Unknown") : "Unknown";
    return `Observed risk points: ${score === null ? "Not calculated" : `${score}/100`} · ${rating}`;
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
    const candidateCount = summary.unique_candidate_urls ?? 0;
    const observationCount = summary.heuristic_observations ?? findings.length;
    const checkedCount = summary.http_checked_candidate_urls ?? 0;
    const counts = summary.severity_counts || {};

    if (!findings.length) {
      return `
        <div class="detail-section">
          <div class="detail-header-row">
            <div class="detail-kicker">Passive Exposure Observations</div>
            <span class="detail-status neutral">No heuristic observations returned</span>
          </div>
          <div class="empty-state">
            <div class="empty-state-icon">◎</div>
            <h4>Passive Exposure Observations</h4>
            <p class="empty-state-primary">No heuristic observations returned</p>
            <div class="empty-metrics">
              <div><span>Unique candidate URLs</span><strong>${candidateCount}</strong></div>
              <div><span>Candidate URLs with HTTP response evidence</span><strong>${checkedCount}</strong></div>
              <div><span>Confirmed misconfigurations</span><strong>Not assessed</strong></div>
              <div><span>Confirmed vulnerabilities</span><strong>Not assessed</strong></div>
              <div><span>Critical observations</span><strong>${counts.Critical ?? 0}</strong></div>
              <div><span>High observations</span><strong>${counts.High ?? 0}</strong></div>
              <div><span>Medium observations</span><strong>${counts.Medium ?? 0}</strong></div>
              <div><span>Low observations</span><strong>${counts.Low ?? 0}</strong></div>
              <div><span>Informational observations</span><strong>${counts.Informational ?? 0}</strong></div>
            </div>
            <p class="empty-state-note">Candidate references are not access checks. This framework does not confirm vulnerabilities.</p>
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
      const recommendation = normalizeText(finding.recommendation || "Review this observation and its collected evidence.");
      const statusCode = finding.status_code !== null && finding.status_code !== undefined
        ? `${finding.status_code}${finding.status_resource ? ` for ${finding.status_resource}` : " (resource attribution unavailable)"}`
        : "Not requested / no exact-resource response recorded";

      return `
        <article class="finding-card">
          <div class="finding-header">
            <div>
              <p class="detail-kicker">Heuristic Observation</p>
              <h4>${escapeHtml(finding.title || "Heuristic Observation")}</h4>
            </div>
            <span class="severity-badge ${severityClass(severity)}">${escapeHtml(severity)}</span>
          </div>
          <div class="finding-meta">
            <div><span>Referenced resource</span><strong>${escapeHtml(resource)}</strong>${resource !== "Not reported" ? `<button class="copy-inline" type="button" data-copy="${escapeHtml(resource)}">Copy</button>` : ""}</div>
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
          <div class="detail-kicker">Heuristic Observations</div>
          <span class="detail-status neutral">${observationCount} observations</span>
        </div>
        <p class="empty-state-note">Unique candidate URLs: ${candidateCount}. Exact-request HTTP responses: ${checkedCount}. Candidate references and heuristic observations do not confirm misconfigurations or vulnerabilities.</p>
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
    const list = Array.isArray(data?.detections) ? data.detections : (Array.isArray(data?.technologies) ? data.technologies.map((name) => ({ name, confidence: "Not reported", evidence: [] })) : (Array.isArray(data) ? data.map((name) => ({ name, confidence: "Not reported", evidence: [] })) : []));
    const state = data?.status || "unknown";
    const stateLabel = state === "identified" ? "Technology identified" : state === "no_match" || state === "ok" ? "No supported technology identified" : state === "incomplete" ? "Detection incomplete" : state === "failed" || state === "error" ? "Detection failed" : "Detection state unavailable";
    return `
      <div class="detail-section">
        <div class="detail-header-row"><div class="detail-kicker">Technology Fingerprint</div><span class="detail-status ${state === "identified" ? "positive" : "neutral"}">${escapeHtml(stateLabel)}</span></div>
        ${data?.message ? `<p class="empty-state-note">${escapeHtml(data.message)}</p>` : ""}
        <div class="finding-stack">${list.length ? list.map((item) => `<article class="finding-card"><h4>${escapeHtml(String(item.name))}</h4><p>Confidence: ${escapeHtml(item.confidence || "Not reported")}</p><pre>${escapeHtml(JSON.stringify(item.evidence || [], null, 2))}</pre></article>`).join("") : `<p class="empty-state-note">No supported technology fingerprint was collected.</p>`}</div>
      </div>
    `;
  }

  if (fileLabel === "RISK / SEVERITY") {
    const risk = data?.risk || {};
    const summary = data?.summary || {};
    const rawScore = risk.overall_score ?? summary.observed_risk_points;
    const score = rawScore !== null && rawScore !== undefined && Number.isFinite(Number(rawScore)) ? Number(rawScore) : null;
    const rating = risk.evidence_status === "complete" ? (risk.overall_rating || summary.risk_interpretation || "Unknown") : "Unknown";
    const exposureRisk = summary.observation_rating || "Not calculated";
    const evidenceStatus = risk.evidence_status || "unknown";
    return `
      <div class="detail-section">
        <div class="detail-header-row"><div class="detail-kicker">Risk Interpretation</div><span class="detail-status ${evidenceStatus !== "complete" || score === null ? "neutral" : score >= 40 ? "negative" : score >= 20 ? "warning" : "positive"}">${escapeHtml(rating)}</span></div>
        <div class="score-panel">
          <div class="score-block">
            <p>Observed risk points (higher = more observed risk)</p>
            <strong>${score === null ? "Not calculated" : `${score} / 100`}</strong>
          </div>
          <div class="progress-track compact"><div style="width:${Math.min(score, 100)}%"></div></div>
          <div class="score-meta">
            <span>Risk interpretation: ${escapeHtml(rating)} · Evidence: ${escapeHtml(evidenceStatus)}</span>
            <span>Exposure observation rating: ${escapeHtml(exposureRisk)}</span>
          </div>
        </div>
        <p class="empty-state-note">These are observed risk points, not a security protection score or probability. Incomplete evidence produces an Unknown interpretation; a low point total is not assurance that the site is secure.</p>
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
    makeFile("EXPOSURES", "OBSERVATIONS", exposure, "!"),
    makeFile("RISK / SEVERITY", "ANALYSIS", { risk, summary }, "△"),
    makeFile("REPORTS", "GENERATED", report.report_paths || investigation, "▤"),
  ].filter((file) => file.available);

  const scoreValue = risk.overall_score ?? report.risk_summary?.observed_risk_points;
  const score = scoreValue !== null && scoreValue !== undefined && Number.isFinite(Number(scoreValue)) ? Number(scoreValue) : null;
  const rating = risk.evidence_status === "complete" ? (risk.overall_rating || report.risk_summary?.risk_interpretation || "Unknown") : "Unknown";
  const exposureRisk = summary.observation_rating || report.risk_summary?.exposure_observation_rating || "Not calculated";
  const htmlReportAvailable = Boolean(investigation.html_report_location || report.report_paths?.html);

  $("dashboard").classList.remove("hidden");
  $("progress-panel").classList.add("hidden");
  $("result-target").textContent = investigation.target;
  $("result-time").textContent = `${report.normalized_target?.hostname || ""} · ${investigation.status}`;
  $("risk-chip").textContent = `${rating} RISK · ${score === null ? "Not scored" : `${score}/100 risk points`}`;
  $("view-html-report").classList.toggle("hidden", !htmlReportAvailable);
  $("view-html-report").onclick = () => openReport(`/investigations/${investigation.id}/report/html`, "text/html");
  $("file-count").textContent = `${files.length} evidence files`;
  $("result-metrics").innerHTML = `
    <div class="metric-card"><span>Observed risk points · higher = more risk</span><strong>${score === null ? "Not calculated" : `${score} / 100`}</strong><small>${escapeHtml(rating)} · evidence ${escapeHtml(risk.evidence_status || "unknown")}</small></div>
    <div class="metric-card"><span>Exposure observation rating</span><strong>${escapeHtml(exposureRisk)}</strong><small>${summary.unique_candidate_urls ?? 0} unique candidate URLs</small></div>
    <div class="metric-card"><span>Heuristic observations</span><strong>${summary.heuristic_observations ?? exposure.findings?.length ?? 0}</strong><small>${summary.http_checked_candidate_urls ?? 0} candidate URLs with exact-request HTTP evidence</small></div>
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
      await loadAssets();
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
$("refresh-assets").addEventListener("click", () => loadAssets());
$("asset-select").addEventListener("change", () => { state.availableScans.clear(); loadAssetHistory(Number($("asset-select").value), 0).catch((error) => { $("compare-status").textContent = error.message; }); });
$("asset-prev").addEventListener("click", () => loadAssets(state.assetId, Math.max(0, state.assetSkip - state.assetLimit)));
$("asset-next").addEventListener("click", () => loadAssets(null, state.assetSkip + state.assetLimit));
$("history-prev").addEventListener("click", () => loadAssetHistory(state.assetId, Math.max(0, state.historySkip - state.historyLimit)).catch((error) => { $("compare-status").textContent = error.message; }));
$("history-next").addEventListener("click", () => loadAssetHistory(state.assetId, state.historySkip + state.historyLimit).catch((error) => { $("compare-status").textContent = error.message; }));
$("compare-button").addEventListener("click", compareSelectedScans);

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
loadAssets();
