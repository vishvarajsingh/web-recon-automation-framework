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

function setMessage(message, error = true) {
  $("form-message").textContent = message;
  $("form-message").style.color = error ? "var(--crimson-dark)" : "var(--signal)";
}

function showError(message) {
  stopScanCopy();
  $("error-state").classList.remove("hidden");
  $("error-message").textContent = message;
  $("progress-panel").classList.add("hidden");
  $("dashboard").classList.add("hidden");
  $("scan-button").disabled = false;
}

function startScanCopy() {
  let index = 0;
  $("scan-word").textContent = scanWords[index];
  $("progress-message").textContent = awarenessLines[index];
  state.copyTimer = setInterval(() => {
    index = (index + 1) % scanWords.length;
    $("scan-word").textContent = scanWords[index];
    $("progress-message").textContent = awarenessLines[index];
  }, 1900);
}

function stopScanCopy() {
  if (state.copyTimer) clearInterval(state.copyTimer);
  state.copyTimer = null;
}

function setProgress(investigation) {
  const percent = investigation.progress || 0;
  $("progress-panel").classList.remove("hidden");
  $("progress-status").textContent = String(investigation.status || "queued").toUpperCase();
  $("progress-percent").textContent = `${percent}%`;
  $("progress-bar").style.width = `${percent}%`;
  if (investigation.progress_message) $("progress-message").textContent = investigation.progress_message;
}

function makeFile(label, tag, data, icon = "[]") {
  return { label, tag, data, icon, available: data !== undefined && data !== null };
}

function openReport(path, contentType) {
  return fetch(`${apiBase}${path}`).then(async (response) => {
    if (!response.ok) throw new Error(`Report request failed (${response.status})`);
    const blob = await response.blob();
    const url = URL.createObjectURL(new Blob([blob], { type: contentType }));
    window.open(url, "_blank", "noopener,noreferrer");
  }).catch((error) => setMessage(error.message));
}

function renderDetail(file, investigation) {
  $("detail-panel").classList.remove("hidden");
  $("detail-title").textContent = file.label;
  const report = investigation.raw_output || {};
  const reportLinks = file.label === "REPORTS" ? `<div class="report-actions"><button id="open-json" type="button">Open JSON report</button><button id="open-html" type="button">Open HTML report</button></div>` : "";
  $("detail-content").innerHTML = `${reportLinks}<pre class="detail-body">${escapeHtml(displayValue(file.data))}</pre>`;
  if (file.label === "REPORTS") {
    $("open-json").onclick = () => openReport(`/investigations/${investigation.id}/report/download`, "application/json");
    $("open-html").onclick = () => openReport(`/investigations/${investigation.id}/report/html`, "text/html");
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

  $("dashboard").classList.remove("hidden");
  $("progress-panel").classList.add("hidden");
  $("result-target").textContent = investigation.target;
  $("result-time").textContent = `${report.normalized_target?.hostname || ""} · ${investigation.status}`;
  $("risk-chip").textContent = `${risk.overall_rating || "ANALYSIS"} RISK · ${risk.overall_score ?? "-"}/100`;
  $("file-count").textContent = `${files.length} evidence files`;
  $("file-grid").innerHTML = files.map((file) => `<button class="file-card" type="button" data-label="${escapeHtml(file.label)}"><span class="file-icon">${escapeHtml(file.icon)}</span><strong>${escapeHtml(file.label)}</strong><small>${escapeHtml(file.tag)}</small></button>`).join("");
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
        renderResults(investigation);
        setMessage("Recon complete. Open the results folder below.", false);
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
