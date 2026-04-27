// results.js — Shepherd AI v0.6 — Days 12 & 13
"use strict";

let lastScanData = null;

const METHOD_COLORS = {
  GET:    "bg-blue-950 text-blue-300",
  POST:   "bg-green-950 text-green-300",
  PUT:    "bg-yellow-950 text-yellow-300",
  DELETE: "bg-red-950 text-red-300",
  PATCH:  "bg-pink-950 text-pink-300",
};

const API_BASE = "http://127.0.0.1:8000";

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────
function getApiKey() {
  return document.getElementById("apiKeyInput")?.value.trim() || "";
}

function showError(msg) {
  const el = document.getElementById("errorMsg");
  if (el) { el.textContent = msg; el.classList.remove("hidden"); }
}

function hideError() {
  const el = document.getElementById("errorMsg");
  if (el) el.classList.add("hidden");
}

function apiHeaders() {
  return { "Content-Type": "application/json", "x-api-key": getApiKey() };
}

// ─────────────────────────────────────────────
//  Initialize
// ─────────────────────────────────────────────
window.addEventListener("load", () => {
  const saved = sessionStorage.getItem("shepherd_api_key");
  if (saved) {
    const keyInput = document.getElementById("apiKeyInput");
    if (keyInput) keyInput.value = saved;
  }
});

// ─────────────────────────────────────────────
//  Risk Assessment
// ─────────────────────────────────────────────
function getRisk(finding) {
  if (finding.is_critical) return { label: "Critical", cls: "bg-red-950 text-red-400" };
  if (finding.compliance?.length) return { label: "Warning", cls: "bg-yellow-950 text-yellow-400" };
  return { label: "Low", cls: "bg-gray-800 text-gray-400" };
}

// ─────────────────────────────────────────────
//  Usage Bar
// ─────────────────────────────────────────────
function updateUsageBar(usage) {
  if (!usage) return;
  const { scans_used, scans_limit, tier } = usage;
  const isUnlimited = scans_limit >= 9999;
  const pct = isUnlimited ? 10 : Math.min((scans_used / scans_limit) * 100, 100);

  document.getElementById("usageBar")?.classList.remove("hidden");

  const usageText = document.getElementById("usageText");
  if (usageText) {
    usageText.textContent = isUnlimited
      ? `${scans_used} used — ${tier.toUpperCase()} (unlimited)`
      : `${scans_used} of ${scans_limit} — ${tier.toUpperCase()}`;
  }

  const fill = document.getElementById("usageBarFill");
  if (fill) {
    fill.style.width = `${pct}%`;
    fill.className = `h-1.5 rounded-full transition-all duration-500 ${
      pct >= 100 ? "bg-red-500" : pct >= 70 ? "bg-yellow-500" : "bg-emerald-500"
    }`;
  }

  const prompt = document.getElementById("upgradePrompt");
  if (prompt) prompt.classList.toggle("hidden", pct < 100);
}

// ─────────────────────────────────────────────
// ─────────────────────────────────────────────
//  Render Results Table — Shepherd AI v0.6
// ─────────────────────────────────────────────
function renderTable(findings, score, target, usage) {
  const tbody = document.getElementById("resultsBody");
  if (!tbody) return;

  // 1. Performance: Clear and prepare a string buffer
  tbody.innerHTML = "";
  let rowsHtml = "";

  // 2. Logic: Only show Enterprise row if the user tier is 'enterprise'
  const enterpriseRow = document.getElementById("enterpriseRow");
  if (enterpriseRow && usage?.tier === "enterprise") {
    enterpriseRow.classList.remove("hidden");
  }

  // 3. Performance: Loop through findings and build one large string
  findings.forEach(f => {
    const risk = getRisk(f);
    const tags = (f.compliance || [])
      .map(t => `<span class="mono text-[10px] bg-gray-800 text-gray-400 px-2 py-0.5 rounded">${t}</span>`)
      .join(" ");

    rowsHtml += `
      <tr class="hover:bg-gray-900/50 transition border-b border-gray-800/50">
        <td class="mono text-xs text-gray-300 px-4 py-3 truncate">${f.route}</td>
        <td class="px-4 py-3">
          <span class="mono text-[10px] font-bold px-2 py-1 rounded ${METHOD_COLORS[f.method] || "bg-gray-800"}">
            ${f.method}
          </span>
        </td>
        <td class="px-4 py-3">
          <span class="mono text-xs flex items-center gap-1.5 text-red-400">
            <span class="w-1.5 h-1.5 rounded-full bg-red-400"></span>
            Unprotected
          </span>
        </td>
        <td class="px-4 py-3">
          <span class="mono text-[10px] px-2 py-1 rounded ${risk.cls}">${risk.label}</span>
        </td>
        <td class="px-4 py-3 text-gray-500">${tags || "—"}</td>
      </tr>`;
  });

  // 4. Performance: Inject all rows at once
  tbody.innerHTML = rowsHtml;

  // ─────────────────────────────────────────────
  //  Stats & UI Visibility
  // ─────────────────────────────────────────────
  const sc = Math.round(score);
  const scoreEl = document.getElementById("statScore");
  if (scoreEl) {
    scoreEl.textContent = sc + "%";
    scoreEl.className = `text-3xl font-bold ${
      sc >= 80 ? "text-emerald-400" : sc >= 50 ? "text-yellow-400" : "text-red-400"
    }`;
  }

  const totalEl = document.getElementById("statTotal");
  if (totalEl) totalEl.textContent = findings.length;

  const unsecEl = document.getElementById("statUnsecured");
  if (unsecEl) unsecEl.textContent = findings.length;

  document.getElementById("resultsSection")?.classList.remove("hidden");

  const dlRow = document.getElementById("downloadRow");
  if (dlRow) {
    dlRow.classList.remove("hidden");
    const dlTarget = document.getElementById("downloadTarget");
    if (dlTarget) dlTarget.textContent = target;
  }

  // Show Tier-Specific Rows
  document.getElementById("alertsRow")?.classList.remove("hidden");
  document.getElementById("slackRow")?.classList.remove("hidden");
}

// ─────────────────────────────────────────────
//  Run Scan
// ─────────────────────────────────────────────
async function runScan() {
  const url    = document.getElementById("urlInput")?.value.trim();
  const apiKey = getApiKey();
  const btn    = document.getElementById("scanBtn");

  hideError();

  if (!url || !apiKey) {
    showError("URL and API Key are both required.");
    return;
  }

  sessionStorage.setItem("shepherd_api_key", apiKey);
  btn.disabled = true;
  document.getElementById("spinner")?.classList.remove("hidden");
  document.getElementById("btnLabel").textContent = "Analyzing...";

  try {
    const res  = await fetch(`${API_BASE}/scan`, {
      method: "POST", headers: apiHeaders(),
      body: JSON.stringify({ target_url: url })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Scan failed.");

    lastScanData = data;
    renderTable(data.findings, data.score, data.target);
    updateUsageBar(data.usage);

  } catch (err) {
    showError(err.message);
  } finally {
    btn.disabled = false;
    document.getElementById("spinner")?.classList.add("hidden");
    document.getElementById("btnLabel").textContent = "Run scan";
  }
}

// ─────────────────────────────────────────────
//  Email Alerts
// ─────────────────────────────────────────────
async function configureAlerts() {
  const alertEmail = document.getElementById("alertEmailInput")?.value.trim();
  const btn        = document.getElementById("alertBtn");
  hideError();

  btn.disabled = true; btn.textContent = "Saving...";

  try {
    const res  = await fetch(`${API_BASE}/alerts/configure`, {
      method: "POST", headers: apiHeaders(),
      body: JSON.stringify({ email_alerts: true, alert_email: alertEmail || "" })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to save.");

    const status = document.getElementById("alertStatus");
    if (status) {
      status.textContent = `✅ Email alerts enabled — ${data.alert_email}`;
      status.classList.remove("hidden");
    }
  } catch (err) {
    showError(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Enable Alerts";
  }
}

// ─────────────────────────────────────────────
//  Day 12 — Slack Alerts
// ─────────────────────────────────────────────
async function configureSlack() {
  const webhookUrl = document.getElementById("slackWebhookInput")?.value.trim();
  const btn        = document.getElementById("slackBtn");
  hideError();

  if (!webhookUrl || !webhookUrl.startsWith("https://hooks.slack.com")) {
    showError("Please enter a valid Slack webhook URL (starts with https://hooks.slack.com).");
    return;
  }

  btn.disabled = true; btn.textContent = "Saving...";

  try {
    const res  = await fetch(`${API_BASE}/slack/configure`, {
      method: "POST", headers: apiHeaders(),
      body: JSON.stringify({ webhook_url: webhookUrl, slack_alerts: true })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to save Slack settings.");

    const status = document.getElementById("slackStatus");
    if (status) {
      status.textContent = "✅ Slack alerts enabled — you'll get a message after every scan.";
      status.classList.remove("hidden");
    }

    // Send test message immediately
    await testSlack();

  } catch (err) {
    showError(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Connect Slack";
  }
}

async function testSlack() {
  try {
    const res  = await fetch(`${API_BASE}/slack/test`, {
      method: "POST", headers: apiHeaders()
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail);
    console.log("✅ Test Slack message sent.");
  } catch (err) {
    console.error("Slack test failed:", err.message);
  }
}

// ─────────────────────────────────────────────
//  Day 13 — Enterprise Settings
// ─────────────────────────────────────────────
async function saveEnterpriseSettings() {
  const companyName    = document.getElementById("companyNameInput")?.value.trim();
  const logoUrl        = document.getElementById("logoUrlInput")?.value.trim();
  const customKeywords = document.getElementById("customKeywordsInput")?.value.trim();
  const btn            = document.getElementById("enterpriseBtn");
  hideError();

  btn.disabled = true; btn.textContent = "Saving...";

  try {
    const res  = await fetch(`${API_BASE}/enterprise/settings`, {
      method: "POST", headers: apiHeaders(),
      body: JSON.stringify({
        company_name:    companyName    || "Shepherd AI",
        logo_url:        logoUrl        || "",
        custom_keywords: customKeywords || "",
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to save enterprise settings.");

    const status = document.getElementById("enterpriseStatus");
    if (status) {
      status.textContent = `✅ Enterprise settings saved — PDFs will use "${data.company_name}"`;
      status.classList.remove("hidden");
    }
  } catch (err) {
    showError(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Save Settings";
  }
}

// ─────────────────────────────────────────────
//  Download PDF
// ─────────────────────────────────────────────
async function downloadPDF() {
  if (!lastScanData) return;
  const btn = document.getElementById("downloadBtn");
  hideError();

  btn.disabled = true; btn.textContent = "Generating...";

  try {
    const res = await fetch(`${API_BASE}/report/download`, {
      method: "POST", headers: apiHeaders(),
      body: JSON.stringify({
        target_url: lastScanData.target,
        score:      lastScanData.score,
        findings:   lastScanData.findings,
      })
    });

    if (res.status === 403) {
      const err = await res.json();
      showError("⚠️ " + err.detail);
      return;
    }
    if (!res.ok) throw new Error("PDF generation failed.");

    const blob = await res.blob();
    const link = document.createElement("a");
    link.href  = URL.createObjectURL(blob);
    link.download = `Shepherd-Report-${Date.now()}.pdf`;
    link.click();
    URL.revokeObjectURL(link.href);

  } catch (err) {
    showError(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Download PDF Report";
  }
}

// ─────────────────────────────────────────────
//  Audit History
// ─────────────────────────────────────────────
async function loadHistory() {
  const btn     = document.getElementById("historyBtn");
  const section = document.getElementById("historySection");
  const tbody   = document.getElementById("historyBody");
  hideError();

  btn.disabled = true; btn.textContent = "Loading...";

  try {
    const res  = await fetch(`${API_BASE}/history`, { headers: apiHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to load history.");

    tbody.innerHTML = "";

    if (!data.history || data.history.length === 0) {
      tbody.innerHTML = `
        <tr><td colspan="4" class="px-4 py-8 text-center mono text-xs text-gray-600">
          No scans yet. Run your first scan above.
        </td></tr>`;
    } else {
      data.history.forEach(h => {
        const sc    = Math.round(h.score);
        const color = sc >= 80 ? "text-emerald-400" : sc >= 50 ? "text-yellow-400" : "text-red-400";
        const badge = sc >= 80 ? "bg-green-950 text-green-400" : sc >= 50 ? "bg-yellow-950 text-yellow-400" : "bg-red-950 text-red-400";
        const label = sc >= 80 ? "Healthy" : sc >= 50 ? "At Risk" : "Critical";

        // ← Fixed: use actual scan date not new Date()
        const date  = h.scanned_at
          ? new Date(h.scanned_at).toLocaleDateString("en-GB", {
              day: "2-digit", month: "short", year: "numeric",
              hour: "2-digit", minute: "2-digit"
            })
          : "—";

        tbody.innerHTML += `
          <tr class="hover:bg-gray-900/50 transition border-b border-gray-800/50">
            <td class="mono text-xs text-gray-400 px-4 py-3">${date}</td>
            <td class="mono text-xs text-gray-300 px-4 py-3 truncate">${h.target_url}</td>
            <td class="px-4 py-3"><span class="mono text-sm font-bold ${color}">${sc}%</span></td>
            <td class="px-4 py-3">
              <span class="mono text-[10px] px-2 py-1 rounded ${badge}">${label}</span>
            </td>
          </tr>`;
      });
    }

    section.classList.remove("hidden");

  } catch (err) {
    showError(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "View Audit History";
  }
}