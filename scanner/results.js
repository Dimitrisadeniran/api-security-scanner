"use strict";

// ─────────────────────────────────────────────
//  State
// ─────────────────────────────────────────────
let lastScanData = null;

// ─────────────────────────────────────────────
//  Run Scan
// ─────────────────────────────────────────────
async function runScan() {
  const url    = document.getElementById("urlInput").value.trim();
  const apiKey = localStorage.getItem("shepherd_api_key");
  const tier   = localStorage.getItem("shepherd_tier") || "free";
  const errEl  = document.getElementById("errorMsg");
  const btn    = document.getElementById("scanBtn");
  const label  = document.getElementById("btnLabel");
  const spinner = document.getElementById("spinner");

  errEl.classList.add("hidden");

  if (!url) {
    errEl.textContent = "Please enter a URL.";
    errEl.classList.remove("hidden");
    return;
  }
  if (!apiKey) {
    window.location.replace("login.html");
    return;
  }

  // UI: loading state
  btn.disabled = true;
  spinner.classList.remove("hidden");
  label.textContent = "Scanning...";
  document.getElementById("resultsSection").classList.add("hidden");

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "x-api-key":    apiKey,
      },
      body: JSON.stringify({ target_url: url }),
    });

    const data = await res.json();

    if (!res.ok) {
      // 429 = scan limit reached
      if (res.status === 429) {
        document.getElementById("upgradePrompt").classList.remove("hidden");
        throw new Error(data.detail || "Monthly scan limit reached. Upgrade to continue.");
      }
      throw new Error(data.detail || `Scan failed (${res.status})`);
    }

    lastScanData = { target_url: url, ...data };

    // Update usage bar
    if (data.usage) {
      const used      = data.usage.scans_used  ?? 0;
      const limit     = data.usage.scans_limit ?? 0;
      const unlimited = limit >= 999999;
      const pct       = (!unlimited && limit > 0) ? Math.min(100, Math.round((used / limit) * 100)) : 0;

      document.getElementById("usageText").textContent    = `${used} / ${unlimited ? "∞" : limit}`;
      document.getElementById("usageBarFill").style.width = `${pct}%`;
      document.getElementById("usageBar").classList.remove("hidden");

      if (pct >= 90) {
        document.getElementById("usageBarFill").classList.replace("bg-emerald-500", "bg-red-500");
      }
      if (!unlimited && used >= limit) {
        document.getElementById("upgradePrompt").classList.remove("hidden");
      }
    }

    renderResults(data, url, tier);

  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
    label.textContent = "Run scan";
  }
}

// ─────────────────────────────────────────────
//  Render Results
// ─────────────────────────────────────────────
function renderResults(data, url, tier) {
  const findings   = data.findings  || [];
  const score      = data.score     ?? 0;
  const total      = findings.length;
  const compliance = data.compliance_score ?? null;
  const auditLabel = data.audit_status_label ?? null;
  const summary    = data.summary || {};

  // Summary stats (unchanged — structural security score)
  document.getElementById("statScore").textContent     = `${Math.round(score)}%`;
  document.getElementById("statScore").className       = `text-3xl font-bold ${score >= 80 ? "text-emerald-400" : score >= 50 ? "text-yellow-400" : "text-red-400"}`;
  document.getElementById("statTotal").textContent     = data.usage ? (data.usage.scans_used) + " scanned" : "—";
  document.getElementById("statUnsecured").textContent = total;

  // NEW: Compliance banner
  if (compliance !== null) {
    const banner  = document.getElementById("complianceBanner");
    const scoreEl = document.getElementById("complianceScoreText");
    const badge   = document.getElementById("auditStatusBadge");
    const overlapEl = document.getElementById("overlapWarning");

    scoreEl.textContent = `${compliance}/100`;

    let colorClass, borderClass, badgeClass;
    if (compliance >= 85) {
      colorClass = "text-emerald-400"; borderClass = "border-emerald-900/50 bg-emerald-950/20"; badgeClass = "bg-emerald-950 text-emerald-400";
    } else if (compliance >= 60) {
      colorClass = "text-yellow-400"; borderClass = "border-yellow-900/50 bg-yellow-950/20"; badgeClass = "bg-yellow-950 text-yellow-400";
    } else {
      colorClass = "text-red-400"; borderClass = "border-red-900/50 bg-red-950/20"; badgeClass = "bg-red-950 text-red-400";
    }

    scoreEl.className = `text-2xl font-bold ${colorClass}`;
    banner.className  = `mb-6 rounded-xl p-5 border ${borderClass}`;
    badge.textContent = auditLabel || "—";
    badge.className   = `mono text-xs px-4 py-2 rounded-full font-bold ${badgeClass}`;

    if (summary.overlap_count > 0) {
      overlapEl.textContent = `🚨 ${summary.overlap_count} route(s) trigger overlapping compliance exposure (e.g. NDPA + PCI) — highest priority to fix.`;
      overlapEl.classList.remove("hidden");
    } else {
      overlapEl.classList.add("hidden");
    }
  }

  // Download row
  const dlRow = document.getElementById("downloadRow");
  document.getElementById("downloadTarget").textContent = url;
  if (tier !== "free") {
    dlRow.classList.remove("hidden");
    dlRow.style.display = "flex";
  }

  if (tier !== "free") {
    document.getElementById("alertsRow").classList.remove("hidden");
    loadAlertSettings();
  }
  if (tier === "pro" || tier === "enterprise") {
    document.getElementById("slackRow").classList.remove("hidden");
    loadSlackSettings();
  }
  if (tier === "enterprise") {
    document.getElementById("enterpriseRow").classList.remove("hidden");
    loadEnterpriseSettings();
  }

  // Results table
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  if (findings.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="mono text-center text-emerald-400 text-xs py-8">
          ✅ All routes are secured. Score: ${Math.round(score)}%
        </td>
      </tr>`;
  } else {
    findings.forEach(f => {
      const methodColors = {
        GET:    "bg-blue-950 text-blue-400",
        POST:   "bg-green-950 text-green-400",
        PUT:    "bg-yellow-950 text-yellow-400",
        DELETE: "bg-red-950 text-red-400",
        PATCH:  "bg-purple-950 text-purple-400",
      };
      const methodClass = methodColors[f.method] || "bg-gray-800 text-gray-400";
      const tags = (f.compliance || []).map(t =>
        `<span class="mono text-[10px] px-2 py-0.5 rounded-full bg-red-950 text-red-400 border border-red-900">${t}</span>`
      ).join(" ");

      // NEW: severity-based badge instead of flat is_critical
      const severity = f.severity || (f.is_critical ? "CRITICAL" : "INFO");
      const severityStyles = {
        CONFIRMED_LEAK: "bg-red-900 text-red-300 border border-red-600",
        CRITICAL:       "bg-red-950 text-red-400",
        WARNING:        "bg-yellow-950 text-yellow-400",
        INFO:           "bg-gray-800 text-gray-400",
      };
      const severityLabels = {
        CONFIRMED_LEAK: "🔴 CONFIRMED LEAK",
        CRITICAL:       "🚨 CRITICAL",
        WARNING:        "⚠ WARNING",
        INFO:           "UNSECURED",
      };
      const overlapBadge = f.is_overlap
        ? `<span class="mono text-[9px] px-1.5 py-0.5 rounded bg-red-900 text-red-300 ml-1">OVERLAP</span>`
        : "";

      tbody.innerHTML += `
        <tr class="hover:bg-gray-900 transition" title="${f.message || ''}">
          <td class="mono text-xs text-gray-300 px-4 py-3 truncate" title="${f.route}">${f.route}</td>
          <td class="px-4 py-3">
            <span class="mono text-[10px] px-2 py-0.5 rounded ${methodClass} font-bold">${f.method}</span>
          </td>
          <td class="px-4 py-3">
            <span class="mono text-[10px] px-2 py-0.5 rounded ${severityStyles[severity]} font-bold">
              ${severityLabels[severity]}
            </span>${overlapBadge}
          </td>
          <td class="px-4 py-3">
            <div class="flex flex-wrap gap-1">${tags || '<span class="mono text-[10px] text-gray-600">—</span>'}</div>
          </td>
          <td class="mono text-[10px] text-gray-500 px-4 py-3 truncate">${f.summary || "—"}</td>
        </tr>`;
    });
  }

  document.getElementById("resultsSection").classList.remove("hidden");
  document.getElementById("resultsSection").scrollIntoView({ behavior: "smooth", block: "start" });
}
// ─────────────────────────────────────────────
//  PDF Download
// ─────────────────────────────────────────────
async function downloadPDF() {
  if (!lastScanData) return;
  const apiKey = localStorage.getItem("shepherd_api_key");
  const btn    = document.getElementById("downloadBtn");

  btn.textContent = "Generating...";
  btn.disabled    = true;

  try {
    const res = await fetch(`${API_BASE}/report/download`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key":    apiKey,
      },
      body: JSON.stringify({
        target_url:   lastScanData.target_url,
        score:        lastScanData.score,
        findings:     lastScanData.findings,
        company_name: "Shepherd AI",
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "PDF generation failed.");
    }

    const blob = await res.blob();
    const link = document.createElement("a");
    link.href     = URL.createObjectURL(blob);
    link.download = "shepherd-report.pdf";
    link.click();

  } catch (err) {
    alert("PDF Error: " + err.message);
  } finally {
    btn.innerHTML = `<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5 5 5-5M12 15V3"/>
    </svg> Download PDF Report`;
    btn.disabled = false;
  }
}

// ─────────────────────────────────────────────
//  Email Alert Settings
// ─────────────────────────────────────────────
async function loadAlertSettings() {
  const apiKey = localStorage.getItem("shepherd_api_key");
  try {
    const res  = await fetch(`${API_BASE}/alerts/settings`, { headers: { "x-api-key": apiKey } });
    if (!res.ok) return;
    const data = await res.json();
    if (data.alert_email) document.getElementById("alertEmailInput").value = data.alert_email;
    if (data.email_alerts) {
      document.getElementById("alertBtn").textContent = "Alerts Enabled ✅";
      document.getElementById("alertBtn").classList.replace("bg-gray-700", "bg-emerald-700");
    }
  } catch (_) {}
}

async function configureAlerts() {
  const apiKey = localStorage.getItem("shepherd_api_key");
  const email  = document.getElementById("alertEmailInput").value.trim();
  const btn    = document.getElementById("alertBtn");
  const status = document.getElementById("alertStatus");

  if (!email) { status.textContent = "Enter an email address."; status.classList.remove("hidden"); return; }

  btn.textContent = "Saving...";
  btn.disabled    = true;

  try {
    const res = await fetch(`${API_BASE}/alerts/configure`, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body:    JSON.stringify({ email_alerts: true, alert_email: email }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to save.");

    status.textContent = `✅ Alerts enabled → ${data.alert_email}`;
    status.classList.remove("hidden");
    btn.textContent = "Alerts Enabled ✅";
    btn.classList.replace("bg-gray-700", "bg-emerald-700");
  } catch (err) {
    status.textContent = "⚠ " + err.message;
    status.classList.remove("hidden");
    btn.textContent = "Enable Alerts";
  } finally {
    btn.disabled = false;
  }
}

// ─────────────────────────────────────────────
//  Slack Settings
// ─────────────────────────────────────────────
async function loadSlackSettings() {
  const apiKey = localStorage.getItem("shepherd_api_key");
  try {
    const res  = await fetch(`${API_BASE}/slack/settings`, { headers: { "x-api-key": apiKey } });
    if (!res.ok) return;
    const data = await res.json();
    if (data.slack_webhook) document.getElementById("slackWebhookInput").value = data.slack_webhook;
    if (data.slack_alerts) {
      document.getElementById("slackBtn").textContent = "Slack Connected ✅";
      document.getElementById("slackBtn").classList.replace("bg-gray-700", "bg-emerald-700");
    }
  } catch (_) {}
}

async function configureSlack() {
  const apiKey  = localStorage.getItem("shepherd_api_key");
  const webhook = document.getElementById("slackWebhookInput").value.trim();
  const btn     = document.getElementById("slackBtn");
  const status  = document.getElementById("slackStatus");

  if (!webhook.startsWith("https://hooks.slack.com")) {
    status.textContent = "Enter a valid Slack webhook URL.";
    status.classList.remove("hidden");
    return;
  }

  btn.textContent = "Connecting...";
  btn.disabled    = true;

  try {
    const res = await fetch(`${API_BASE}/slack/configure`, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body:    JSON.stringify({ webhook_url: webhook, slack_alerts: true }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed.");

    status.textContent = "✅ Slack connected successfully.";
    status.classList.remove("hidden");
    btn.textContent = "Slack Connected ✅";
    btn.classList.replace("bg-gray-700", "bg-emerald-700");
  } catch (err) {
    status.textContent = "⚠ " + err.message;
    status.classList.remove("hidden");
    btn.textContent = "Connect Slack";
  } finally {
    btn.disabled = false;
  }
}

// ─────────────────────────────────────────────
//  Enterprise Settings
// ─────────────────────────────────────────────
async function loadEnterpriseSettings() {
  const apiKey = localStorage.getItem("shepherd_api_key");
  try {
    const res  = await fetch(`${API_BASE}/enterprise/settings`, { headers: { "x-api-key": apiKey } });
    if (!res.ok) return;
    const data = await res.json();
    if (data.company_name)    document.getElementById("companyNameInput").value    = data.company_name;
    if (data.logo_url)        document.getElementById("logoUrlInput").value        = data.logo_url;
    if (data.custom_keywords) document.getElementById("customKeywordsInput").value = data.custom_keywords;
  } catch (_) {}
}

async function saveEnterpriseSettings() {
  const apiKey   = localStorage.getItem("shepherd_api_key");
  const btn      = document.getElementById("enterpriseBtn");
  const status   = document.getElementById("enterpriseStatus");

  btn.textContent = "Saving...";
  btn.disabled    = true;

  try {
    const res = await fetch(`${API_BASE}/enterprise/settings`, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body:    JSON.stringify({
        company_name:    document.getElementById("companyNameInput").value.trim(),
        logo_url:        document.getElementById("logoUrlInput").value.trim(),
        custom_keywords: document.getElementById("customKeywordsInput").value.trim(),
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed.");

    status.textContent = "✅ Enterprise settings saved.";
    status.classList.remove("hidden");
  } catch (err) {
    status.textContent = "⚠ " + err.message;
    status.classList.remove("hidden");
  } finally {
    btn.textContent = "Save Settings";
    btn.disabled    = false;
  }
}

// ─────────────────────────────────────────────
//  Audit History
// ─────────────────────────────────────────────
async function loadHistory() {
  const apiKey  = localStorage.getItem("shepherd_api_key");
  const section = document.getElementById("historySection");
  const btn     = document.getElementById("historyBtn");
  const tbody   = document.getElementById("historyBody");

  if (!section.classList.contains("hidden")) {
    section.classList.add("hidden");
    btn.querySelector("span") && (btn.querySelector("span").textContent = "View Audit History");
    return;
  }

  btn.textContent = "Loading...";

  try {
    const res = await fetch(`${API_BASE}/history`, { headers: { "x-api-key": apiKey } });
    const data = await res.json();

    if (!res.ok) {
      tbody.innerHTML = `<tr><td colspan="4" class="mono text-xs text-yellow-400 px-4 py-6 text-center">⚠ ${data.detail || "History unavailable."}</td></tr>`;
      section.classList.remove("hidden");
      return;
    }

    tbody.innerHTML = "";
    if (!data.history || data.history.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="mono text-xs text-gray-600 px-4 py-6 text-center">No scans yet.</td></tr>`;
    } else {
      data.history.forEach(h => {
        const score  = h.score ?? 0;
        const color  = score >= 80 ? "text-emerald-400" : score >= 50 ? "text-yellow-400" : "text-red-400";
        const date   = h.scanned_at ? new Date(h.scanned_at).toLocaleString() : "—";
        tbody.innerHTML += `
          <tr class="hover:bg-gray-900 transition">
            <td class="mono text-xs text-gray-500 px-4 py-3">${date}</td>
            <td class="mono text-xs text-gray-300 px-4 py-3 truncate" title="${h.target_url}">${h.target_url}</td>
            <td class="mono text-xs ${color} px-4 py-3 font-bold">${Math.round(score)}%</td>
            <td class="px-4 py-3">
              <span class="mono text-[10px] px-2 py-0.5 rounded ${score >= 80 ? "bg-emerald-950 text-emerald-400" : "bg-red-950 text-red-400"}">
                ${score >= 80 ? "PASS" : "REVIEW"}
              </span>
            </td>
          </tr>`;
      });
    }

    section.classList.remove("hidden");

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="mono text-xs text-red-400 px-4 py-6 text-center">Error: ${err.message}</td></tr>`;
    section.classList.remove("hidden");
  } finally {
    btn.innerHTML = `<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
    </svg> View Audit History`;
  }
}
