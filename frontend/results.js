// results.js — Shepherd AI Logic
console.log("🚀 Shepherd Logic File Loaded!");
let lastScanData = null; 

const METHOD_COLORS = {
  GET:    "bg-blue-950 text-blue-300",
  POST:   "bg-green-950 text-green-300",
  PUT:    "bg-yellow-950 text-yellow-300",
  DELETE: "bg-red-950 text-red-300",
  PATCH:  "bg-pink-950 text-pink-300",
};

// ─────────────────────────────────────────────
//  Initialize: Load saved key
// ─────────────────────────────────────────────
window.addEventListener("load", () => {
  const saved = sessionStorage.getItem("shepherd_api_key");
  if (saved) {
    const keyInput = document.getElementById("apiKeyInput");
    if (keyInput) keyInput.value = saved;
  }
});

// ─────────────────────────────────────────────
//  Logic: Risk Assessment
// ─────────────────────────────────────────────
function getRisk(finding, isSecured) {
  if (isSecured) return { label: "Safe", cls: "bg-green-950 text-green-400" };
  if (finding.is_critical) return { label: "Critical", cls: "bg-red-950 text-red-400" };
  return { label: "Warning", cls: "bg-yellow-950 text-yellow-400" };
}

// ─────────────────────────────────────────────
//  UI: Usage Bar Update
// ─────────────────────────────────────────────
function updateUsageBar(usage) {
  if (!usage) return;
  const { scans_used, scans_limit, tier } = usage;
  const isUnlimited = scans_limit >= 9999;
  const pct = isUnlimited ? 10 : Math.min((scans_used / scans_limit) * 100, 100);

  const bar = document.getElementById("usageBar");
  if (bar) bar.classList.remove("hidden");

  const usageText = document.getElementById("usageText");
  if (usageText) {
    usageText.textContent = isUnlimited 
      ? `${scans_used} scans used — ${tier.toUpperCase()}`
      : `${scans_used} of ${scans_limit} scans — ${tier.toUpperCase()}`;
  }

  const fill = document.getElementById("usageBarFill");
  if (fill) {
    fill.style.width = `${pct}%`;
    fill.className = `h-1.5 rounded-full transition-all duration-500 ${pct >= 100 ? 'bg-red-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-emerald-500'}`;
  }
}

// ─────────────────────────────────────────────
//  UI: Table Rendering
// ─────────────────────────────────────────────
function renderTable(allFindings, score, target) {
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  allFindings.forEach(f => {
    const isUnsecured = f.is_unsecured !== false; // Assuming your engine flags these
    const risk = getRisk(f, !isUnsecured);

    const tags = (f.compliance || [])
      .map(t => `<span class="mono text-[10px] bg-gray-800 text-gray-400 px-2 py-0.5 rounded">${t}</span>`)
      .join(" ");

    tbody.innerHTML += `
      <tr class="hover:bg-gray-900/50 transition border-b border-gray-800/50">
        <td class="mono text-xs text-gray-300 px-4 py-3 truncate">${f.route}</td>
        <td class="px-4 py-3">
          <span class="mono text-[10px] font-bold px-2 py-1 rounded ${METHOD_COLORS[f.method] || 'bg-gray-800'}">
            ${f.method}
          </span>
        </td>
        <td class="px-4 py-3">
          <span class="mono text-xs flex items-center gap-1.5 ${isUnsecured ? 'text-red-400' : 'text-emerald-400'}">
            <span class="w-1.5 h-1.5 rounded-full ${isUnsecured ? 'bg-red-400' : 'bg-emerald-400'}"></span>
            ${isUnsecured ? "Unprotected" : "Secured"}
          </span>
        </td>
        <td class="px-4 py-3">
          <span class="mono text-[10px] px-2 py-1 rounded ${risk.cls}">${risk.label}</span>
        </td>
        <td class="px-4 py-3 text-gray-500">${tags || "—"}</td>
      </tr>`;
  });

  // Update Stats
  const sc = Math.round(score);
  const scoreEl = document.getElementById("statScore");
  if (scoreEl) {
    scoreEl.textContent = sc + "%";
    scoreEl.className = `text-3xl font-bold ${sc >= 80 ? "text-emerald-400" : sc >= 50 ? "text-yellow-400" : "text-red-400"}`;
  }
  
  document.getElementById("statTotal").textContent = allFindings.length;
  document.getElementById("resultsSection").classList.remove("hidden");

  // Show Download Section
  const dlRow = document.getElementById("downloadRow");
  if (dlRow) {
    dlRow.classList.remove("hidden");
    document.getElementById("downloadTarget").textContent = target;
  }
}

// ─────────────────────────────────────────────
//  Action: Run Analysis
// ─────────────────────────────────────────────
async function runScan() {
  const url = document.getElementById("urlInput").value.trim();
  const apiKey = document.getElementById("apiKeyInput").value.trim();
  const btn = document.getElementById("scanBtn");
  const errMsg = document.getElementById("errorMsg");

  if (!url || !apiKey) {
    errMsg.textContent = "URL and API Key are required.";
    errMsg.classList.remove("hidden");
    return;
  }

  errMsg.classList.add("hidden");
  sessionStorage.setItem("shepherd_api_key", apiKey);
  
  btn.disabled = true;
  document.getElementById("spinner").classList.remove("hidden");
  document.getElementById("btnLabel").textContent = "Analyzing...";

  try {
    const res = await fetch("http://127.0.0.1:8000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify({ target_url: url })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Scan failed.");

    lastScanData = data;
    renderTable(data.findings, data.score, data.target);
    updateUsageBar(data.usage);
  } catch (err) {
    errMsg.textContent = err.message;
    errMsg.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    document.getElementById("spinner").classList.add("hidden");
    document.getElementById("btnLabel").textContent = "Run scan";
  }
}
// Show alerts config row
const alertsRow = document.getElementById("alertsRow");
if (alertsRow) alertsRow.classList.remove("hidden");

// ─────────────────────────────────────────────
//  Action: Prepare Manual Email
// ─────────────────────────────────────────────
async function prepareManualEmail() {
  if (!lastScanData) return;
  const apiKey = sessionStorage.getItem("shepherd_api_key");

  try {
    const res = await fetch("http://127.0.0.1:8000/alerts/prepare-manual", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body: JSON.stringify({
        target_url: lastScanData.target,
        score: lastScanData.score,
        findings: lastScanData.findings
      })
    });

    const draft = await res.json();
    if (draft.mailto_link) {
      window.location.href = draft.mailto_link;
    }
  } catch (err) {
    console.error("Drafting failed", err);
  }
}

// ─────────────────────────────────────────────
//  Action: Configure Email Alerts
// ─────────────────────────────────────────────
async function configureAlerts() {
  const apiKey = document.getElementById("apiKeyInput").value.trim();
  const alertEmail = document.getElementById("alertEmailInput")?.value.trim();
  const errMsg = document.getElementById("errorMsg");
  const btn = document.getElementById("alertBtn");

  if (!apiKey) {
    errMsg.textContent = "API key required.";
    errMsg.classList.remove("hidden");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Saving...";

  try {
    const res = await fetch("http://127.0.0.1:8000/alerts/configure", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body: JSON.stringify({
        email_alerts: true,
        alert_email: alertEmail || ""
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to save.");

    const status = document.getElementById("alertStatus");
    if (status) {
      status.textContent = `✅ Alerts enabled for ${data.alert_email}`;
      status.classList.remove("hidden");
    }
  } catch (err) {
    errMsg.textContent = err.message;
    errMsg.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.textContent = "Enable Alerts";
  }
}

// ─────────────────────────────────────────────
//  Action: Download PDF Report
// ─────────────────────────────────────────────
async function downloadPDF() {
  if (!lastScanData) return;
  const apiKey = document.getElementById("apiKeyInput").value.trim();
  const btn = document.getElementById("downloadBtn");
  
  btn.disabled = true;
  btn.textContent = "Generating...";

  try {
    const res = await fetch("http://127.0.0.1:8000/report/download", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body: JSON.stringify({
        target_url: lastScanData.target,
        score: lastScanData.score,
        findings: lastScanData.findings
      })
    });

    if (!res.ok) throw new Error("PDF generation failed.");

    const blob = await res.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `Shepherd-Report-${new Date().getTime()}.pdf`;
    link.click();
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Download PDF Report";
  }
}
// ─────────────────────────────────────────────
//  Action: Fetch and View History
// ─────────────────────────────────────────────
async function loadHistory() {
  const apiKey = document.getElementById("apiKeyInput").value.trim();
  const historySection = document.getElementById("historySection");
  const historyBody = document.getElementById("historyBody");

  if (!apiKey) return alert("Please enter your API Key first.");

  try {
    const res = await fetch("http://127.0.0.1:8000/history", {
      method: "GET",
      headers: { "X-API-Key": apiKey }
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to load history.");

    if (data.history && data.history.length > 0) {
      // 1. Show the History Section
      historySection.classList.remove("hidden");

      // 2. Clear the history table body
      historyBody.innerHTML = ""; 

      // 3. Build the history rows
      data.history.forEach(item => {
        const row = document.createElement("tr");
        row.className = "hover:bg-gray-900/50 transition";
        
        // Formating the date for the "Date" column
        const scanDate = new Date().toLocaleDateString(); 

        row.innerHTML = `
          <td class="px-4 py-4 text-gray-400 mono text-xs">${scanDate}</td>
          <td class="px-4 py-4 font-mono text-gray-300 truncate">${item.target || "http://127.0.0.1:8000"}</td>
          <td class="px-4 py-4 font-bold ${item.score >= 80 ? 'text-emerald-500' : 'text-red-500'}">${item.score || 0}%</td>
          <td class="px-4 py-4">
            <span class="px-2 py-1 bg-gray-800 text-gray-400 rounded text-[10px] font-bold uppercase">Stored</span>
          </td>
        `;
        historyBody.appendChild(row);
      });

      console.log("History table populated successfully.");
    } else {
      alert("No previous scan history found.");
    }
  } catch (err) {
    console.error("History Error:", err);
    alert("Error: " + err.message);
  }
}