// results.js — Shepherd AI Logic
let lastScanData = null; // Global storage for PDF generator

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

  const prompt = document.getElementById("upgradePrompt");
  if (prompt) prompt.classList.toggle("hidden", pct < 100);
}

// ─────────────────────────────────────────────
//  UI: Table Rendering
// ─────────────────────────────────────────────
function renderTable(allRoutes, unsecuredRoutes, score, target) {
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  // Create a set for quick lookup of unsecured paths
  const unsecuredPaths = new Set(unsecuredRoutes.map(r => `${r.method}:${r.route}`));
  const findingMap = {};
  unsecuredRoutes.forEach(r => { findingMap[`${r.method}:${r.route}`] = r; });

  allRoutes.forEach(r => {
    const key = `${r.method}:${r.route}`;
    const isUnsecured = unsecuredPaths.has(key);
    const finding = findingMap[key] || r;
    const risk = getRisk(finding, !isUnsecured);

    const tags = (finding.compliance || [])
      .map(t => `<span class="mono text-[10px] bg-gray-800 text-gray-400 px-2 py-0.5 rounded">${t}</span>`)
      .join(" ");

    tbody.innerHTML += `
      <tr class="hover:bg-gray-900/50 transition border-b border-gray-800/50">
        <td class="mono text-xs text-gray-300 px-4 py-3 truncate">${r.route}</td>
        <td class="px-4 py-3">
          <span class="mono text-[10px] font-bold px-2 py-1 rounded ${METHOD_COLORS[r.method] || 'bg-gray-800'}">
            ${r.method}
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

  // Update Statistics
  const sc = Math.round(score);
  const scoreEl = document.getElementById("statScore");
  if (scoreEl) {
    scoreEl.textContent = sc + "%";
    scoreEl.className = `text-3xl font-bold ${sc >= 80 ? "text-emerald-400" : sc >= 50 ? "text-yellow-400" : "text-red-400"}`;
  }
  document.getElementById("statTotal").textContent = allRoutes.length;
  document.getElementById("statUnsecured").textContent = unsecuredRoutes.length;
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
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body: JSON.stringify({ target_url: url })
    });

    const data = await res.json();

    if (!res.ok) {
      errMsg.textContent = data.detail || "Scan failed.";
      errMsg.classList.remove("hidden");
      return;
    }

    lastScanData = data;
    renderTable(data.findings, data.findings, data.score, data.target);
    updateUsageBar(data.usage);
  } catch (err) {
    errMsg.textContent = "Connection Error: " + err.message;
    errMsg.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    document.getElementById("spinner").classList.add("hidden");
    document.getElementById("btnLabel").textContent = "Run scan";
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

    if (!res.ok) throw new Error("PDF generation failed or unauthorized.");

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