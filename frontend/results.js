// results.js — Day 8: Tier Enforcement + Usage Bar

const METHOD_COLORS = {
  GET:    "bg-blue-950 text-blue-300",
  POST:   "bg-green-950 text-green-300",
  PUT:    "bg-yellow-950 text-yellow-300",
  DELETE: "bg-red-950 text-red-300",
  PATCH:  "bg-pink-950 text-pink-300",
};

// ─────────────────────────────────────────────
//  Load saved API key when page opens
// ─────────────────────────────────────────────
window.addEventListener("load", () => {
  const saved = sessionStorage.getItem("shepherd_api_key");
  if (saved) {
    const keyInput = document.getElementById("apiKeyInput");
    if (keyInput) keyInput.value = saved;
  }
});

// ─────────────────────────────────────────────
//  Risk Level — now takes isSecured into account
// ─────────────────────────────────────────────
function getRisk(finding, isSecured) {
  if (isSecured) return { label: "Safe",     cls: "bg-green-950 text-green-400" };
  if (finding.is_critical) return { label: "Critical", cls: "bg-red-950 text-red-400" };
  if (finding.compliance?.length || finding.pii_detected?.length)
                       return { label: "Warning",  cls: "bg-yellow-950 text-yellow-400" };
  return               { label: "Warning",  cls: "bg-yellow-950 text-yellow-400" };
}

// ─────────────────────────────────────────────
//  Usage Bar — shows scans used vs limit
// ─────────────────────────────────────────────
function updateUsageBar(usage) {
  if (!usage) return;

  const { scans_used, scans_limit, tier } = usage;
  const isUnlimited = scans_limit >= 999999;
  const pct = isUnlimited
    ? 10
    : Math.min((scans_used / scans_limit) * 100, 100);

  // Show the bar container
  const bar = document.getElementById("usageBar");
  if (bar) bar.classList.remove("hidden");

  // Update the label text
  const usageText = document.getElementById("usageText");
  if (usageText) {
    usageText.textContent = isUnlimited
      ? `${scans_used} scans used — ${tier.toUpperCase()} (unlimited)`
      : `${scans_used} of ${scans_limit} scans — ${tier.toUpperCase()}`;
  }

  // Update the fill bar width + color
  const fill = document.getElementById("usageBarFill");
  if (fill) {
    fill.style.width = `${pct}%`;
    if (pct >= 100) {
      fill.className = "h-1.5 rounded-full bg-red-500 transition-all duration-500";
    } else if (pct >= 70) {
      fill.className = "h-1.5 rounded-full bg-yellow-500 transition-all duration-500";
    } else {
      fill.className = "h-1.5 rounded-full bg-emerald-500 transition-all duration-500";
    }
  }

  // Show upgrade prompt if maxed out
  const prompt = document.getElementById("upgradePrompt");
  if (prompt) {
    if (pct >= 100) {
      prompt.classList.remove("hidden");
    } else {
      prompt.classList.add("hidden");
    }
  }
}

// ─────────────────────────────────────────────
//  Render Results Table
// ─────────────────────────────────────────────
function renderTable(allRoutes, unsecuredRoutes, score, target) {
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  const unsecuredPaths = new Set(
    unsecuredRoutes.map(r => `${r.method}:${r.route}`)
  );

  const findingMap = {};
  unsecuredRoutes.forEach(r => {
    findingMap[`${r.method}:${r.route}`] = r;
  });

  allRoutes.forEach(r => {
    const key        = `${r.method}:${r.route}`;
    const isUnsecured = unsecuredPaths.has(key);
    const finding    = findingMap[key] || r;

    // ← fixed: pass isSecured so Safe only shows on truly secured routes
    const risk       = getRisk(finding, !isUnsecured);

    const tags = (finding.compliance || [])
      .map(t => `<span class="mono text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">${t}</span>`)
      .join(" ");

    const methodCls = METHOD_COLORS[r.method] || "bg-gray-800 text-gray-400";

    tbody.innerHTML += `
      <tr class="hover:bg-gray-900 transition">
        <td class="mono text-xs text-gray-300 px-4 py-3 truncate">${r.route}</td>
        <td class="px-4 py-3">
          <span class="mono text-xs font-medium px-2 py-1 rounded ${methodCls}">
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
          <span class="mono text-xs px-2 py-1 rounded ${risk.cls}">${risk.label}</span>
        </td>
        <td class="px-4 py-3">
          <div class="flex gap-1 flex-wrap">
            ${tags || '<span class="text-gray-700 text-xs">—</span>'}
          </div>
        </td>
      </tr>`;
  });

  // Update stat cards
  const sc = Math.round(score);
  const scoreEl = document.getElementById("statScore");
  if (scoreEl) {
    scoreEl.textContent = sc + "%";
    scoreEl.className = `text-3xl font-bold ${
      sc >= 80 ? "text-emerald-400" :
      sc >= 50 ? "text-yellow-400"  :
                 "text-red-400"
    }`;
  }

  const totalEl = document.getElementById("statTotal");
  if (totalEl) totalEl.textContent = allRoutes.length;

  const unsecuredEl = document.getElementById("statUnsecured");
  if (unsecuredEl) unsecuredEl.textContent = unsecuredRoutes.length;

  document.getElementById("resultsSection").classList.remove("hidden");
}

// ─────────────────────────────────────────────
//  Main Scan Function
// ─────────────────────────────────────────────
async function runScan() {
  const url    = document.getElementById("urlInput").value.trim();
  const keyEl  = document.getElementById("apiKeyInput");
  const apiKey = keyEl ? keyEl.value.trim() : "your-free-key";
  const btn    = document.getElementById("scanBtn");
  const spinner = document.getElementById("spinner");
  const label  = document.getElementById("btnLabel");
  const errMsg = document.getElementById("errorMsg");

  errMsg.classList.add("hidden");

  // Validate URL
  if (!url) {
    errMsg.textContent = "Please enter a FastAPI URL to scan.";
    errMsg.classList.remove("hidden");
    return;
  }

  // Validate API key
  if (!apiKey || apiKey === "your-free-key") {
    errMsg.textContent = "Please enter your API key from /auth/register.";
    errMsg.classList.remove("hidden");
    return;
  }

  // Save key for this session so user doesn't retype
  sessionStorage.setItem("shepherd_api_key", apiKey);

  btn.disabled = true;
  spinner.classList.remove("hidden");
  label.textContent = "Scanning...";

  try {
    const res = await fetch("http://127.0.0.1:8000/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey
      },
      body: JSON.stringify({ target_url: url })
    });

    const data = await res.json();

    // ── Tier limit hit ──
    if (res.status === 429) {
      errMsg.textContent = "⚠️ " + data.detail;
      errMsg.classList.remove("hidden");
      updateUsageBar({ scans_used: 1, scans_limit: 1, tier: "free" });
      return;
    }

    // ── Auth error ──
    if (res.status === 401) {
      errMsg.textContent = "Invalid API key. Register at /auth/register.";
      errMsg.classList.remove("hidden");
      return;
    }

    // ── Other errors ──
    if (!res.ok) {
      errMsg.textContent = "Error: " + (data.detail || "Scan failed.");
      errMsg.classList.remove("hidden");
      return;
    }

    // ── Success ──
    renderTable(
      data.findings,
      data.findings,
      data.score,
      data.target
    );

    // Update usage bar with real data from backend
    updateUsageBar(data.usage);

  } catch (err) {
    errMsg.textContent = "Error: " + err.message;
    errMsg.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
    label.textContent = "Run scan";
  }
}