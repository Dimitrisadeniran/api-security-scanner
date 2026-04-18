// results.js — Day 6: Results Table Logic

const METHOD_COLORS = {
  GET:    "bg-blue-950 text-blue-300",
  POST:   "bg-green-950 text-green-300",
  PUT:    "bg-yellow-950 text-yellow-300",
  DELETE: "bg-red-950 text-red-300",
  PATCH:  "bg-pink-950 text-pink-300",
};

function getRisk(finding) {
  if (finding.is_critical) return { label: "Critical", cls: "bg-red-950 text-red-400" };
  if (finding.compliance?.length || finding.pii_detected?.length)
    return { label: "Warning", cls: "bg-yellow-950 text-yellow-400" };
  return { label: "Safe", cls: "bg-green-950 text-green-400" };
}

function renderTable(allRoutes, unsecuredRoutes, score, target) {
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  const unsecuredPaths = new Set(
    unsecuredRoutes.map(r => `${r.method}:${r.route}`)
  );

  const findingMap = {};
  unsecuredRoutes.forEach(r => { findingMap[`${r.method}:${r.route}`] = r; });

  allRoutes.forEach(r => {
    const key = `${r.method}:${r.route}`;
    const isUnsecured = unsecuredPaths.has(key);
    const finding = findingMap[key] || r;
    const risk = isUnsecured ? getRisk(finding) : { label: "Safe", cls: "bg-green-950 text-green-400" };
    const tags = (finding.compliance || [])
      .map(t => `<span class="mono text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">${t}</span>`)
      .join(" ");
    const methodCls = METHOD_COLORS[r.method] || "bg-gray-800 text-gray-400";

    tbody.innerHTML += `
      <tr class="hover:bg-gray-900 transition">
        <td class="mono text-xs text-gray-300 px-4 py-3 truncate">${r.route}</td>
        <td class="px-4 py-3">
          <span class="mono text-xs font-medium px-2 py-1 rounded ${methodCls}">${r.method}</span>
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
          <div class="flex gap-1 flex-wrap">${tags || '<span class="text-gray-700 text-xs">—</span>'}</div>
        </td>
      </tr>`;
  });

  const sc = Math.round(score);
  document.getElementById("statScore").textContent = sc + "%";
  document.getElementById("statScore").className =
    `text-3xl font-bold ${sc >= 80 ? "text-emerald-400" : sc >= 50 ? "text-yellow-400" : "text-red-400"}`;
  document.getElementById("statTotal").textContent = allRoutes.length;
  document.getElementById("statUnsecured").textContent = unsecuredRoutes.length;
  document.getElementById("resultsSection").classList.remove("hidden");
}

async function runScan() {
  const url = document.getElementById("urlInput").value.trim();
  const btn = document.getElementById("scanBtn");
  const spinner = document.getElementById("spinner");
  const label = document.getElementById("btnLabel");
  const errMsg = document.getElementById("errorMsg");

  errMsg.classList.add("hidden");

  if (!url) {
    errMsg.textContent = "Please enter a FastAPI URL to scan.";
    errMsg.classList.remove("hidden");
    return;
  }

  btn.disabled = true;
  spinner.classList.remove("hidden");
  label.textContent = "Scanning...";

  try {
    const res = await fetch("http://127.0.0.1:8000/scan", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": "your-free-key"
  },
  body: JSON.stringify({ target_url: url })
});

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Scan failed.");
    }

    const data = await res.json();

    // Build full route list from findings + assume rest are secured
    renderTable(data.findings, data.findings.filter(f => true), data.score, data.target);

  } catch (err) {
    errMsg.textContent = "Error: " + err.message;
    errMsg.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
    label.textContent = "Run scan";
  }
}