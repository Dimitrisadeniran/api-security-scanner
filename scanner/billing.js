"use strict";

const BILLING_API_BASE = "https://api-security-scanner-qksl.onrender.com/api";

// ─────────────────────────────────────────────
//  Boot — runs on page load
// ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function () {
  const key   = localStorage.getItem("shepherd_api_key");
  const email = localStorage.getItem("shepherd_email");
  const tier  = localStorage.getItem("shepherd_tier") || "free";

  // Load API key into the input
  const keyInput = document.getElementById("api-key-input");
  if (keyInput && key) keyInput.value = key;

  // Show current tier
  const tierDisplay = document.getElementById("current-tier-display");
  if (tierDisplay) tierDisplay.textContent = tier.toUpperCase();

  // Highlight active tier card
  highlightActiveTier(tier);

  // Fetch live usage from server
  fetchUsage(key);
});

// ─────────────────────────────────────────────
//  Fetch Usage
// ─────────────────────────────────────────────
async function fetchUsage(key) {
  if (!key) return;
  try {
    const res  = await fetch(`${BILLING_API_BASE}/usage`, {
      headers: { "x-api-key": key, "Accept": "application/json" }
    });
    if (!res.ok) return;
    const data = await res.json();

    const used      = data.scans_used  ?? 0;
    const limit     = data.scans_limit ?? 0;
    const unlimited = limit >= 999999;

    const usedEl  = document.getElementById("scans-used");
    const limitEl = document.getElementById("scans-limit");
    if (usedEl)  usedEl.textContent  = used;
    if (limitEl) limitEl.textContent = unlimited ? "∞" : limit;

    // Update cached tier if server says differently
    if (data.tier) {
      localStorage.setItem("shepherd_tier", data.tier);
      const tierDisplay = document.getElementById("current-tier-display");
      if (tierDisplay) tierDisplay.textContent = data.tier.toUpperCase();
      highlightActiveTier(data.tier);
    }
  } catch (_) {}
}

// ─────────────────────────────────────────────
//  Highlight the user's current tier card
// ─────────────────────────────────────────────
function highlightActiveTier(tier) {
  // Remove any existing highlights
  document.querySelectorAll(".tier-card").forEach(card => {
    card.classList.remove("featured-card", "border-emerald-500");
    card.classList.add("border-gray-800");
  });

  const map = { starter: ".tier-card.starter", pro: ".tier-card.pro", enterprise: ".tier-card.enterprise" };
  const selector = map[tier];
  if (selector) {
    const card = document.querySelector(selector);
    if (card) {
      card.classList.remove("border-gray-800");
      card.classList.add("featured-card", "border-emerald-500");
    }
  }

  // Disable buttons for current or lower tiers
  updateButtonStates(tier);
}

// ─────────────────────────────────────────────
//  Update button states based on current tier
// ─────────────────────────────────────────────
function updateButtonStates(tier) {
  const tierRank = { free: 0, starter: 1, pro: 2, enterprise: 3 };
  const current  = tierRank[tier] ?? 0;

  const btnMap = {
    starter:    document.getElementById("starter-btn"),
    pro:        document.getElementById("pro-btn"),
    enterprise: document.getElementById("enterprise-btn"),
  };

  Object.entries(btnMap).forEach(([t, btn]) => {
    if (!btn) return;
    const rank = tierRank[t] ?? 0;
    if (rank <= current) {
      btn.disabled = true;
      btn.textContent = rank === current ? "Current Plan ✓" : "Included";
      btn.classList.add("opacity-50", "cursor-not-allowed");
      btn.classList.remove("bg-emerald-500", "hover:bg-emerald-400");
      btn.classList.add("bg-gray-700");
    }
  });
}

// ─────────────────────────────────────────────
//  Handle Upgrade — calls /api/billing/upgrade
// ─────────────────────────────────────────────
async function handleUpgrade(newTier) {
  const key  = localStorage.getItem("shepherd_api_key");
  const tier = localStorage.getItem("shepherd_tier") || "free";

  if (!key) {
    window.location.replace("/scanner/login.html");
    return;
  }

  // Map visible card names to backend tier names
  const tierMap = { starter: "starter", pro: "pro", enterprise: "enterprise" };
  const backendTier = tierMap[newTier];
  if (!backendTier) return;

  const tierRank = { free: 0, starter: 1, pro: 2, enterprise: 3 };
  if ((tierRank[backendTier] ?? 0) <= (tierRank[tier] ?? 0)) {
    showStatus("⚠ You are already on this plan or higher.", "warning");
    return;
  }

  // Find the right button
  const btnId = `${newTier}-btn`;
  const btn   = document.getElementById(btnId);
  const origText = btn ? btn.textContent : "";

  if (btn) {
    btn.disabled = true;
    btn.textContent = "Redirecting to checkout...";
  }

  showStatus("⏳ Initializing secure checkout via Paystack...", "info");

  try {
    const res = await fetch(`${BILLING_API_BASE}/billing/upgrade`, {
      method:  "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "x-api-key":    key,
      },
      body: JSON.stringify({ new_tier: backendTier }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.detail || `Upgrade failed (${res.status})`);
    }

    if (data.checkout_url) {
      showStatus("✅ Redirecting to Paystack checkout...", "success");
      // Small delay so user sees the message
      setTimeout(() => { window.location.href = data.checkout_url; }, 800);
    } else {
      throw new Error("No checkout URL returned from server.");
    }

  } catch (err) {
    showStatus("❌ " + err.message, "error");
    if (btn) {
      btn.disabled    = false;
      btn.textContent = origText;
    }
  }
}

// ─────────────────────────────────────────────
//  Status Message Helper
// ─────────────────────────────────────────────
function showStatus(message, type = "info") {
  const el = document.getElementById("status-message");
  if (!el) return;

  const styles = {
    info:    "bg-blue-950 border-blue-800 text-blue-300",
    success: "bg-emerald-950 border-emerald-800 text-emerald-300",
    warning: "bg-yellow-950 border-yellow-800 text-yellow-300",
    error:   "bg-red-950 border-red-800 text-red-300",
  };

  el.className = `mono text-center mb-10 px-6 py-3 border rounded-xl text-sm ${styles[type] || styles.info}`;
  el.textContent = message;
  el.classList.remove("hidden");

  // Auto-hide non-error messages after 6s
  if (type !== "error") {
    setTimeout(() => el.classList.add("hidden"), 6000);
  }
}

// ─────────────────────────────────────────────
//  Copy API Key
// ─────────────────────────────────────────────
function copyApiKey() {
  const key = localStorage.getItem("shepherd_api_key") || "";
  if (!key) return;
  navigator.clipboard.writeText(key).then(() => {
    showStatus("✅ API key copied to clipboard.", "success");
  });
}

// ─────────────────────────────────────────────
//  Check for ?billing=success on return from Paystack
// ─────────────────────────────────────────────
(function checkBillingReturn() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("billing") === "success") {
    showStatus("🎉 Payment received! Your plan will update within a few seconds — refresh to confirm.", "success");
    // Remove the query param cleanly
    window.history.replaceState({}, "", window.location.pathname);
  }
})();
