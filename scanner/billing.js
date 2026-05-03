// billing.js — Shepherd AI Settings & Billing
"use strict";

const API_BASE = "https://api-security-scanner-qksl.onrender.com";

// ─────────────────────────────────────────────
//  Auth helper
// ─────────────────────────────────────────────
function getApiKey() {
  return localStorage.getItem("shepherd_api_key") || "";
}

function apiHeaders() {
  return {
    "Content-Type": "application/json",
    "x-api-key": getApiKey()
  };
}

// ─────────────────────────────────────────────
//  Load user settings on page load
// ─────────────────────────────────────────────
async function loadUserSettings() {
  const apiKey = getApiKey();

  if (!apiKey) {
    window.location.href = "/scanner/login.html";
    return;
  }

  // Fill API key input
  const apiKeyInput = document.getElementById("api-key-input");
  if (apiKeyInput) apiKeyInput.value = apiKey;

  // Fill email and tier from localStorage
  const email = localStorage.getItem("shepherd_email") || "";
  const tier  = localStorage.getItem("shepherd_tier")  || "free";

  const tierDisplay = document.getElementById("current-tier-display");
  if (tierDisplay) {
    tierDisplay.textContent = tier.toUpperCase();
    const colors = {
      free:       "text-gray-400",
      starter:    "text-blue-400",
      pro:        "text-purple-400",
      enterprise: "text-emerald-400",
    };
    tierDisplay.className = `font-bold ${colors[tier] || "text-gray-400"}`;
  }

  try {
    const res  = await fetch(`${API_BASE}/usage`, {
      headers: apiHeaders()
    });
    const data = await res.json();

    if (res.ok) {
      // Update scan usage display
      const usedEl  = document.getElementById("scans-used");
      const limitEl = document.getElementById("scans-limit");
      if (usedEl)  usedEl.textContent  = data.scans_used;
      if (limitEl) limitEl.textContent = data.scans_limit >= 999999
        ? "∞"
        : data.scans_limit;

      // Update tier display with live data from backend
      if (tierDisplay) tierDisplay.textContent = data.tier.toUpperCase();

      // Save fresh tier to localStorage
      localStorage.setItem("shepherd_tier", data.tier);

      // Highlight the user's current active plan card
      highlightActivePlan(data.tier);

    } else {
      console.error("Failed to load usage:", data.detail);
    }

  } catch (err) {
    console.error("Network error loading settings:", err);
    showStatus("Could not connect to server. Please try again.", "red");
  }
}

// ─────────────────────────────────────────────
//  Highlight the active plan card
// ─────────────────────────────────────────────
function highlightActivePlan(tier) {
  // Remove all active styles first
  document.querySelectorAll(".tier-card").forEach(card => {
    card.classList.remove("featured-card", "border-emerald-500", "border-2");
  });

  // Map tier to card class
  const map = {
    starter:    ".tier-card.starter",
    pro:        ".tier-card.pro",
    enterprise: ".tier-card.enterprise",
  };

  const selector = map[tier];
  if (selector) {
    const card = document.querySelector(selector);
    if (card) {
      card.classList.add("featured-card", "border-emerald-500", "border-2");

      // Add "Current Plan" badge
      const existingBadge = card.querySelector(".current-plan-badge");
      if (!existingBadge) {
        const badge = document.createElement("div");
        badge.className = "current-plan-badge mono text-xs bg-emerald-500 text-black font-bold px-3 py-1 rounded-full absolute top-4 right-4";
        badge.textContent = "Current Plan";
        card.style.position = "relative";
        card.appendChild(badge);
      }
    }
  }
}

// ─────────────────────────────────────────────
//  Show status message
// ─────────────────────────────────────────────
function showStatus(message, color = "white") {
  const el = document.getElementById("status-message");
  if (!el) return;
  el.textContent = message;
  el.classList.remove("hidden");
  el.style.color = color;
}

// ─────────────────────────────────────────────
//  Handle upgrade button click
// ─────────────────────────────────────────────
async function handleUpgrade(requestedTier) {
  const apiKey = getApiKey();

  if (!apiKey) {
    showStatus("Please log in first.", "red");
    return;
  }

  // Map button tier names to backend tier names
  const tierMap = {
    "pro":        "starter",    // your "pro" card = backend "starter"
    "enterprise": "pro",        // your "enterprise" card = backend "pro"
    "starter":    "starter",
  };

  const backendTier = tierMap[requestedTier] || requestedTier;

  showStatus(`Preparing your ${requestedTier.toUpperCase()} subscription...`, "cyan");

  // Disable all upgrade buttons
  document.querySelectorAll("[id$='-btn']").forEach(btn => {
    btn.disabled = true;
    btn.classList.add("opacity-50", "cursor-not-allowed");
  });

  try {
    const res  = await fetch(`${API_BASE}/billing/upgrade`, {
      method:  "POST",
      headers: apiHeaders(),
      body:    JSON.stringify({ new_tier: backendTier })
    });

    const data = await res.json();

    if (res.ok && data.checkout_url) {
      showStatus("Connecting to Paystack checkout...", "white");
      window.location.href = data.checkout_url;
    } else {
      showStatus(`❌ ${data.detail || "Payment gateway error."}`, "red");
      // Re-enable buttons
      document.querySelectorAll("[id$='-btn']").forEach(btn => {
        btn.disabled = false;
        btn.classList.remove("opacity-50", "cursor-not-allowed");
      });
    }

  } catch (err) {
    console.error("Payment error:", err);
    showStatus("Connection error. Please try again or contact support.", "red");
    document.querySelectorAll("[id$='-btn']").forEach(btn => {
      btn.disabled = false;
      btn.classList.remove("opacity-50", "cursor-not-allowed");
    });
  }
}

// ─────────────────────────────────────────────
//  Check if returning from Paystack payment
// ─────────────────────────────────────────────
function checkPaymentStatus() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("billing") === "success") {
    showStatus("✅ Payment successful! Your plan has been upgraded. Refreshing...", "green");
    // Reload usage after 2 seconds to show new tier
    setTimeout(() => {
      loadUserSettings();
      // Clean the URL
      window.history.replaceState({}, "", "/scanner/settings.html");
    }, 2000);
  }
}

// ─────────────────────────────────────────────
//  Toggle API key visibility
// ─────────────────────────────────────────────
function toggleApiKey() {
  const input = document.getElementById("api-key-input");
  const btn   = document.getElementById("show-api-key");
  if (!input) return;

  if (input.type === "password") {
    input.type      = "text";
    btn.textContent = "Hide";
    btn.classList.add("bg-emerald-600");
    btn.classList.remove("bg-gray-800");
  } else {
    input.type      = "password";
    btn.textContent = "Show";
    btn.classList.remove("bg-emerald-600");
    btn.classList.add("bg-gray-800");
  }
}

// ─────────────────────────────────────────────
//  Copy API key
// ─────────────────────────────────────────────
function copyApiKey() {
  const key = getApiKey();
  navigator.clipboard.writeText(key).then(() => {
    showStatus("✅ API key copied to clipboard.", "green");
    setTimeout(() => {
      document.getElementById("status-message")?.classList.add("hidden");
    }, 2000);
  });
}

// ─────────────────────────────────────────────
//  Page load
// ─────────────────────────────────────────────
window.addEventListener("load", () => {
  checkPaymentStatus();
  loadUserSettings();
});