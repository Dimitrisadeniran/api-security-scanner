# engine.py — Shepherd AI v2.0
# Compliance-first API risk scoring: NDPA / PCI / HIPAA overlap detection,
# severity-tiered findings, and an audit-readiness score.

import httpx
import re
from datetime import datetime

# ─────────────────────────────────────────────
#  Regex Patterns (PII / sensitive-data signals)
# ─────────────────────────────────────────────
PII_REGEX = {
    "NIG_BVN_NIN": r"\b\d{11}\b",
    "NIG_NUBAN":   r"\b\d{10}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "EMAIL_ADDR":  r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "PHONE_NG":    r"\b(?:234|0)[789][01]\d{8}\b",
    "PATIENT_ID":  r"\bPAT-\d{4,8}\b",
}

# ─────────────────────────────────────────────
#  Framework Keyword Sets
# ─────────────────────────────────────────────
SENSITIVE_KEYWORDS = {
    "HIPAA": [
        "patient", "health", "phi", "medical", "diagnosis",
        "clinical", "triage", "prescription", "lab", "vitals",
    ],
    "PCI": [
        "card", "payment", "cvv", "billing", "transaction",
        "account_number", "bank_account", "wallet", "payout",
    ],
    "NDPA": [
        "bvn", "nin", "identity", "passport", "enrollment",
        "next_of_kin", "guarantor", "date_of_birth", "dob",
        "address", "nationality", "gender", "marital_status",
        "kyc", "biometric",
    ],
}

# Human-readable labels for output messages
FRAMEWORK_LABELS = {
    "HIPAA": "HIPAA (health data)",
    "PCI":   "PCI-DSS (payment data)",
    "NDPA":  "NDPA (Nigerian personal data)",
    "CUSTOM": "Custom-flagged data",
}

HTTP_METHODS = {"get", "post", "put", "delete", "patch"}

# ─────────────────────────────────────────────
#  Severity weights — used for the compliance score
# ─────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "CRITICAL": 12,
    "WARNING":  5,
    "INFO":     1,
}

AUDIT_THRESHOLDS = [
    (85, "AUDIT_READY",        "✅ Audit-ready"),
    (60, "NEEDS_IMPROVEMENT",  "⚠️ Needs improvement before audit"),
    (0,  "NOT_AUDIT_READY",    "🚨 Not audit-ready"),
]

# ─────────────────────────────────────────────
#  Logic: Fetch OpenAPI Schema
# ─────────────────────────────────────────────
async def fetch_openapi_schema(url: str):
    """
    Fetches the openapi.json from the target FastAPI URL.
    Handles URL cleaning (adding /openapi.json if missing).

    Raises ValueError with a specific, user-facing message on any failure —
    callers should catch ValueError and surface str(e) directly rather than
    a generic message, so the real cause is visible in logs and the UI.
    """
    target = url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not target.endswith("openapi.json"):
        target = target.rstrip("/") + "/openapi.json"

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; ShepherdAI-Scanner/2.0; "
            "+https://api-security-scanner-pq3w.onrender.com)"
        ),
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(target, headers=headers)
    except httpx.ConnectTimeout:
        raise ValueError(f"Connection timed out reaching {target}. The server may be slow or unreachable.")
    except httpx.ConnectError:
        raise ValueError(f"Could not connect to {target}. Check the URL is correct and the server is online.")
    except httpx.RequestError as e:
        raise ValueError(f"Network error reaching {target}: {e}")

    if response.status_code == 404:
        raise ValueError(
            f"No OpenAPI schema found at {target} (404). "
            f"Confirm your API exposes /openapi.json at this path."
        )
    if response.status_code in (401, 403):
        raise ValueError(
            f"Access to {target} was denied ({response.status_code}). "
            f"The schema endpoint may be protected or blocking automated requests."
        )
    if response.status_code != 200:
        raise ValueError(f"Schema not found at {target} (Status {response.status_code}).")

    try:
        schema = response.json()
    except Exception:
        raise ValueError(
            f"{target} responded but did not return valid JSON. "
            f"Confirm this URL serves an OpenAPI schema, not an HTML page."
        )

    if not schema or not isinstance(schema, dict) or "paths" not in schema:
        raise ValueError(
            f"{target} returned JSON, but it doesn't look like a valid OpenAPI schema (no 'paths' found)."
        )

    return schema

# ─────────────────────────────────────────────
#  Helper: Determine severity + message for a route
# ─────────────────────────────────────────────
def _classify_finding(found_tags: list, patterns_found: list, route: str):
    """
    Returns (severity, message, is_overlap) for a single unsecured route.
    """
    overlap = len(found_tags) >= 2
    has_pii_pattern = bool(patterns_found)
    has_framework_hit = bool(found_tags)

    if overlap:
        labels = " + ".join(FRAMEWORK_LABELS.get(t, t) for t in found_tags)
        severity = "CRITICAL"
        message = f"🚨 CRITICAL: Overlapping compliance exposure — {labels} both apply to this route"
        return severity, message, True

    if has_framework_hit:
        tag = found_tags[0]
        severity = "CRITICAL"
        message = f"🚨 CRITICAL: {FRAMEWORK_LABELS.get(tag, tag)} exposure detected — route is unsecured"
        return severity, message, False

    if has_pii_pattern:
        severity = "WARNING"
        message = f"⚠️ WARNING: Possible sensitive data pattern ({', '.join(patterns_found)}) on an unsecured route"
        return severity, message, False

    severity = "INFO"
    message = "ℹ️ INFO: Route is unsecured but no sensitive-data signals detected"
    return severity, message, False

# ─────────────────────────────────────────────
#  Logic: Find Unsecured Routes (v2.0 — severity + compliance scoring)
# ─────────────────────────────────────────────
def find_unsecured_routes(schema: dict, custom_keywords: list = []):
    unsecured = []
    total_routes = 0
    protected_count = 0
    paths = schema.get("paths", {})

    active_keywords = {**SENSITIVE_KEYWORDS}
    if custom_keywords:
        active_keywords["CUSTOM"] = custom_keywords

    severity_counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    overlap_count = 0

    for route, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, details in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue

            total_routes += 1
            route_security = details.get("security")
            is_unsecured = route_security is None or route_security == []

            if not is_unsecured:
                protected_count += 1
                continue

            searchable_text = (
                f"{route} "
                f"{details.get('summary', '')} "
                f"{details.get('description', '')}"
            ).lower()

            found_tags = []
            for tag, words in active_keywords.items():
                if any(re.search(rf"\b{re.escape(w)}\b", searchable_text, re.I) for w in words):
                    found_tags.append(tag)

            patterns_found = [
                name for name, pat in PII_REGEX.items()
                if re.search(pat, searchable_text)
            ]

            severity, message, is_overlap = _classify_finding(found_tags, patterns_found, route)
            severity_counts[severity] += 1
            if is_overlap:
                overlap_count += 1

            unsecured.append({
                "route":         route,
                "method":        method.upper(),
                "summary":       details.get("summary", "N/A"),
                "compliance":    found_tags,
                "pii_detected":  patterns_found,
                "severity":      severity,
                "message":       message,
                "is_overlap":    is_overlap,
                # kept for backward compatibility with existing frontend/PDF code
                "is_critical":   severity == "CRITICAL",
            })

    # ── Structural security score (unchanged behavior: % of routes protected) ──
    security_score = (protected_count / total_routes * 100) if total_routes > 0 else 100.0

    # ── Compliance-readiness score ──
    # Starts at 100, deducts weighted points per finding severity, floors at 0.
    penalty = sum(
        SEVERITY_WEIGHTS[f["severity"]] for f in unsecured
    )
    compliance_score = max(0, round(100 - penalty, 1))

    audit_status_code = "NOT_AUDIT_READY"
    audit_status_label = "🚨 Not audit-ready"
    for threshold, code, label in AUDIT_THRESHOLDS:
        if compliance_score >= threshold:
            audit_status_code = code
            audit_status_label = label
            break

    summary = {
        "total_routes":       total_routes,
        "protected_routes":   protected_count,
        "unsecured_routes":   len(unsecured),
        "critical_count":     severity_counts["CRITICAL"],
        "warning_count":      severity_counts["WARNING"],
        "info_count":         severity_counts["INFO"],
        "overlap_count":      overlap_count,
        "compliance_score":   compliance_score,
        "audit_status":       audit_status_code,
        "audit_status_label": audit_status_label,
    }

    # Returns: (findings list, structural security score, compliance summary dict)
    return unsecured, security_score, summary
