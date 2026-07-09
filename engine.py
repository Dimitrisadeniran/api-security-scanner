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
    "CONFIRMED_LEAK": 25,
    "CRITICAL":       12,
    "WARNING":        5,
    "INFO":           1,
}

AUDIT_THRESHOLDS = [
    (85, "AUDIT_READY",        "✅ Audit-ready"),
    (60, "NEEDS_IMPROVEMENT",  "⚠️ Needs improvement before audit"),
    (0,  "NOT_AUDIT_READY",    "🚨 Not audit-ready"),
]

# Max number of live GET requests fired per scan, and per-request timeout.
# Keeps probing bounded so a scan can't hammer someone's production API.
MAX_LIVE_PROBES = 15
PROBE_TIMEOUT = 6.0


def _redact(value: str) -> str:
    """
    Masks a matched sensitive value before it's ever stored or displayed.
    Shows only enough to confirm a real match occurred (first 2 / last 2 chars).
    The full value is never persisted anywhere.
    """
    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"

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

def _compute_summary(unsecured: list, total_routes: int, protected_count: int):
    """
    Computes security score, compliance score, and audit status from a
    findings list. Shared by both the schema-only pass and the post-probe
    pass, so scores stay consistent regardless of when they're computed.
    """
    security_score = (protected_count / total_routes * 100) if total_routes > 0 else 100.0

    severity_counts = {"CONFIRMED_LEAK": 0, "CRITICAL": 0, "WARNING": 0, "INFO": 0}
    overlap_count = 0
    for f in unsecured:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
        if f.get("is_overlap"):
            overlap_count += 1

    penalty = sum(SEVERITY_WEIGHTS[f["severity"]] for f in unsecured)
    compliance_score = max(0, round(100 - penalty, 1))

    audit_status_code = "NOT_AUDIT_READY"
    audit_status_label = "🚨 Not audit-ready"
    for threshold, code, label in AUDIT_THRESHOLDS:
        if compliance_score >= threshold:
            audit_status_code = code
            audit_status_label = label
            break

    return {
        "total_routes":       total_routes,
        "protected_routes":   protected_count,
        "unsecured_routes":   len(unsecured),
        "confirmed_leak_count": severity_counts["CONFIRMED_LEAK"],
        "critical_count":     severity_counts["CRITICAL"],
        "warning_count":      severity_counts["WARNING"],
        "info_count":         severity_counts["INFO"],
        "overlap_count":      overlap_count,
        "compliance_score":   compliance_score,
        "audit_status":       audit_status_code,
        "audit_status_label": audit_status_label,
    }, security_score

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

            unsecured.append({
                "route":         route,
                "method":        method.upper(),
                "summary":       details.get("summary", "N/A"),
                "compliance":    found_tags,
                "pii_detected":  patterns_found,
                "severity":      severity,
                "message":       message,
                "is_overlap":    is_overlap,
                "confirmed_leak": False,
                "leak_evidence":  [],
                # kept for backward compatibility with existing frontend/PDF code
                "is_critical":   severity == "CRITICAL",
            })

    summary, security_score = _compute_summary(unsecured, total_routes, protected_count)

    # Returns: (findings list, structural security score, compliance summary dict)
    return unsecured, security_score, summary

# ─────────────────────────────────────────────
#  Logic: Live Leak Probing (v2.0 — the literal "detect leaks" feature)
# ─────────────────────────────────────────────
def _has_path_params(route: str) -> bool:
    return "{" in route and "}" in route


async def probe_for_leaks(base_url: str, unsecured: list, total_routes: int, protected_count: int):
    """
    For unsecured GET routes with no path parameters, sends a real request
    and scans the ACTUAL response body for PII patterns.

    - Bounded to MAX_LIVE_PROBES requests per scan.
    - Only GET (never mutates data on the target system).
    - Never stores the real matched value — only a redacted preview and
      the pattern type, so Shepherd AI never becomes a second copy of
      whatever sensitive data it finds.

    Mutates `unsecured` in place (upgrades matching findings to
    CONFIRMED_LEAK) and returns a freshly recomputed summary dict.
    """
    base = base_url.strip()
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    base = base.rstrip("/")

    candidates = [
        f for f in unsecured
        if f["method"] == "GET" and not _has_path_params(f["route"])
    ][:MAX_LIVE_PROBES]

    if not candidates:
        summary, security_score = _compute_summary(unsecured, total_routes, protected_count)
        return summary

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; ShepherdAI-Scanner/2.0; "
            "+https://api-security-scanner-pq3w.onrender.com)"
        ),
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, follow_redirects=True) as client:
        for finding in candidates:
            full_url = base + finding["route"]
            try:
                response = await client.get(full_url, headers=headers)
            except httpx.RequestError:
                continue  # unreachable route — skip, don't fail the whole scan

            if response.status_code != 200:
                continue

            body_text = response.text[:20000]  # cap how much we scan per response

            evidence = []
            for pattern_name, pattern in PII_REGEX.items():
                match = re.search(pattern, body_text)
                if match:
                    evidence.append({
                        "type":    pattern_name,
                        "preview": _redact(match.group(0)),
                    })

            if evidence:
                finding["confirmed_leak"] = True
                finding["leak_evidence"]  = evidence
                finding["severity"] = "CONFIRMED_LEAK"
                types = ", ".join(e["type"] for e in evidence)
                finding["message"] = (
                    f"🔴 CONFIRMED LEAK: Live response from this unsecured route "
                    f"contains real {types} data ({', '.join(e['preview'] for e in evidence)})"
                )
                finding["is_critical"] = True

    summary, security_score = _compute_summary(unsecured, total_routes, protected_count)
    return summary
