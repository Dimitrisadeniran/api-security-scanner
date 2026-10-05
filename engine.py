# engine.py — Shepherd AI v2.0 (Multi-Tier Architecture)
# Compliance-first API risk scoring: NDPA / PCI / HIPAA overlap detection,
# severity-tiered findings, and tier-specific auditing modules.

import httpx
import re
import json
import yaml
from datetime import datetime
from enum import Enum
from typing import Tuple, Dict, Any, Optional, List

# 2. ENUMS & CONSTANTS
class TargetType(str, Enum):
    STATIC_SCHEMA = "STATIC_SCHEMA"
    LIVE_ROUTE = "LIVE_ROUTE"
    UNKNOWN = "UNKNOWN"

PROBE_TIMEOUT = 5.0

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

# 3. HELPER & AUTO-DETECTION FUNCTIONS
def _redact(text: str) -> str:
    """Utility to mask sensitive data before recording findings."""
    if len(text) <= 4:
        return "****"
    return text[:2] + "*" * (len(text) - 4) + text[-2:]

async def auto_detect_target(target_input: str) -> Tuple[TargetType, Optional[Dict[str, Any]]]:
    """
    Analyzes the user input (raw JSON/YAML or URL) and classifies it 
    as a Static Schema or a Live API Route in under 200ms.
    """
    target_input = target_input.strip()

    # 1. Check if input is inline raw JSON/YAML text
    if target_input.startswith("{") or target_input.startswith("openapi:") or target_input.startswith("swagger:"):
        try:
            data = json.loads(target_input) if target_input.startswith("{") else yaml.safe_load(target_input)
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                return TargetType.STATIC_SCHEMA, data
        except Exception:
            pass

    # 2. Check if input is a URL
    if target_input.startswith("http://") or target_input.startswith("https://"):
        try:
            async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
                res = await client.get(target_input, headers={"User-Agent": "ShepherdAI-Detector/1.0"})
                
                if res.status_code == 200:
                    try:
                        data = res.json()
                        if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                            return TargetType.STATIC_SCHEMA, data
                    except Exception:
                        pass

                return TargetType.LIVE_ROUTE, None

        except httpx.RequestError:
            return TargetType.LIVE_ROUTE, None

    return TargetType.UNKNOWN, None

# 4. CORE ENGINE WORKERS (Static Audits, Live Probes, Remediation Generators)
async def audit_static_schema(schema: dict) -> list:
    # Existing AST/Schema inspection logic here
    pass

async def probe_single_live_route(target_url: str, auth_header: Optional[str] = None) -> dict:
    # Live HTTP probing logic here
    pass
# 5. MASTER ORCHESTRATOR
async def run_smart_scan(target_input: str, auth_header: Optional[str] = None) -> dict:
    target_type, parsed_schema = await auto_detect_target(target_input)
    
    if target_type == TargetType.STATIC_SCHEMA:
        findings = await audit_static_schema(parsed_schema or target_input)
        return {"mode_detected": TargetType.STATIC_SCHEMA, "findings": findings}
    
    elif target_type == TargetType.LIVE_ROUTE:
        findings = await probe_single_live_route(target_url=target_input, auth_header=auth_header)
        return {"mode_detected": TargetType.LIVE_ROUTE, "findings": findings}
    
    raise ValueError("Unrecognized target format.")
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
    "WARNING":         5,
    "INFO":            1,
}

AUDIT_THRESHOLDS = [
    (85, "AUDIT_READY",        "✅ Audit-ready"),
    (60, "NEEDS_IMPROVEMENT",  "⚠️ Needs improvement before audit"),
    (0,  "NOT_AUDIT_READY",    "🚨 Not audit-ready"),
]

MAX_LIVE_PROBES = 15
PROBE_TIMEOUT = 6.0


def _redact(value: str) -> str:
    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


# ─────────────────────────────────────────────
#  Route-Specific Technical Remediation Engine
# ─────────────────────────────────────────────
def _generate_route_code_remediation(finding: dict, path_details: dict = None) -> str:
    """
    Generates a route-specific, code-level remediation plan including
    flaw analysis and framework code patches (FastAPI / Express).
    """
    route = finding.get("route", "")
    method = finding.get("method", "GET").upper()
    route_lower = route.lower()
    
    # Context flags
    is_confirmed_leak = finding.get("severity") == "CONFIRMED_LEAK"
    compliance_tags = finding.get("compliance", [])
    pii_tags = finding.get("pii_detected", [])
    
    # Path parameters check
    path_params = re.findall(r"\{([^}]+)\}", route)
    
    parts = []

    if is_confirmed_leak:
        parts.append(
            "🔴 **CRITICAL ACTION REQUIRED**: Live data exposure confirmed on this route! "
            "Immediately disable public access or deploy the code patch below to restrict unauthenticated access."
        )

    # 1. BOLA / IDOR Pattern Detection
    if path_params or any(k in route_lower for k in ["user", "account", "profile", "patient", "order"]):
        param_str = ", ".join(path_params) if path_params else "resource_id"
        parts.append(f"""
#### 🚨 Flaw Analysis: Broken Object Level Authorization (BOLA/IDOR)
Route `{method} {route}` handles resource identifiers (`{param_str}`) without verifying if the requesting user owns the object.

#### 🛠️ Code-Level Patch (FastAPI Example):
```python
# BEFORE (Vulnerable): Direct query without ownership scope
@app.{method.lower()}("{route}")
async def get_resource({param_str}: str, db: Session = Depends(get_db)):
    return db.query(Model).filter(Model.id == {param_str}).first()

# AFTER (Secure): Scope query to authenticated user context
@app.{method.lower()}("{route}")
async def get_resource(
    {param_str}: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    resource = db.query(Model).filter(
        Model.id == {param_str}, 
        Model.owner_id == current_user.id
    ).first()
    if not resource:
        raise HTTPException(status_code=403, detail="Access denied to requested resource")
    return resource
```""")

    # 2. Authentication & Sensitive Data Exposure Pattern
    elif any(tag in compliance_tags for tag in ["HIPAA", "PCI", "NDPA"]) or pii_tags:
        parts.append(f"""
#### 🚨 Flaw Analysis: Unprotected Sensitive Data Route
Route `{method} {route}` exposes regulated payload fields ({', '.join(compliance_tags or pii_tags)}) without enforced auth schemes or field sanitization.

#### 🛠️ Code-Level Patch (Express.js Example):
```javascript
// BEFORE (Vulnerable): Exposing raw database objects over open endpoint
app.{method.lower()}('{route}', async (req, res) => {{
  const data = await Database.find(req.query);
  res.json(data);
}});

// AFTER (Secure): JWT Authentication + Field Minimization
app.{method.lower()}('{route}', verifyJwtToken, enforceRole('ADMIN'), async (req, res) => {{
  const data = await Database.find(req.query)
    .select('-password -bvn -cvv -ssn'); // Sanitize sensitive fields
  res.json(data);
}});
```""")

    # 3. Default General Endpoint Patch
    else:
        parts.append(f"""
#### 🚨 Flaw Analysis: Missing Authentication Scheme
Route `{method} {route}` is reachable without an API key, OAuth2 scope, or JWT authorization header.

#### 🛠️ Code-Level Patch (FastAPI Dependency Injection):
```python
from fastapi import Security
from app.auth import get_current_user

@app.{method.lower()}("{route}", dependencies=[Security(get_current_user)])
async def secure_route_handler():
    return {{"status": "protected"}}
```""")

    return "\n".join(parts)


def build_remediation_roadmap(findings: list) -> list:
    severity_order = {"CONFIRMED_LEAK": 0, "CRITICAL": 1, "WARNING": 2, "INFO": 3}

    actionable = [
        f for f in findings
        if f.get("severity") in ("CONFIRMED_LEAK", "CRITICAL", "WARNING")
    ]
    actionable.sort(key=lambda f: severity_order.get(f.get("severity"), 4))

    return [
        {
            "route": f["route"],
            "method": f["method"],
            "severity": f["severity"],
            "remediation": f.get("remediation", _generate_route_code_remediation(f)),
        }
        for f in actionable
    ]


# ─────────────────────────────────────────────
#  Logic: Fetch OpenAPI Schema
# ─────────────────────────────────────────────
async def fetch_openapi_schema(url: str):
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
        "ngrok-skip-browser-warning": "true",
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
#  Helper Functions & Scoring Summary
# ─────────────────────────────────────────────
def _classify_finding(found_tags: list, patterns_found: list, route: str):
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
    message = "ℹ INFO: Route is unsecured but no sensitive-data signals detected"
    return severity, message, False


def _compute_summary(unsecured: list, total_routes: int, protected_count: int):
    security_score = (protected_count / total_routes * 100) if total_routes > 0 else 100.0

    severity_counts = {"CONFIRMED_LEAK": 0, "CRITICAL": 0, "WARNING": 0, "INFO": 0}
    overlap_count = 0
    for f in unsecured:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
        if f.get("is_overlap"):
            overlap_count += 1

    penalty = sum(SEVERITY_WEIGHTS.get(f["severity"], 1) for f in unsecured)
    compliance_score = max(0, round(100 - penalty, 1))

    audit_status_code = "NOT_AUDIT_READY"
    audit_status_label = "🚨 Not audit-ready"
    for threshold, code, label in AUDIT_THRESHOLDS:
        if compliance_score >= threshold:
            audit_status_code = code
            audit_status_label = label
            break

    return {
        "total_routes":         total_routes,
        "protected_routes":     protected_count,
        "unsecured_routes":     len(unsecured),
        "confirmed_leak_count": severity_counts["CONFIRMED_LEAK"],
        "critical_count":       severity_counts["CRITICAL"],
        "warning_count":        severity_counts["WARNING"],
        "info_count":           severity_counts["INFO"],
        "overlap_count":        overlap_count,
        "compliance_score":     compliance_score,
        "audit_status":         audit_status_code,
        "audit_status_label":   audit_status_label,
    }, security_score


# ─────────────────────────────────────────────
#  Core Schema Finding Logic (Base / Starter)
# ─────────────────────────────────────────────
def find_unsecured_routes(schema: dict, custom_keywords: list = None):
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

            finding_entry = {
                "route":          route,
                "method":         method.upper(),
                "summary":        details.get("summary", "N/A"),
                "compliance":     found_tags,
                "pii_detected":   patterns_found,
                "severity":       severity,
                "message":        message,
                "is_overlap":      is_overlap,
                "confirmed_leak": False,
                "leak_evidence":  [],
                "is_critical":    severity == "CRITICAL",
            }

            # Generate route-specific code remediation
            finding_entry["remediation"] = _generate_route_code_remediation(finding_entry, details)
            unsecured.append(finding_entry)

    summary, security_score = _compute_summary(unsecured, total_routes, protected_count)
    return unsecured, security_score, summary


# ─────────────────────────────────────────────
#  Tier-Specific Additional Checks
# ─────────────────────────────────────────────
async def check_professional_headers_and_cors(target_url: str, unsecured: list):
    """
    Professional Tier: Checks root target for wildcard CORS and missing basic security headers.
    """
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, follow_redirects=True) as client:
            resp = await client.options(target_url)
            headers = resp.headers

            # 1. CORS check
            if headers.get("access-control-allow-origin") == "*":
                cors_finding = {
                    "route": "/",
                    "method": "OPTIONS",
                    "summary": "CORS Policy Check",
                    "compliance": [],
                    "pii_detected": [],
                    "severity": "WARNING",
                    "message": "⚠️ WARNING: Global Wildcard CORS (`Access-Control-Allow-Origin: *`) enabled.",
                    "is_overlap": False,
                    "confirmed_leak": False,
                    "leak_evidence": [],
                    "is_critical": False,
                }
                cors_finding["remediation"] = (
                    "Restrict `Access-Control-Allow-Origin` headers to explicit whitelisted domains "
                    "rather than wildcards (`*`)."
                )
                unsecured.append(cors_finding)

            # 2. Basic Security Headers check
            missing = []
            if "strict-transport-security" not in headers:
                missing.append("HSTS")
            if "x-content-type-options" not in headers:
                missing.append("X-Content-Type-Options")

            if missing:
                headers_finding = {
                    "route": "/",
                    "method": "HEAD",
                    "summary": "HTTP Security Headers Check",
                    "compliance": [],
                    "pii_detected": [],
                    "severity": "INFO",
                    "message": f"ℹ️ INFO: Missing recommended security headers: {', '.join(missing)}.",
                    "is_overlap": False,
                    "confirmed_leak": False,
                    "leak_evidence": [],
                    "is_critical": False,
                }
                headers_finding["remediation"] = (
                    f"Inject missing headers ({', '.join(missing)}) via server middleware."
                )
                unsecured.append(headers_finding)
    except Exception:
        pass


async def check_business_rate_limiting(target_url: str, unsecured: list):
    """
    Business Tier: Probes key endpoints for rate limit header presence.
    """
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(target_url)
            headers = resp.headers

            has_rate_limit = any(h in headers for h in ["x-ratelimit-limit", "retry-after", "ratelimit-limit"])
            if not has_rate_limit:
                rl_finding = {
                    "route": "/",
                    "method": "GET",
                    "summary": "Rate Limiting Policy Check",
                    "compliance": [],
                    "pii_detected": [],
                    "severity": "WARNING",
                    "message": "⚠️ WARNING: Target endpoint missing standard Rate-Limiting response headers.",
                    "is_overlap": False,
                    "confirmed_leak": False,
                    "leak_evidence": [],
                    "is_critical": False,
                }
                rl_finding["remediation"] = (
                    "Attach rate-limiting middleware (e.g. `slowapi` or Redis token bucket) "
                    "returning `429 Too Many Requests` on excessive hits."
                )
                unsecured.append(rl_finding)
    except Exception:
        pass


def _has_path_params(route: str) -> bool:
    return "{" in route and "}" in route


async def probe_for_leaks(base_url: str, unsecured: list, total_routes: int, protected_count: int):
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
        "ngrok-skip-browser-warning": "true",
    }

    async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, follow_redirects=True) as client:
        for finding in candidates:
            full_url = base + finding["route"]
            try:
                response = await client.get(full_url, headers=headers)
            except httpx.RequestError:
                continue

            if response.status_code != 200:
                continue

            body_text = response.text[:20000]

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
                # Refresh remediation text to highlight live leak
                finding["remediation"] = _generate_route_code_remediation(finding)

    summary, security_score = _compute_summary(unsecured, total_routes, protected_count)
    return summary


# ─────────────────────────────────────────────
#  Master Orchestrator (Tier-Aware Scanner)
# ─────────────────────────────────────────────
async def run_tier_based_scan(
    target_url: str, 
    user_tier: str = "starter", 
    custom_keywords: list = None
):
    """
    Executes tiered security checks based on user subscription level.
    """
    # 1. Fetch Schema & Run Base OpenAPI Inspection
    schema = await fetch_openapi_schema(target_url)
    unsecured, security_score, summary = find_unsecured_routes(
        schema, 
        custom_keywords=custom_keywords if user_tier == "enterprise" else None
    )

    total_routes = summary["total_routes"]
    protected_count = summary["protected_routes"]

    # 2. Professional+ Tier Features: CORS & Header Analysis
    if user_tier in {"professional", "business", "enterprise"}:
        await check_professional_headers_and_cors(target_url, unsecured)

    # 3. Business+ Tier Features: Rate Limiting & Live PII Probing
    if user_tier in {"business", "enterprise"}:
        await check_business_rate_limiting(target_url, unsecured)
        summary = await probe_for_leaks(target_url, unsecured, total_routes, protected_count)
    else:
        # Re-compute summary if CORS/Header checks added new findings
        summary, security_score = _compute_summary(unsecured, total_routes, protected_count)

    return {
        "findings": unsecured,
        "security_score": security_score,
        "summary": summary
    }
