# engine.py
import httpx
import re
import asyncio
from datetime import datetime

# ─────────────────────────────────────────────
#  Regex & Keywords
# ─────────────────────────────────────────────
PII_REGEX = {
    "NIG_BVN_NIN": r"\b\d{11}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "EMAIL_ADDR":  r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "PHONE_NG":    r"\b(?:234|0)[789][01]\d{8}\b",
    "PATIENT_ID":  r"\bPAT-\d{4,8}\b",
}

SENSITIVE_KEYWORDS = {
    "HIPAA": ["patient", "health", "phi", "medical", "diagnosis", "clinical", "triage"],
    "PCI":   ["card", "payment", "cvv", "billing", "transaction"],
    "NDPA":  ["bvn", "nin", "identity", "passport", "enrollment"],
}

HTTP_METHODS = {"get", "post", "put", "delete", "patch"}

# ─────────────────────────────────────────────
#  Logic: Fetch OpenAPI Schema
# ─────────────────────────────────────────────
async def fetch_openapi_schema(url: str):
    """
    Fetches the openapi.json from the target FastAPI URL.
    Handles URL cleaning (adding /openapi.json if missing).
    """
    target = url.strip()
    # Ensure protocol exists
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    # Ensure it points to the JSON spec
    if not target.endswith("openapi.json"):
        target = target.rstrip("/") + "/openapi.json"

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        response = await client.get(target)
        if response.status_code != 200:
            raise Exception(f"Schema not found at {target} (Status {response.status_code})")
        return response.json()

# ─────────────────────────────────────────────
#  Logic: Find Unsecured Routes
# ─────────────────────────────────────────────
def find_unsecured_routes(schema: dict, custom_keywords: list = []):
    unsecured = []
    total_routes = 0
    protected_count = 0
    paths = schema.get("paths", {})

    # Merge custom keywords for enterprise users
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
                if any(re.search(rf"\b{w}\b", searchable_text, re.I) for w in words):
                    found_tags.append(tag)

            patterns_found = [
                name for name, pat in PII_REGEX.items()
                if re.search(pat, searchable_text)
            ]

            is_critical = bool(found_tags) or bool(patterns_found) or "phi" in route.lower()

            unsecured.append({
                "route":        route,
                "method":       method.upper(),
                "summary":      details.get("summary", "N/A"),
                "compliance":   found_tags,
                "pii_detected": patterns_found,
                "is_critical":  is_critical,
            })

    score = (protected_count / total_routes * 100) if total_routes > 0 else 100.0
    return unsecured, score