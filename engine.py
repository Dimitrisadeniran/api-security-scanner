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
#  Logic: Find Unsecured Routes
# ─────────────────────────────────────────────
def find_unsecured_routes(schema: dict):
    unsecured = []
    total_routes = 0
    protected_count = 0
    paths = schema.get("paths", {})

    for route, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
            
        for method, details in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
                
            total_routes += 1
            
            # Check for security schemes
            route_security = details.get("security")
            is_unsecured = route_security is None or route_security == []
            
            if not is_unsecured:
                protected_count += 1
                continue

            # Analyze text for sensitivity
            searchable_text = (
                f"{route} "
                f"{details.get('summary', '')} "
                f"{details.get('description', '')}"
            ).lower()

            found_tags = []
            for tag, words in SENSITIVE_KEYWORDS.items():
                if any(re.search(rf"\b{w}\b", searchable_text, re.I) for w in words):
                    found_tags.append(tag)

            patterns_found = [
                name for name, pat in PII_REGEX.items()
                if re.search(pat, searchable_text)
            ]

            # Critical if it's sensitive AND unprotected
            is_critical = bool(found_tags) or bool(patterns_found) or "phi" in route.lower()

            unsecured.append({
                "route": route,
                "method": method.upper(),
                "summary": details.get("summary", "N/A"),
                "compliance": found_tags,
                "pii_detected": patterns_found,
                "is_critical": is_critical,
            })

    score = (protected_count / total_routes * 100) if total_routes > 0 else 100.0
    return unsecured, score

# ─────────────────────────────────────────────
#  Logic: Async Schema Fetching
# ─────────────────────────────────────────────
async def fetch_openapi_schema(base_url: str):
    """
    Asynchronously fetches the OpenAPI schema. 
    Checks multiple common paths if the first one fails.
    """
    base_url = base_url.rstrip("/")
    # Common paths for FastAPI/Swagger
    potential_paths = ["/openapi.json", "/docs/openapi.json", "/v1/openapi.json"]
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        for path in potential_paths:
            try:
                target = f"{base_url}{path}"
                response = await client.get(target)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                print(f"DEBUG: Failed to fetch from {path}: {e}")
                continue
    
    return None