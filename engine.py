# engine.py
import httpx
import re
from datetime import datetime

PII_REGEX = {
    "NIG_BVN_NIN": r"\b\d{11}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "EMAIL_ADDR":  r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "PHONE_NG":    r"\b(?:234|0)[789][01]\d{8}\b",
    "PATIENT_ID":  r"\bPAT-\d{4,8}\b",
}

SENSITIVE_KEYWORDS = {
    "HIPAA": ["patient", "health", "phi", "medical", "diagnosis"],
    "PCI":   ["card", "payment", "cvv", "billing"],
    "NDPA":  ["bvn", "nin", "identity", "passport"],
}

HTTP_METHODS = {"get", "post", "put", "delete", "patch"}

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
            route_security = details.get("security")
            is_unsecured = route_security is None or route_security == []
            if not is_unsecured:
                protected_count += 1
                continue
            searchable_text = (
                f"{route} "
                f"{details.get('summary', '')} "
                f"{details.get('description', '')}"
            )
            found_tags = []
            for tag, words in SENSITIVE_KEYWORDS.items():
                if any(re.search(rf"\b{w}\b", searchable_text, re.I) for w in words):
                    found_tags.append(tag)
            patterns_found = [
                name for name, pat in PII_REGEX.items()
                if re.search(pat, searchable_text)
            ]
            path_danger = "phi" in route.lower()
            unsecured.append({
                "route": route,
                "method": method.upper(),
                "summary": details.get("summary", "N/A"),
                "compliance": found_tags,
                "pii_detected": patterns_found,
                "is_critical": bool(found_tags) or bool(patterns_found) or path_danger,
            })

    score = (protected_count / total_routes * 100) if total_routes > 0 else 100.0
    return unsecured, score

def print_report(unsecured: list, score: float, target_url: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "═" * 50)
    print(" 🛡️  SHEPHERD AI SECURITY REPORT")
    print("═" * 50)
    print(f" 🕐 Time     : {now}")
    print(f" 📊 Score    : {score:.1f}%")
    print(f" 🎯 Target   : {target_url}")
    print(f" 🚨 Unsecured: {len(unsecured)}")
    print("═" * 50)
    if not unsecured:
        print("\n ✅ All scanned routes are secured. Good job!")
        return
    for r in unsecured:
        badge = "🚨 [CRITICAL]" if r["is_critical"] else "⚠️  [WARNING]"
        print(f"\n{badge} [{r['method']}] {r['route']}")
        print(f"   └─ Summary  : {r['summary']}")
        if r["pii_detected"]:
            print(f"   └─ PII Match: {', '.join(r['pii_detected'])}")
        if r["compliance"]:
            print(f"   └─ Framework: {', '.join(r['compliance'])}")

def fetch_openapi_schema(base_url: str):
    url = f"{base_url.rstrip('/')}/openapi.json"
    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"❌ Error fetching schema from {url}: {e}")
        return None