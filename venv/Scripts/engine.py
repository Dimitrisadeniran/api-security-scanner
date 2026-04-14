import httpx
import re
import json
from datetime import datetime

# ─────────────────────────────────────────────
#  "Red Flag" keywords mapped to compliance tag
# ─────────────────────────────────────────────
SENSITIVE_KEYWORDS: dict[str, list[str]] = {
    "HIPAA": ["patient", "health", "phi", "medical", "record", "diagnosis", "prescription"],
    "PCI":   ["card", "payment", "cvv", "transaction", "bank", "billing", "checkout"],
    "NDPA":  ["bvn", "nin", "address", "phone", "identity", "passport", "dob", "gender"],
}

# Flat list used for regex matching
ALL_KEYWORDS = [(tag, word) for tag, words in SENSITIVE_KEYWORDS.items() for word in words]

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


# ─────────────────────────────────────────────
#  Fetch
# ─────────────────────────────────────────────
def fetch_openapi_schema(base_url: str) -> dict | None:
    """Fetch and return the OpenAPI JSON schema from a given base URL."""
    url = f"{base_url.rstrip('/')}/openapi.json"
    print(f"\n📡 Fetching schema from: {url}")

    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        response.raise_for_status()
        schema = response.json()

        # Validate it's actually an OpenAPI schema
        if not isinstance(schema, dict) or "paths" not in schema:
            print("❌ Response is not a valid OpenAPI schema (missing 'paths').")
            return None

        return schema

    except httpx.HTTPStatusError as e:
        print(f"❌ HTTP error {e.response.status_code}: {e.request.url}")
    except httpx.RequestError as e:
        print(f"❌ Could not reach the API: {e}")
    except json.JSONDecodeError:
        print("❌ Response is not valid JSON.")

    return None


# ─────────────────────────────────────────────
#  Keyword matcher (word-boundary safe)
# ─────────────────────────────────────────────
def detect_sensitive_keywords(text: str) -> dict[str, list[str]]:
    """
    Returns a dict of { compliance_tag: [matched_words] }
    Uses word-boundary regex to avoid false positives.
    """
    hits: dict[str, list[str]] = {}
    for tag, word in ALL_KEYWORDS:
        if re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
            hits.setdefault(tag, []).append(word)
    return hits


# ─────────────────────────────────────────────
#  Route Scanner
# ─────────────────────────────────────────────
def find_unsecured_routes(schema: dict) -> list[dict]:
    """
    Scan all paths in the schema.
    Returns a list of unsecured route findings with compliance context.
    """
    unsecured = []
    paths = schema.get("paths", {})

    for route, path_item in paths.items():
        # Skip non-dict path items (malformed specs)
        if not isinstance(path_item, dict):
            continue

        for method, details in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue  # skip 'parameters', 'summary', etc. at path level

            if not isinstance(details, dict):
                continue

            # ── Security check ──────────────────────────────────────────
            # A route is "secured" if it has a non-empty 'security' key
            route_security = details.get("security")
            is_unsecured = route_security is None or route_security == []

            if not is_unsecured:
                continue

            # ── Sensitive keyword scan ───────────────────────────────────
            searchable_text = " ".join([
                route,
                details.get("summary", ""),
                details.get("description", ""),
                " ".join(details.get("tags", [])),
            ]).lower()

            compliance_hits = detect_sensitive_keywords(searchable_text)

            unsecured.append({
                "route":       route,
                "method":      method.upper(),
                "summary":     details.get("summary", "N/A"),
                "tags":        details.get("tags", []),
                "compliance":  compliance_hits,          # { "HIPAA": ["patient"], ... }
                "is_critical": bool(compliance_hits),
            })

    return unsecured


# ─────────────────────────────────────────────
#  Report Printer
# ─────────────────────────────────────────────
def print_report(unsecured: list[dict], target_url: str) -> None:
    """Print a formatted security report to the terminal."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    critical = [r for r in unsecured if r["is_critical"]]
    warnings  = [r for r in unsecured if not r["is_critical"]]

    print("\n" + "═" * 50)
    print("  🛡️  SHEPHERD AI — SECURITY SCAN REPORT")
    print("═" * 50)
    print(f"  Target : {target_url}")
    print(f"  Time   : {now}")
    print(f"  Total  : {len(unsecured)} unsecured route(s) found")
    print(f"           🚨 {len(critical)} Critical  |  ⚠️  {len(warnings)} Warning")
    print("═" * 50)

    if not unsecured:
        print("\n  ✅ All scanned routes appear to be secured. Great job!\n")
        return

    # Print criticals first
    for r in critical + warnings:
        badge = "🚨 [CRITICAL]" if r["is_critical"] else "⚠️  [WARNING]"
        print(f"\n{badge} [{r['method']}] {r['route']}")
        print(f"   └─ Summary : {r['summary']}")

        if r["tags"]:
            print(f"   └─ Tags    : {', '.join(r['tags'])}")

        if r["compliance"]:
            for framework, words in r["compliance"].items():
                print(f"   └─ {framework:<6} : {', '.join(words)}")

        print("  " + "─" * 46)

    print()


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("╔══════════════════════════════════╗")
    print("║   🛡️  Shepherd AI Scanner v0.2   ║")
    print("╚══════════════════════════════════╝")
    print("💡 Tip: Try https://petstore3.swagger.io for a live test\n")

    target_url = input("Enter the FastAPI Base URL to scan: ").strip()

    if not target_url:
        print("❌ No URL entered. Exiting.")
        exit(1)

    schema = fetch_openapi_schema(target_url)

    if schema:
        info = schema.get("info", {})
        print(f"✅ Schema loaded: \"{info.get('title', 'Unknown API')}\" v{info.get('version', '?')}")

        unsecured = find_unsecured_routes(schema)
        print_report(unsecured, target_url)