# .github/scripts/shepherd_scan.py
# Runs inside GitHub Actions — calls your Shepherd AI API and fails the build
# if critical unprotected PHI routes are found.

import httpx
import json
import os
import sys

API_KEY    = os.environ.get("SHEPHERD_API_KEY", "")
API_URL    = os.environ.get("SHEPHERD_API_URL", "http://127.0.0.1:8000")
TARGET_URL = os.environ.get("TARGET_URL", "")

def run():
    if not API_KEY:
        print("❌ SHEPHERD_API_KEY secret not set in GitHub.")
        sys.exit(1)

    if not TARGET_URL:
        print("❌ TARGET_URL secret not set in GitHub.")
        sys.exit(1)

    print(f"🛡️  Shepherd AI — Scanning {TARGET_URL}")

    try:
        res = httpx.post(
            f"{API_URL}/scan",
            headers={
                "Content-Type": "application/json",
                "x-api-key": API_KEY
            },
            json={"target_url": TARGET_URL},
            timeout=30,
        )
    except Exception as e:
        print(f"❌ Could not connect to Shepherd AI API: {e}")
        sys.exit(1)

    if res.status_code != 200:
        print(f"❌ Scan failed: {res.status_code} — {res.text}")
        sys.exit(1)

    data = res.json()

    # Save report as artifact
    with open("shepherd_report.json", "w") as f:
        json.dump(data, f, indent=2)

    score    = data.get("score", 0)
    findings = data.get("findings", [])
    critical = [f for f in findings if f.get("is_critical")]

    print(f"\n{'═'*50}")
    print(f"  🛡️  SHEPHERD AI SCAN COMPLETE")
    print(f"{'═'*50}")
    print(f"  📊 Score         : {score:.1f}%")
    print(f"  🚨 Unprotected   : {len(findings)}")
    print(f"  🔴 Critical      : {len(critical)}")
    print(f"{'═'*50}\n")

    if critical:
        print("❌ CRITICAL unprotected PHI routes found:\n")
        for f in critical:
            fw = ", ".join(f.get("compliance", [])) or "—"
            print(f"  🚨 {f['method']} {f['route']} | Frameworks: {fw}")
        print(f"\n❌ Build FAILED — fix the above routes before merging.")
        sys.exit(1)  # Fails the GitHub Actions build
    elif findings:
        print("⚠️  Non-critical unprotected routes found — review recommended.")
        print("✅ Build PASSED — no critical PHI routes exposed.")
        sys.exit(0)
    else:
        print("✅ All routes secured. Build PASSED.")
        sys.exit(0)

if __name__ == "__main__":
    run()