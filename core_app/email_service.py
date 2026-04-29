# email_service.py
import urllib.parse
from datetime import datetime

# ─────────────────────────────────────────────
#  Manual Configuration (Option 3: Mock/Debug)
# ─────────────────────────────────────────────

def get_mailto_link(to_email, subject, body_text):
    """
    Creates a link that opens the user's default email client 
    with the subject and body pre-filled.
    """
    params = {
        "subject": subject,
        "body": body_text
    }
    # Using quote_plus to ensure spaces and special characters are URL-safe
    return f"mailto:{to_email}?{urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}"

def send_scan_alert(
    to_email:       str,
    target_url:     str,
    score:          float,
    total_unsecured: int,
    critical_count:  int,
    findings:       list,
):
    now = datetime.now().strftime("%B %d, %Y at %H:%M UTC")
    verdict = (
        "Healthy"   if score >= 80 else
        "At Risk"  if score >= 50 else
        "Critical"
    )
    
    # 1. Generate Findings Summary
    findings_summary = ""
    for f in findings[:5]:
        status = "CRITICAL" if f.get('is_critical') else "Warning"
        findings_summary += f"- {f.get('method')} {f.get('route')} ({status})\n"

    subject = f"🛡️ Shepherd AI: {verdict} — {total_unsecured} unprotected route(s) found"
    
    body_text = (
        f"SHEPHERD AI SECURITY ALERT\n"
        f"Timestamp: {now}\n"
        f"Target: {target_url}\n\n"
        f"SECURITY SCORE: {score:.1f}% ({verdict})\n"
        f"Unprotected Routes: {total_unsecured}\n"
        f"Critical Issues: {critical_count}\n\n"
        f"TOP FINDINGS:\n{findings_summary}\n"
        f"View full report at: http://127.0.0.1:8000/dashboard"
    )

    # --- Option 3: Mock Output to Terminal ---
    print("\n" + "="*50)
    print(f"📧 MOCK EMAIL LOG: Scan Alert to {to_email}")
    print(f"Subject: {subject}")
    print("-" * 50)
    print(body_text)
    print("="*50 + "\n")

    return {
        "sent": False, # Explicitly false since we aren't using an API
        "manual_mode": True,
        "subject": subject,
        "body": body_text,
        "mailto_link": get_mailto_link(to_email, subject, body_text)
    }

def send_welcome_email(to_email: str, api_key: str, tier: str):
    tier_limit = {
        "free": "1 scan/month", 
        "starter": "10 scans/month",
        "pro": "Unlimited scans", 
        "enterprise": "Unlimited scans"
    }.get(tier, "—")

    subject = "🛡️ Welcome to Shepherd AI — Your API key is inside"
    body_text = (
        f"Welcome aboard to Shepherd AI!\n\n"
        f"Your account is ready. Details:\n"
        f"PLAN: {tier.upper()}\n"
        f"LIMIT: {tier_limit}\n"
        f"API KEY: {api_key}\n\n"
        f"Keep this key safe. Start scanning at: http://127.0.0.1:8000/dashboard"
    )

    # --- Option 3: Mock Output to Terminal ---
    print("\n" + "="*50)
    print(f"📧 MOCK EMAIL LOG: Welcome Email to {to_email}")
    print(f"Subject: {subject}")
    print("-" * 50)
    print(body_text)
    print("="*50 + "\n")

    return {
        "sent": False,
        "manual_mode": True,
        "subject": subject,
        "body": body_text,
        "mailto_link": get_mailto_link(to_email, subject, body_text)
    }