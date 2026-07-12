# slack_service.py — Shepherd AI v2.0
import httpx
from datetime import datetime

SEVERITY_LABELS = {
    "CONFIRMED_LEAK": "🔴 CONFIRMED LEAK",
    "CRITICAL":        "🚨 Critical",
    "WARNING":          "⚠️ Warning",
    "INFO":             "ℹ️ Info",
}


def _get_severity(finding: dict) -> str:
    """
    Reads finding['severity'] if present (v2.0 findings).
    Falls back to the old is_critical/compliance boolean logic for any
    finding shape that predates the severity field.
    """
    if finding.get("severity"):
        return finding["severity"]
    if finding.get("is_critical"):
        return "CRITICAL"
    if finding.get("compliance"):
        return "WARNING"
    return "INFO"


def send_slack_alert(
    webhook_url: str,
    target_url: str,
    score: float,
    total_unsecured: int,
    critical_count: int,
    findings: list,
    compliance_score: float = None,
    audit_status_label: str = None,
    confirmed_leak_count: int = 0,
) -> dict:
    """
    Sends a Shepherd AI compliance scan alert to a Slack channel
    via an Incoming Webhook URL.
    Get your webhook at: https://api.slack.com/messaging/webhooks

    compliance_score / audit_status_label / confirmed_leak_count are
    optional (v2.0 fields) — the alert still renders correctly without
    them, just without the compliance-readiness fields.
    """
    now = datetime.now().strftime("%b %d, %Y at %H:%M UTC")

    # Color/verdict driven by compliance score when available (the more
    # meaningful number), falling back to the structural security score.
    headline_score = compliance_score if compliance_score is not None else score
    verdict = (
        "✅ Healthy"  if headline_score >= 80 else
        "⚠️ At Risk" if headline_score >= 50 else
        "🚨 Critical"
    )
    color = (
        "#10b981" if headline_score >= 80 else
        "#f59e0b" if headline_score >= 50 else
        "#ef4444"
    )

    # Sort findings so CONFIRMED_LEAK / CRITICAL surface first
    severity_order = {"CONFIRMED_LEAK": 0, "CRITICAL": 1, "WARNING": 2, "INFO": 3}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(_get_severity(f), 4))

    findings_text = ""
    for f in findings_sorted[:5]:
        severity = _get_severity(f)
        risk = SEVERITY_LABELS.get(severity, "Low")
        fw   = ", ".join(f.get("compliance", [])) or "—"
        findings_text += f"• `{f.get('method')} {f.get('route')}` — {risk} | {fw}\n"

    if len(findings) > 5:
        findings_text += f"_...and {len(findings) - 5} more. Download the PDF report for full details._\n"
    if not findings_text:
        findings_text = "✅ No unprotected routes detected."

    fields = [
        {"type": "mrkdwn", "text": f"*Status*\n{verdict}"},
    ]
    if compliance_score is not None:
        fields.append({"type": "mrkdwn", "text": f"*Compliance Score*\n{compliance_score}/100"})
    else:
        fields.append({"type": "mrkdwn", "text": f"*Security Score*\n{score:.1f}%"})
    fields.append({"type": "mrkdwn", "text": f"*Unprotected Routes*\n{total_unsecured}"})
    fields.append({"type": "mrkdwn", "text": f"*Critical Findings*\n{critical_count}"})

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ Shepherd AI — Compliance Scan Complete"}
        },
        {"type": "section", "fields": fields},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Target:* `{target_url}`\n*Scanned:* {now}"}
        },
    ]

    if audit_status_label:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Audit Status:* {audit_status_label}"}
        })

    if confirmed_leak_count > 0:
        plural = "s" if confirmed_leak_count != 1 else ""
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"🔴 *{confirmed_leak_count} CONFIRMED data leak{plural}* found in live API "
                    f"responses — real sensitive data was returned by an unsecured route. "
                    f"Highest priority to fix."
                )
            }
        })

    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": f"*Unprotected Routes:*\n{findings_text}"}
    })
    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": "Shepherd AI • Compliance-First API Risk Scoring — NDPA · PCI · HIPAA"}
        ]
    })

    payload = {"attachments": [{"color": color, "blocks": blocks}]}

    try:
        response = httpx.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 200:
            return {"sent": True}
        else:
            return {"sent": False, "error": f"Slack returned {response.status_code}: {response.text}"}
    except Exception as e:
        return {"sent": False, "error": str(e)}
