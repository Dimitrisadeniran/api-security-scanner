# slack_service.py
import httpx
from datetime import datetime

def send_slack_alert(
    webhook_url: str,
    target_url: str,
    score: float,
    total_unsecured: int,
    critical_count: int,
    findings: list,
) -> dict:
    """
    Sends a Shepherd AI scan alert to a Slack channel
    via an Incoming Webhook URL.
    Get your webhook at: https://api.slack.com/messaging/webhooks
    """
    now     = datetime.now().strftime("%b %d, %Y at %H:%M UTC")
    verdict = (
        "✅ Healthy"  if score >= 80 else
        "⚠️ At Risk" if score >= 50 else
        "🚨 Critical"
    )
    color = (
        "#10b981" if score >= 80 else
        "#f59e0b" if score >= 50 else
        "#ef4444"
    )

    # Build findings list — cap at 5 for Slack readability
    findings_text = ""
    for f in findings[:5]:
        risk  = "🚨 Critical" if f.get("is_critical") else "⚠️ Warning"
        fw    = ", ".join(f.get("compliance", [])) or "—"
        findings_text += f"• `{f.get('method')} {f.get('route')}` — {risk} | {fw}\n"

    if len(findings) > 5:
        findings_text += f"_...and {len(findings) - 5} more. Download the PDF report for full details._\n"

    if not findings_text:
        findings_text = "✅ No unprotected PHI routes detected."

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🛡️ Shepherd AI — Scan Complete"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Status*\n{verdict}"},
                            {"type": "mrkdwn", "text": f"*Score*\n{score:.1f}%"},
                            {"type": "mrkdwn", "text": f"*Unprotected Routes*\n{total_unsecured}"},
                            {"type": "mrkdwn", "text": f"*Critical Findings*\n{critical_count}"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Target:* `{target_url}`\n*Scanned:* {now}"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Unprotected Routes:*\n{findings_text}"
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "Shepherd AI • HIPAA Compliance Scanner"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    try:
        response = httpx.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 200:
            return {"sent": True}
        else:
            return {"sent": False, "error": f"Slack returned {response.status_code}: {response.text}"}
    except Exception as e:
        return {"sent": False, "error": str(e)}