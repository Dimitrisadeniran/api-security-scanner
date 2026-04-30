# main.py — Shepherd AI v0.6 — Production Ready
import io
import json
import hmac
import hashlib
import logging
import requests
from datetime import datetime

from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import database
import pdf_generator
import email_service
import slack_service
import engine
from auth import RegisterRequest, LoginRequest
from config import PAYSTACK_SECRET_KEY, PAYSTACK_BASE_URL, TIER_PRICES

# ─────────────────────────────────────────────
#  Logging & Rate Limiter
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ShepherdAI")
limiter = Limiter(key_func=get_remote_address)

# ─────────────────────────────────────────────
#  App Init
# ─────────────────────────────────────────────
app = FastAPI(
    title="Shepherd AI - Scanner API",
    description="HIPAA Compliance Scanner for Health Tech APIs",
    version="0.6"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend at /scanner route
app.mount("/scanner", StaticFiles(directory="scanner", html=True), name="scanner")

@app.on_event("startup")
def on_startup():
    database.init_db()
    logger.info("🚀 Shepherd AI ready.")

# ─────────────────────────────────────────────
#  Models
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str

class ReportRequest(BaseModel):
    target_url:   str
    score:        float
    findings:     list
    company_name: str = "Shepherd AI"

class AlertSettingsRequest(BaseModel):
    email_alerts: bool = True
    alert_email:  str  = ""

class TestAlertRequest(BaseModel):
    alert_email: str

class SlackSettingsRequest(BaseModel):
    webhook_url:  str
    slack_alerts: bool = True

class EnterpriseSettingsRequest(BaseModel):
    company_name:    str = "Shepherd AI"
    logo_url:        str = ""
    custom_keywords: str = ""

class BillingUpgradeRequest(BaseModel):
    new_tier: str

# ─────────────────────────────────────────────
#  Auth Dependency
# ─────────────────────────────────────────────
async def verify_api_key(x_api_key: str = Header(...)):
    user = database.get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return user

# ─────────────────────────────────────────────
#  Auth Routes
# ─────────────────────────────────────────────
@app.post("/auth/register")
def register(body: RegisterRequest):
    allowed_tiers = {"free", "starter", "pro", "enterprise"}
    if body.tier not in allowed_tiers:
        raise HTTPException(status_code=400, detail="Invalid tier.")
    result = database.create_user(body.email, body.password, body.tier)
    if not result:
        raise HTTPException(status_code=409, detail="Email already exists.")
    email_service.send_welcome_email(body.email, result["api_key"], body.tier)
    return {"message": "Account created.", "api_key": result["api_key"], "tier": body.tier}

@app.post("/auth/login")
def login(body: LoginRequest):
    user = database.get_user_by_email(body.email, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    return user

# ─────────────────────────────────────────────
#  Health
# ─────────────────────────────────────────────
@app.get("/")
def home():
    return {"message": "Shepherd AI Online", "version": "0.6"}

@app.get("/health")
def health():
    return {"status": "ok"}

# ─────────────────────────────────────────────
#  Scan Route
# ─────────────────────────────────────────────
@app.post("/scan")
@limiter.limit("10/minute")
async def run_scan(
    request: Request,
    body: ScanRequest,
    user: dict = Depends(verify_api_key)
):
    usage = database.check_scan_limit(user["id"], user["tier"])
    if not usage["allowed"]:
        raise HTTPException(status_code=429, detail="Monthly scan limit reached. Upgrade to scan more.")

    try:
        custom_keywords = []
        if user["tier"] == "enterprise":
            ent = database.get_enterprise_settings(user["id"])
            kw_string = ent.get("custom_keywords", "")
            if kw_string:
                custom_keywords = [k.strip() for k in kw_string.split(",") if k.strip()]

        schema = await engine.fetch_openapi_schema(body.target_url)
        if not schema:
            raise HTTPException(status_code=400, detail="Could not fetch OpenAPI schema.")

        unsecured_routes, score = engine.find_unsecured_routes(schema, custom_keywords)
        database.log_scan(user["id"], body.target_url, score)

        # Email alert
        alert_settings = database.get_alert_settings(user["id"])
        if alert_settings and alert_settings["email_alerts"]:
            critical_count = sum(1 for f in unsecured_routes if f.get("is_critical"))
            email_service.send_scan_alert(
                to_email=alert_settings["alert_email"],
                target_url=body.target_url,
                score=score,
                total_unsecured=len(unsecured_routes),
                critical_count=critical_count,
                findings=unsecured_routes,
            )

        # Slack alert
        slack_settings = database.get_slack_settings(user["id"])
        if slack_settings and slack_settings["slack_alerts"] and slack_settings["slack_webhook"]:
            critical_count = sum(1 for f in unsecured_routes if f.get("is_critical"))
            slack_service.send_slack_alert(
                webhook_url=slack_settings["slack_webhook"],
                target_url=body.target_url,
                score=score,
                total_unsecured=len(unsecured_routes),
                critical_count=critical_count,
                findings=unsecured_routes,
            )

        return {
            "target":   body.target_url,
            "score":    round(score, 1),
            "findings": unsecured_routes,
            "usage": {
                "scans_used":  usage["used"] + 1,
                "scans_limit": usage["limit"],
                "tier":        user["tier"]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan Error: {e}")
        raise HTTPException(status_code=500, detail="Internal scan error.")

# ─────────────────────────────────────────────
#  Usage
# ─────────────────────────────────────────────
@app.get("/usage")
def get_usage(user: dict = Depends(verify_api_key)):
    usage = database.check_scan_limit(user["id"], user["tier"])
    return {
        "email":           user["email"],
        "tier":            user["tier"],
        "scans_used":      usage["used"],
        "scans_limit":     usage["limit"],
        "scans_remaining": max(0, usage["limit"] - usage["used"])
    }

# ─────────────────────────────────────────────
#  Email Alerts
# ─────────────────────────────────────────────
@app.post("/alerts/configure")
def configure_alerts(body: AlertSettingsRequest, user: dict = Depends(verify_api_key)):
    if body.email_alerts and user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Email alerts available on Starter and above.")
    database.save_alert_settings(
        user_id=user["id"],
        email_alerts=body.email_alerts,
        alert_email=body.alert_email or user["email"],
    )
    return {"message": "Alert settings saved.", "alert_email": body.alert_email or user["email"]}

@app.post("/alerts/test")
def test_alert(body: TestAlertRequest, user: dict = Depends(verify_api_key)):
    if user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Email alerts available on Starter and above.")
    result = email_service.send_scan_alert(
        to_email=body.alert_email,
        target_url="https://test-api.example.com",
        score=47.5,
        total_unsecured=3,
        critical_count=2,
        findings=[
            {"route": "/patient/records", "method": "GET",  "is_critical": True,  "compliance": ["HIPAA"]},
            {"route": "/billing/payment", "method": "POST", "is_critical": True,  "compliance": ["PCI"]},
            {"route": "/user/profile",    "method": "PUT",  "is_critical": False, "compliance": []},
        ]
    )
    return {"message": "Test alert sent.", "result": result}

@app.get("/alerts/settings")
def get_alert_settings_route(user: dict = Depends(verify_api_key)):
    settings = database.get_alert_settings(user["id"])
    return settings or {"email_alerts": False, "alert_email": user["email"]}

# ─────────────────────────────────────────────
#  Slack Alerts
# ─────────────────────────────────────────────
@app.post("/slack/configure")
def configure_slack(body: SlackSettingsRequest, user: dict = Depends(verify_api_key)):
    if user["tier"] not in {"pro", "enterprise"}:
        raise HTTPException(status_code=403, detail="Slack alerts available on Pro and above.")
    database.save_slack_settings(user["id"], body.webhook_url, body.slack_alerts)
    return {"message": "Slack alerts configured.", "webhook_saved": True}

@app.post("/slack/test")
def test_slack(user: dict = Depends(verify_api_key)):
    if user["tier"] not in {"pro", "enterprise"}:
        raise HTTPException(status_code=403, detail="Slack alerts available on Pro and above.")
    settings = database.get_slack_settings(user["id"])
    if not settings or not settings.get("slack_webhook"):
        raise HTTPException(status_code=400, detail="No Slack webhook configured yet.")
    result = slack_service.send_slack_alert(
        webhook_url=settings["slack_webhook"],
        target_url="https://test-api.example.com",
        score=47.5,
        total_unsecured=3,
        critical_count=2,
        findings=[
            {"route": "/patient/records", "method": "GET",  "is_critical": True, "compliance": ["HIPAA"]},
            {"route": "/billing/payment", "method": "POST", "is_critical": True, "compliance": ["PCI"]},
        ]
    )
    return {"message": "Test Slack alert sent.", "result": result}

@app.get("/slack/settings")
def get_slack_settings_route(user: dict = Depends(verify_api_key)):
    settings = database.get_slack_settings(user["id"])
    return settings or {"slack_alerts": False, "slack_webhook": ""}

# ─────────────────────────────────────────────
#  Enterprise Settings
# ─────────────────────────────────────────────
@app.post("/enterprise/settings")
def save_enterprise(body: EnterpriseSettingsRequest, user: dict = Depends(verify_api_key)):
    if user["tier"] != "enterprise":
        raise HTTPException(status_code=403, detail="Enterprise plan required.")
    database.save_enterprise_settings(
        user_id=user["id"],
        company_name=body.company_name,
        logo_url=body.logo_url,
        custom_keywords=body.custom_keywords,
    )
    return {
        "message":         "Enterprise settings saved.",
        "company_name":    body.company_name,
        "custom_keywords": body.custom_keywords,
    }

@app.get("/enterprise/settings")
def get_enterprise(user: dict = Depends(verify_api_key)):
    if user["tier"] != "enterprise":
        raise HTTPException(status_code=403, detail="Enterprise plan required.")
    return database.get_enterprise_settings(user["id"])

# ─────────────────────────────────────────────
#  PDF Report
# ─────────────────────────────────────────────
@app.post("/report/download")
async def download_report(body: ReportRequest, user: dict = Depends(verify_api_key)):
    if user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Upgrade to Starter to download PDF reports.")
    company_name = body.company_name
    if user["tier"] == "enterprise":
        ent = database.get_enterprise_settings(user["id"])
        company_name = ent.get("company_name", "Shepherd AI")
    try:
        pdf_bytes = pdf_generator.generate_pdf_report(
            target_url=body.target_url,
            score=body.score,
            findings=body.findings,
            user_email=user["email"],
            tier=user["tier"],
            company_name=company_name,
        )
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=shepherd-report.pdf"}
        )
    except Exception as e:
        logger.error(f"PDF Error: {e}")
        raise HTTPException(status_code=500, detail="PDF generation failed.")

# ─────────────────────────────────────────────
#  Audit History
# ─────────────────────────────────────────────
@app.get("/history")
def get_history(user: dict = Depends(verify_api_key)):
    if user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Audit history available on Starter and above.")
    history = database.get_scan_history(user["id"])
    return {"email": user["email"], "tier": user["tier"], "count": len(history), "history": history}

# ─────────────────────────────────────────────
#  DAY 14 — Billing: Paystack
# ─────────────────────────────────────────────
def verify_paystack_webhook(request_data: bytes, signature: str) -> bool:
    """Cryptographically verify the webhook came from Paystack."""
    if not PAYSTACK_SECRET_KEY or "sk_test_your_key" in PAYSTACK_SECRET_KEY:
        logger.warning("⚠️ PAYSTACK_SECRET_KEY not configured.")
        return False
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        request_data,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)

@app.post("/billing/upgrade")
def create_upgrade_link(body: BillingUpgradeRequest, user: dict = Depends(verify_api_key)):
    """Generates a Paystack checkout URL for tier upgrade."""
    if body.new_tier not in {"starter", "pro", "enterprise"}:
        raise HTTPException(status_code=400, detail="Invalid tier.")
    if user["tier"] == body.new_tier:
        raise HTTPException(status_code=400, detail=f"Already on {body.new_tier} plan.")

    amount = TIER_PRICES[body.new_tier]
    payload = {
        "email":        user["email"],
        "amount":       amount,
        "callback_url": "https://api-security-scanner-qksl.onrender.com/scanner/?billing=success",
        "metadata": {
            "user_id":     user["id"],
            "target_tier": body.new_tier
        }
    }
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type":  "application/json"
    }

    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/transaction/initialize",
            json=payload,
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            checkout_url = response.json()["data"]["authorization_url"]
            return {"checkout_url": checkout_url}
        logger.error(f"Paystack error: {response.status_code} {response.text}")
        raise HTTPException(status_code=500, detail="Paystack failed to initialize.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Billing error: {e}")
        raise HTTPException(status_code=500, detail="Billing service unavailable.")

@app.post("/billing/webhook")
async def paystack_webhook(request: Request):
    """Receives Paystack payment confirmation and upgrades user tier."""
    payload_body = await request.body()
    signature    = request.headers.get("x-paystack-signature", "")

    if not verify_paystack_webhook(payload_body, signature):
        logger.warning("❌ Invalid Paystack webhook signature.")
        raise HTTPException(status_code=400, detail="Invalid signature.")

    event_data = json.loads(payload_body)
    event_type = event_data.get("event")

    if event_type == "charge.success":
        data   = event_data.get("data", {})
        status = data.get("status")

        if status == "success":
            metadata  = data.get("metadata", {})
            user_id   = metadata.get("user_id")
            new_tier  = metadata.get("target_tier")
            reference = data.get("reference")

            if user_id and new_tier:
                database.update_user_tier(user_id, new_tier)
                logger.info(f"✅ User {user_id} upgraded to {new_tier}. Ref: {reference}")
                return JSONResponse(content={"message": "OK", "upgraded": True})
            else:
                logger.error(f"❌ Webhook metadata missing. Ref: {reference}")

    return JSONResponse(content={"message": "OK"})