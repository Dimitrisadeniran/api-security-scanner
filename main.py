# main.py — Shepherd AI v0.7 — with 2FA Support
import io
import json
import hmac
import hashlib
import logging
import requests
import uuid
import qrcode
from base64 import b64encode
from io import BytesIO
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from pathlib import Path

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
    version="0.7"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    database.init_db()
    logger.info("🚀 Shepherd AI ready with 2FA support.")

# ─────────────────────────────────────────────
#  ALL Models — defined together before any route
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

# NEW: 2FA Models
class TwoFactorVerifyRequest(BaseModel):
    otp_code: str

class TwoFactorDisableRequest(BaseModel):
    otp_code: str

class LoginWith2FARequest(BaseModel):
    email: str
    password: str
    otp_code: str | None = None

# ─────────────────────────────────────────────
#  Auth Dependency (API Key)
# ─────────────────────────────────────────────
async def verify_api_key(x_api_key: str = Header(None)):
    print("API KEY RECEIVED:", x_api_key)

    user = database.get_user_by_api_key(x_api_key)

    print("USER FOUND:", user)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key.")

    return user

# ─────────────────────────────────────────────
#  Session Dependency (for Web UI)
# ─────────────────────────────────────────────
async def get_current_user(request: Request):
    """Get current user from session cookie (for web UI)"""
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None
    
    user = database.get_session_user(session_token)
    return user

async def require_current_user(request: Request):
    """Require authenticated user for web UI routes"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

# ─────────────────────────────────────────────
#  Health Routes
# ─────────────────────────────────────────────
@app.get("/")
def home():
    return {"message": "Shepherd AI Online", "version": "0.7", "api_docs": "/docs"}

@app.get("/api/health")
def health():
    return {"status": "ok"}
# ─────────────────────────────────────────────
#  Auth Routes (Updated with 2FA)
# ─────────────────────────────────────────────
@app.post("/api/auth/register")
def register(body: RegisterRequest):
    allowed_tiers = {"free", "starter", "pro", "enterprise"}
    if body.tier not in allowed_tiers:
        raise HTTPException(status_code=400, detail="Invalid tier.")
    result = database.create_user(body.email, body.password, body.tier)
    if not result:
        raise HTTPException(status_code=409, detail="Email already exists.")
    
    try:
        email_service.send_welcome_email(body.email, result["api_key"], body.tier)
    except Exception as e:
        logger.error(f"Welcome email failed: {e}")
    
    return {"message": "Account created.", "api_key": result["api_key"], "tier": body.tier}

@app.post("/api/auth/login")
def login(body: LoginWith2FARequest):
    logger.info(f"LOGIN ATTEMPT: {body.email}")

    try:
        user = database.get_user_by_email(body.email, body.password)

        logger.info(f"USER LOOKUP RESULT: {user}")

        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        # rest of login code...

    except Exception as e:
        logger.exception("LOGIN ERROR")
        raise
    
    # Check if 2FA is enabled
    if user.get("is_2fa_enabled", False):
        if not body.otp_code:
            # Return that 2FA is required but don't authenticate yet
            return {
                "requires_2fa": True,
                "message": "2FA code required",
                "user_id": user["id"]
            }
        
        # Verify OTP code
        user_data = database.get_user_by_id(user["id"])
        if not user_data or not user_data.get("otp_secret"):
            raise HTTPException(status_code=401, detail="2FA not properly configured")
        
        if not database.verify_otp(user_data["otp_secret"], body.otp_code):
            raise HTTPException(status_code=401, detail="Invalid 2FA code")
    
    # Create session for web login
    session_token = str(uuid.uuid4())
    expires_at = (datetime.now() + timedelta(days=7)).isoformat()
    database.create_session(
    user["id"],
    session_token,
    expires_at
    )
    
    return {
        "id": user["id"],
        "email": user["email"],
        "tier": user["tier"],
        "api_key": user["api_key"],
        "is_2fa_enabled": user.get("is_2fa_enabled", False),
        "session_token": session_token
    }

@app.post("/api/auth/logout")
async def logout(request: Request):
    """Logout and clear session"""
    session_token = request.cookies.get("session_token")
    if session_token:
        database.delete_session(session_token)
    return JSONResponse({"message": "Logged out"})

# ─────────────────────────────────────────────
#  NEW: 2FA Routes
# ─────────────────────────────────────────────
@app.post("/api/auth/setup-2fa")
async def setup_2fa(
    user: dict = Depends(verify_api_key)
):
    """Generate 2FA secret and QR code for setup"""
    # Check if 2FA is already enabled
    status = database.get_user_2fa_status(user["id"])

    print("2FA status:", status)

    if status is None:
        raise HTTPException(status_code=500, detail="get_user_2fa_status returned None")

    if status.get("enabled", False):
        raise HTTPException(status_code=400, detail="2FA already enabled")
    
    # Generate new secret
    secret = database.generate_otp_secret()
    uri = database.get_otp_uri(user["email"], secret, issuer="Shepherd AI")
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = b64encode(buffered.getvalue()).decode()
    
    # Store secret temporarily (not enabled yet)
    database.store_otp_secret_temp(user["id"], secret)
    
    return {
        "secret": secret,
        "qr_code": qr_base64,
        "uri": uri
    }

@app.post("/api/auth/verify-2fa")
async def verify_2fa(
    body: TwoFactorVerifyRequest,
    user: dict = Depends(verify_api_key)
):
    """Verify 2FA code and enable 2FA for the user"""
    # Get user's secret
    user_data = database.get_user_by_id(user["id"])
    if not user_data or not user_data.get("otp_secret"):
        raise HTTPException(status_code=400, detail="2FA not set up")
    
    if user_data.get("is_2fa_enabled", False):
        raise HTTPException(status_code=400, detail="2FA already enabled")
    
    # Verify the OTP code
    if not database.verify_otp(user_data["otp_secret"], body.otp_code):
        raise HTTPException(status_code=400, detail="Invalid 2FA code")
    
    # Enable 2FA
    if database.enable_2fa_for_user(user["id"], user_data["otp_secret"]):
        return {"message": "2FA enabled successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to enable 2FA")

@app.post("/api/auth/disable-2fa")
async def disable_2fa(
    body: TwoFactorDisableRequest,
    user: dict = Depends(verify_api_key)
):
    """Disable 2FA for the user (requires OTP verification)"""
    # Get user's secret
    user_data = database.get_user_by_id(user["id"])
    if not user_data or not user_data.get("otp_secret"):
        raise HTTPException(status_code=400, detail="2FA not enabled")
    
    if not user_data.get("is_2fa_enabled", False):
        raise HTTPException(status_code=400, detail="2FA not enabled")
    
    # Verify OTP code before disabling
    if not database.verify_otp(user_data["otp_secret"], body.otp_code):
        raise HTTPException(status_code=400, detail="Invalid 2FA code")
    
    if database.disable_2fa_for_user(user["id"]):
        return {"message": "2FA disabled successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to disable 2FA")

@app.get("/api/auth/me")
async def get_current_user_info(user: dict = Depends(require_current_user)):
    """Get current user info (for web UI)"""
    status = database.get_user_2fa_status(user["id"])
    return {
        "id": user["id"],
        "email": user["email"],
        "tier": user["tier"],
        "is_2fa_enabled": status["enabled"]
    }

@app.get("/api/auth/2fa-status")
@app.get("/api/auth/2fa-status")
async def get_2fa_status(
    user: dict = Depends(verify_api_key)
):
    """Get 2FA status for the current user"""
    return database.get_user_2fa_status(user["id"])

# ─────────────────────────────────────────────
#  Scan Route
# ─────────────────────────────────────────────
@app.post("/api/scan")
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
@app.get("/api/usage")
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
@app.post("/api/alerts/configure")
def configure_alerts(body: AlertSettingsRequest, user: dict = Depends(verify_api_key)):
    if body.email_alerts and user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Email alerts available on Starter and above.")
    database.save_alert_settings(
        user_id=user["id"],
        email_alerts=body.email_alerts,
        alert_email=body.alert_email or user["email"],
    )
    return {"message": "Alert settings saved.", "alert_email": body.alert_email or user["email"]}

@app.post("/api/alerts/test")
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

@app.get("/api/alerts/settings")
def get_alert_settings_route(user: dict = Depends(verify_api_key)):
    settings = database.get_alert_settings(user["id"])
    return settings or {"email_alerts": False, "alert_email": user["email"]}

# ─────────────────────────────────────────────
#  Slack Alerts
# ─────────────────────────────────────────────
@app.post("/api/slack/configure")
def configure_slack(body: SlackSettingsRequest, user: dict = Depends(verify_api_key)):
    if user["tier"] not in {"pro", "enterprise"}:
        raise HTTPException(status_code=403, detail="Slack alerts available on Pro and above.")
    database.save_slack_settings(user["id"], body.webhook_url, body.slack_alerts)
    return {"message": "Slack alerts configured.", "webhook_saved": True}

@app.post("/api/slack/test")
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

@app.get("/api/slack/settings")
def get_slack_settings_route(user: dict = Depends(verify_api_key)):
    settings = database.get_slack_settings(user["id"])
    return settings or {"slack_alerts": False, "slack_webhook": ""}

# ─────────────────────────────────────────────
#  Enterprise Settings
# ─────────────────────────────────────────────
@app.post("/api/enterprise/settings")
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

@app.get("/api/enterprise/settings")
def get_enterprise(user: dict = Depends(verify_api_key)):
    if user["tier"] != "enterprise":
        raise HTTPException(status_code=403, detail="Enterprise plan required.")
    return database.get_enterprise_settings(user["id"])

# ─────────────────────────────────────────────
#  PDF Report
# ─────────────────────────────────────────────
@app.post("/api/report/download")
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
@app.get("/api/history")
def get_history(user: dict = Depends(verify_api_key)):
    if user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Audit history available on Starter and above.")
    history = database.get_scan_history(user["id"])
    return {"email": user["email"], "tier": user["tier"], "count": len(history), "history": history}

# ─────────────────────────────────────────────
#  Billing: Paystack
# ─────────────────────────────────────────────
def verify_paystack_webhook(request_data: bytes, signature: str) -> bool:
    if not PAYSTACK_SECRET_KEY or "sk_test_your_key" in PAYSTACK_SECRET_KEY:
        logger.warning("⚠️ PAYSTACK_SECRET_KEY not configured.")
        return False
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        request_data,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)

@app.post("/api/billing/upgrade")
def create_upgrade_link(body: BillingUpgradeRequest, user: dict = Depends(verify_api_key)):
    if body.new_tier not in {"starter", "pro", "enterprise"}:
        raise HTTPException(status_code=400, detail="Invalid tier.")
    if user["tier"] == body.new_tier:
        raise HTTPException(status_code=400, detail=f"Already on {body.new_tier} plan.")

    amount = TIER_PRICES[body.new_tier]
    payload = {
        "email":        user["email"],
        "amount":       amount,
        "callback_url": "https://api-security-scanner-55gm.onrender.com/scanner/?billing=success",
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

@app.post("/api/billing/webhook")
async def paystack_webhook(request: Request):
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


@app.get("/debug/schema")
def debug_schema():
    import sqlite3

    conn = sqlite3.connect(database.DATABASE_PATH)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()

    cur.execute("PRAGMA table_info(users)")
    users = [dict(row) for row in cur.fetchall()]

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row["name"] for row in cur.fetchall()]

    conn.close()

    return {
        "database": str(database.DATABASE_PATH),
        "tables": tables,
        "users_table": users,
    }
# TEMP DEBUG ROUTE
# ==========================================

@app.get("/debug/user/{email}")
def debug_user(email: str):
    import sqlite3

    conn = sqlite3.connect(database.DATABASE_PATH)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute(
        "SELECT email, password FROM users WHERE email=?",
        (email,)
    )

    row = cur.fetchone()
    conn.close()

    if not row:
        return {"found": False}

    return dict(row)    
# ─────────────────────────────────────────────
#  Web UI Routes (with 2FA)
# ─────────────────────────────────────────────
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page with 2FA support"""
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page with 2FA management"""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    # Get 2FA status
    status = database.get_user_2fa_status(user["id"])
    user["is_2fa_enabled"] = status["enabled"]
    
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "user": user
    })

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Dashboard page"""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user
    })

# ─────────────────────────────────────────────
#  Static Files — MUST be last
# ─────────────────────────────────────────────
app.mount("/scanner", StaticFiles(directory="scanner", html=True), name="scanner")
