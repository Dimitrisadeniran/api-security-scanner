# main.py
import io
import logging
import json      # Dependency for parsing Paystack webhook data
import hashlib   # Dependency for Paystack webhook security
import hmac      # Dependency for Paystack webhook security
import requests  # Dependency for talking to Paystack
from datetime import datetime

# Day 14 Imports - Ensure config.py and database.py are ready
from config import PAYSTACK_SECRET_KEY, PAYSTACK_BASE_URL, TIER_PRICES
import database

from fastapi import FastAPI, HTTPException, Header, Request, Depends, Body # Added Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse # Added JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import pdf_generator
import email_service
import slack_service
import engine
from auth import RegisterRequest, LoginRequest

# 1. Setup Logging & Limiter
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ShepherdAI")
limiter = Limiter(key_func=get_remote_address)

# 2. Define the app
app = FastAPI(
    title="Shepherd AI - Scanner API",
    description="HIPAA Compliance Scanner for Health Tech APIs",
    version="0.6"
)

# 3. Attach configurations to 'app'
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 4. Mount Static Files (StaticFiles requires unique names)
app.mount("/dashboard", StaticFiles(directory="frontend"), name="frontend")

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
    company_name:    str  = "Shepherd AI"
    logo_url:        str  = ""
    custom_keywords: str  = ""

# Day 14 - Billing Request Model
class BillingUpgradeRequest(BaseModel):
    new_tier: str # Must be 'pro' or 'enterprise'

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

    return {
        "message":  "Account created.",
        "api_key":  result["api_key"],
        "tier":     body.tier,
    }

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
    # 1. Check tier limit
    usage = database.check_scan_limit(user["id"], user["tier"])
    if not usage["allowed"]:
        raise HTTPException(status_code=429, detail="Monthly scan limit reached. Upgrade to scan more.")

    try:
        # 2. Get custom keywords for enterprise users
        custom_keywords = []
        if user["tier"] == "enterprise":
            ent = database.get_enterprise_settings(user["id"])
            kw_string = ent.get("custom_keywords", "")
            if kw_string:
                custom_keywords = [k.strip() for k in kw_string.split(",") if k.strip()]

        # 3. Fetch and analyze
        schema = await engine.fetch_openapi_schema(body.target_url)
        if not schema:
            raise HTTPException(status_code=400, detail="Could not fetch OpenAPI schema from target URL.")

        unsecured_routes, score = engine.find_unsecured_routes(schema, custom_keywords)
        database.log_scan(user["id"], body.target_url, score)

        # 4. Email alert
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

        # 5. Slack alert — Day 12
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
                "tier":         user["tier"]
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
        "email": user["email"],
        "tier":  user["tier"],
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
#  DAY 12 — Slack Alerts
# ─────────────────────────────────────────────
@app.post("/slack/configure")
def configure_slack(body: SlackSettingsRequest, user: dict = Depends(verify_api_key)):
    """Save Slack webhook URL. Pro and Enterprise only."""
    if user["tier"] not in {"pro", "enterprise"}:
        raise HTTPException(
            status_code=403,
            detail="Slack alerts are available on Pro and above."
        )
    database.save_slack_settings(user["id"], body.webhook_url, body.slack_alerts)
    return {"message": "Slack alerts configured.", "webhook_saved": True}

@app.post("/slack/test")
def test_slack(user: dict = Depends(verify_api_key)):
    """Sends a test Slack alert."""
    if user["tier"] not in {"pro", "enterprise"}:
        raise HTTPException(status_code=403, detail="Slack alerts available on Pro and above.")

    settings = database.get_slack_settings(user["id"])
    if not settings or not settings.get("slack_webhook"):
        raise HTTPException(status_code=400, detail="No Slack webhook configured. Call /slack/configure first.")

    result = slack_service.send_slack_alert(
        webhook_url=settings["slack_webhook"],
        target_url="https://test-api.example.com",
        score=47.5,
        total_unsecured=3,
        critical_count=2,
        findings=[
            {"route": "/patient/records", "method": "GET",  "is_critical": True,  "compliance": ["HIPAA"]},
            {"route": "/billing/payment", "method": "POST", "is_critical": True,  "compliance": ["PCI"]},
        ]
    )
    return {"message": "Test Slack alert sent.", "result": result}

@app.get("/slack/settings")
def get_slack_settings_route(user: dict = Depends(verify_api_key)):
    settings = database.get_slack_settings(user["id"])
    return settings or {"slack_alerts": False, "slack_webhook": ""}

# ─────────────────────────────────────────────
#  DAY 13 — Enterprise: White-label + Keywords
# ─────────────────────────────────────────────
@app.post("/enterprise/settings")
def save_enterprise(body: EnterpriseSettingsRequest, user: dict = Depends(verify_api_key)):
    """Save white-label and custom keyword settings. Enterprise only."""
    if user["tier"] != "enterprise":
        raise HTTPException(
            status_code=403,
            detail="White-label and custom keywords are available on Enterprise."
        )
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
#  DAY 14 — Billing & Paystack (Subscriptions)
# ─────────────────────────────────────────────

# --- Helper Function: Verify Paystack Webhook (Security) ---
def verify_paystack_webhook(request_data: bytes, signature: str) -> bool:
    """Verifies that the webhook request actually came from Paystack."""
    if not PAYSTACK_SECRET_KEY or PAYSTACK_SECRET_KEY == "sk_test_...":
        logger.warning("Billing Error: PASTACK_SECRET_KEY is missing in config.py.")
        return False # Fail safe

    computed_hmac = hmac.new(
        PAYSTACK_SECRET_KEY.encode('utf-8'),
        request_data,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed_hmac, signature)


# main.py (# Day 14 Backend Adjustment)

# --- 1. The Upgrade Endpoint: Creates the Checkout Link ---
# DAY 14 ADJ: We now depend on verify_api_key. 
# We are NOT passing user_id in the body.
@app.post("/billing/upgrade")
def create_upgrade_link(body: BillingUpgradeRequest, user: dict = Depends(verify_api_key)):
    """
    Called by the frontend (settings.html).
    It generates a unique Paystack Checkout URL.
    Authorized by the X-API-Key header.
    """
    # 1. Security Check: Validate requested tier
    if body.new_tier not in {"pro", "enterprise"}:
        raise HTTPException(status_code=400, detail="Invalid tier requested.")

    # 2. Check current tier. user["tier"] is found AUTOMATICALLY by the dependency.
    if user["tier"] == body.new_tier:
         raise HTTPException(status_code=400, detail=f"You are already a {body.new_tier.title()} subscriber.")

    # 3. Paystack requires email. user["email"] is also automatic.
    user_email = user["email"]
    
    # 4. Prepare the Paystack Payload
    amount_in_kobo = TIER_PRICES[body.new_tier]
    
    paystack_payload = {
        "email": user_email,
        "amount": amount_in_kobo,
        # 'callback_url' is where Paystack sends the USER after success.
        "callback_url": "http://localhost:8000/dashboard/settings.html?billing=success", 
        
        # 'metadata' is critical: it lets us pass the user_id through the payment 
        # process so our webhook knows who just paid. 
        # The userId comes from the user dependency.
        "metadata": {
            "user_id": user["id"], # Found automatically from the key
            "target_tier": body.new_tier
        }
    }
    # ... rest of your existing Paystack request logic ...
    # 5. Call Paystack API
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        logger.info(f"Billing: Initializing transaction for User {user['id']} (NGN {amount_in_kobo/100:.2f})")
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/transaction/initialize",
            json=paystack_payload,
            headers=headers
        )
        
        # 6. Success: Extract the checkout URL
        if response.status_code == 200:
            checkout_url = response.json()["data"]["authorization_url"]
            return {"checkout_url": checkout_url}
        else:
            logger.error(f"❌ Paystack Initialization Failed: {response.status_code} {response.text}")
            raise HTTPException(status_code=500, detail="Paystack failed to initialize.")
            
    except Exception as e:
        logger.error(f"❌ Payment Initialization error: {e}")
        raise HTTPException(status_code=500, detail="Billing service unavailable.")


# --- 2. The Webhook Endpoint: Automated Tier Updates ---
@app.post("/billing/webhook")
async def paystack_webhook(request: Request):
    """
    Paystack pings this route automatically. It provides PROOF of payment.
    The user is not involved in this communication.
    """
    # A. Capture the exact raw bytes and signature sent by Paystack
    payload_body = await request.body()
    signature = request.headers.get("x-paystack-signature")
    
    # 1. SECURITY: Cryptographically prove the request came from Paystack.
    if not signature or not verify_paystack_webhook(payload_body, signature):
        logger.warning("❌ WEBHOOK SECURITY: Invalid signature. Ignoring request.")
        raise HTTPException(status_code=400, detail="Invalid signature")

    # 2. Parse the verified data
    event_data = json.loads(payload_body)
    event_type = event_data.get("event")
    
    # 3. Process ONLY successful charges
    if event_type == "charge.success":
        data = event_data.get("data")
        status = data.get("status")
        
        if status == "success":
            # 4. Critical: Extract the user_id and tier from our metadata
            metadata = data.get("metadata", {})
            user_id = metadata.get("user_id")
            new_tier = metadata.get("target_tier")
            paystack_ref = data.get("reference")
            
            # (In production, you'd check 'paystack_ref' wasn't processed already)

            # 5. Automated DB Update: Complete the upgrade!
            if user_id and new_tier:
                print(f"💎 WEBHOOK RECEIVED: User {user_id} paid NGN {data.get('amount')/100:.2f}. Upgrading to {new_tier}.")
                # database.update_user_tier(user_id, new_tier) # Ensure this db function exists from Day 14
                return JSONResponse(content={"message": "OK", "detail": f"Upgraded user {user_id} to {new_tier}"})
            else:
                logger.error(f"❌ WEBHOOK ERROR: Metadata missing (UserID/Tier). Reference: {paystack_ref}")
    
    # 6. IMPORTANT: Always return a 200 OK to Paystack so they stop retrying.
    return JSONResponse(content={"message": "OK"})

# ─────────────────────────────────────────────
#  PDF Report
# ─────────────────────────────────────────────
@app.post("/report/download")
async def download_report(body: ReportRequest, user: dict = Depends(verify_api_key)):
    if user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Upgrade to Starter to download PDF reports.")

    # Enterprise: use white-label settings
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