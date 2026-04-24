# main.py

# 1. Standard Library
import io
import logging
from datetime import datetime

# 2. Third-Party Libraries
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# 3. Local/Project Modules
import database
import pdf_generator
import email_service
import engine
from auth import RegisterRequest, LoginRequest

# ─────────────────────────────────────────────
#  Configuration & Logging
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ShepherdAI")

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Shepherd AI - Scanner API",
    description="HIPAA Compliance Scanner for Health Tech APIs",
    version="0.5"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─────────────────────────────────────────────
#  Middleware & Static Files
# ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serves the moved frontend folder at /dashboard
app.mount("/dashboard", StaticFiles(directory="frontend"), name="frontend")

@app.on_event("startup")
def on_startup():
    database.init_db()
    logger.info("🚀 Database & Shepherd AI Engine ready.")

# ─────────────────────────────────────────────
#  Pydantic Models
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str

class ReportRequest(BaseModel):
    target_url: str
    score: float
    findings: list
    company_name: str = "Shepherd AI"

class AlertConfig(BaseModel):
    recipient_email: EmailStr
    frequency: str = "immediate"

class AlertSettingsRequest(BaseModel):
    email_alerts: bool = True
    alert_email:  str  = ""

class TestAlertRequest(BaseModel):
    alert_email: str

# ─────────────────────────────────────────────
#  Dependency: API Key Validation
# ─────────────────────────────────────────────
async def verify_api_key(x_api_key: str = Header(...)):
    user = database.get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return user

# ─────────────────────────────────────────────
#  Routes: Authentication
# ─────────────────────────────────────────────
@app.post("/auth/register")
def register(body: RegisterRequest):
    allowed_tiers = {"free", "starter", "pro", "enterprise"}
    if body.tier not in allowed_tiers:
        raise HTTPException(status_code=400, detail="Invalid tier selection.")

    result = database.create_user(body.email, body.password, body.tier)
    if not result:
        raise HTTPException(status_code=409, detail="Email already exists.")

    # Generate a welcome draft for the dev to send manually
    welcome_draft = email_service.send_welcome_email(body.email, result["api_key"], body.tier)
    

    return {
        "message": "Account created.",
        "api_key": result["api_key"],
        "welcome_draft": welcome_draft 
    }

@app.post("/auth/login")
def login(body: LoginRequest):
    user = database.get_user_by_email(body.email, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    return user

# ─────────────────────────────────────────────
#  Routes: Scanner Logic
# ─────────────────────────────────────────────
@app.post("/scan")
@limiter.limit("10/minute")
async def run_scan(request: Request, body: ScanRequest, user: dict = Depends(verify_api_key)):
    usage = database.check_scan_limit(user["id"], user["tier"])
    if not usage["allowed"]:
        raise HTTPException(status_code=429, detail="Monthly scan limit reached.")

    try:
        schema = await engine.fetch_openapi_schema(body.target_url)
        if not schema:
            raise HTTPException(status_code=400, detail="Target URL returned no valid schema.")
            
        unsecured_routes, score = engine.find_unsecured_routes(schema)
        database.log_scan(user["id"], body.target_url, score)

        # ── AUTO-ALERT LOGIC ──
        # Sends automated alert if user enabled them in settings
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
        
      # Ensure these keys match what database.check_scan_limit returns!
        # If your DB returns 'scans_used', use 'scans_used' below.
        
        return {
            "target": body.target_url,
            "score": round(score, 1),
            "findings": unsecured_routes,
            "usage": {
                "scans_used": usage.get("scans_used", 0) + 1, 
                "scans_limit": usage.get("scans_limit", 0),
                "tier": user["tier"]
            }
        }
    except Exception as e:
        logger.error(f"Scan Error: {e}")
        raise HTTPException(status_code=500, detail="Internal analysis error.")

# ─────────────────────────────────────────────
#  Routes: Alert Management
# ─────────────────────────────────────────────
@app.post("/alerts/configure")
def configure_alerts(body: AlertSettingsRequest, user: dict = Depends(verify_api_key)):
    """Save the user's email alert preferences."""
    if body.email_alerts and user["tier"] == "free":
        raise HTTPException(
            status_code=403,
            detail="Email alerts are available on Starter ($49/mo) and above."
        )

    database.save_alert_settings(
        user_id=user["id"],
        email_alerts=body.email_alerts,
        alert_email=body.alert_email or user["email"],
    )
    return {
        "message": "Alert settings saved.",
        "email_alerts": body.email_alerts,
        "alert_email": body.alert_email or user["email"],
    }

@app.post("/alerts/test")
def test_alert(body: TestAlertRequest, user: dict = Depends(verify_api_key)):
    """Sends a test alert email to confirm setup is working."""
    if user["tier"] == "free":
        raise HTTPException(
            status_code=403,
            detail="Email alerts are available on Starter ($49/mo) and above."
        )

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

    # Note: result["sent"] depends on your email_service implementation
    return {"message": "Test alert generated successfully.", "data": result}

@app.get("/alerts/settings")
def get_alert_settings(user: dict = Depends(verify_api_key)):
    """Returns the user's current alert settings."""
    settings = database.get_alert_settings(user["id"])
    return settings or {
        "email_alerts": False,
        "alert_email":  user["email"],
        "message":      "No alert settings configured yet."
    }

@app.post("/alerts/prepare-manual")
async def prepare_manual_alert(body: ReportRequest, user: dict = Depends(verify_api_key)):
    """Generates the mailto link and text for manual sending."""
    critical_count = sum(1 for f in body.findings if f.get("is_critical"))
    
    draft = email_service.send_scan_alert(
        to_email=user["email"],
        target_url=body.target_url,
        score=body.score,
        total_unsecured=len(body.findings),
        critical_count=critical_count,
        findings=body.findings
    )
    return draft

# ─────────────────────────────────────────────
#  Routes: Reporting
# ─────────────────────────────────────────────
@app.post("/report/download")
async def download_report(body: ReportRequest, user: dict = Depends(verify_api_key)):
    if user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Upgrade to download PDF reports.")

    try:
        pdf_bytes = pdf_generator.generate_pdf_report(
            target_url=body.target_url,
            score=body.score,
            findings=body.findings,
            user_email=user["email"],
            tier=user["tier"],
            company_name=body.company_name
        )
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=shepherd-report.pdf"}
        )
    except Exception as e:
        logger.error(f"PDF Error: {e}")
        raise HTTPException(status_code=500, detail="PDF generation failed.")
    # ─────────────────────────────────────────────
#  DAY 11 — Audit History
# ─────────────────────────────────────────────
@app.get("/history")
def get_history(user: dict = Depends(verify_api_key)):
    """Returns the last 20 scans for this user."""
    if user["tier"] == "free":
        raise HTTPException(
            status_code=403,
            detail="Audit history is available on Starter ($49/mo) and above."
        )
    history = database.get_scan_history(user["id"])
    return {
        "email":   user["email"],
        "tier":    user["tier"],
        "count":   len(history),
        "history": history
    }