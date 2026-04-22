# main.py

# 1. Standard Library
import io
import logging
from datetime import datetime

# 2. Third-Party Libraries
from datetime import datetime
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# 3. Local/Project Modules
import database
import pdf_generator
from auth import RegisterRequest, LoginRequest

# ─────────────────────────────────────────────
#  Logging Configuration
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ShepherdAI")

# ─────────────────────────────────────────────
#  Safe Engine Import
# ─────────────────────────────────────────────
try:
    import engine
    ENGINE_LOADED = True
except Exception as e:
    logger.error(f"⚠️  CRITICAL: engine.py failed to load: {e}")
    ENGINE_LOADED = False

# ─────────────────────────────────────────────
#  Rate Limiter
# ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ─────────────────────────────────────────────
#  App Init
# ─────────────────────────────────────────────
app = FastAPI(
    title="Shepherd AI - Scanner API",
    description="HIPAA Compliance Scanner for Health Tech APIs",
    version="0.4"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─────────────────────────────────────────────
#  Startup — initialize DB on every launch
# ─────────────────────────────────────────────
@app.on_event("startup")
def on_startup():
    database.init_db()
    logger.info("Database initialized.")

# ─────────────────────────────────────────────
#  CORS
# ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  Models
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str

class ReportRequest(BaseModel):
    target_url: str
    score: float
    findings: list
    company_name: str = "Shepherd AI"

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
        raise HTTPException(status_code=409, detail="Email already registered.")

    return {
        "message": "Account created successfully.",
        "email": body.email,
        "tier": body.tier,
        "api_key": result["api_key"]
    }

@app.post("/auth/login")
def login(body: LoginRequest):
    user = database.get_user_by_email(body.email, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    return {
        "email": user["email"],
        "tier": user["tier"],
        "api_key": user["api_key"]
    }

# ─────────────────────────────────────────────
#  Scan Route
# ─────────────────────────────────────────────
@app.post("/scan")
@limiter.limit("10/minute")
async def run_scan(
    request: Request,
    body: ScanRequest,
    x_api_key: str = Header(...),
):
    if not ENGINE_LOADED:
        raise HTTPException(status_code=503, detail="Scanner engine failed to load.")

    # 1. Validation: Get user and check limits
    user = database.get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key.")

    usage = database.check_scan_limit(user["id"], user["tier"])
    if not usage["allowed"]:
        raise HTTPException(
            status_code=429,
            detail=f"Scan limit reached for {user['tier']} tier."
        )

    # 2. Fetch and Analyze
    try:
        # FIX: You MUST use 'await' here because fetch_openapi_schema is now async
        schema = await engine.fetch_openapi_schema(body.target_url)
        
        if not schema:
            # Using 400 (Bad Request) instead of 422 for reachability issues
            raise HTTPException(status_code=400, detail="Schema empty or unreachable. Check your URL.")
            
        unsecured_routes, score = engine.find_unsecured_routes(schema)
        
    except HTTPException:
        # Re-raise FastAPI exceptions so they aren't caught by the general 'except'
        raise 
    except Exception as e:
        logger.error(f"Analysis failed for {body.target_url}: {e}")
        raise HTTPException(status_code=500, detail="Internal analysis engine error.")

    # 3. Log and Return
    # Improvement: Capture the return of log_scan to get the most accurate 'used' count
    database.log_scan(user["id"], body.target_url, score)
    
    return {
        "target": body.target_url,
        "score": round(score, 1),
        "total_unsecured": len(unsecured_routes),
        "findings": unsecured_routes,
        "usage": {
            "scans_used": usage["used"] + 1,
            "scans_limit": usage["limit"],
            "tier": user["tier"]
        }
    }
# ─────────────────────────────────────────────
#  Usage Route
# ─────────────────────────────────────────────
@app.get("/usage")
def get_usage(x_api_key: str = Header(...)):
    user = database.get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key.")

    usage = database.check_scan_limit(user["id"], user["tier"])
    return {
        "email": user["email"],
        "tier": user["tier"],
        "usage": {
            "scans_used": usage["used"],
            "scans_limit": usage["limit"],
            "scans_remaining": max(0, usage["limit"] - usage["used"])
        }
    }

# ─────────────────────────────────────────────
#  PDF Report Download
# ─────────────────────────────────────────────
@app.post("/report/download")
async def download_report(
    body: ReportRequest,
    x_api_key: str = Header(...),
):
    user = database.get_user_by_api_key(x_api_key)
    if not user or user["tier"] == "free":
        raise HTTPException(status_code=403, detail="Upgrade to Starter to download PDFs.")

    try:
        pdf_bytes = pdf_generator.generate_pdf_report(
            target_url=body.target_url,
            score=body.score,
            findings=body.findings,
            user_email=user["email"],
            tier=user["tier"],
            company_name=body.company_name,
        )
        
        filename = f"shepherd-report-{datetime.now().strftime('%Y%m%d')}.pdf"
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.error(f"PDF Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF.")