# main.py
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import database
from auth import RegisterRequest, LoginRequest

# ─────────────────────────────────────────────
#  Safe Engine Import
# ─────────────────────────────────────────────
try:
    import engine
    ENGINE_LOADED = True
except Exception as e:
    print(f"⚠️  WARNING: engine.py failed to load: {e}")
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

# ─────────────────────────────────────────────
#  Auth Routes
# ─────────────────────────────────────────────
@app.post("/auth/register")
def register(body: RegisterRequest):
    """Creates a new account and returns an API key."""
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
        "api_key": result["api_key"],
        "note": "Save your API key — pass it as x-api-key header on every scan."
    }

@app.post("/auth/login")
def login(body: LoginRequest):
    """Returns the user's API key on valid login."""
    user = database.get_user_by_email(body.email, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    return {
        "message": "Login successful.",
        "email": user["email"],
        "tier": user["tier"],
        "api_key": user["api_key"]
    }

# ─────────────────────────────────────────────
#  Health Routes
# ─────────────────────────────────────────────
@app.get("/")
def home():
    return {
        "message": "Shepherd AI Scanner Engine is Online",
        "version": "0.4",
        "engine_loaded": ENGINE_LOADED
    }

@app.get("/health")
def health_check():
    return {
        "status": "ok" if ENGINE_LOADED else "degraded",
        "engine": "loaded" if ENGINE_LOADED else "FAILED - check engine.py",
    }

# ─────────────────────────────────────────────
#  Scan Route — with real tier enforcement
# ─────────────────────────────────────────────
@app.post("/scan")
@limiter.limit("10/minute")
async def run_scan(
    request: Request,
    body: ScanRequest,
    x_api_key: str = Header(...),
):
    # 0. Engine guard
    if not ENGINE_LOADED:
        raise HTTPException(status_code=503, detail="Scanner engine failed to load.")

    # 1. Validate API key + get user from DB
    user = database.get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")

    # 2. Check scan limit for their tier
    usage = database.check_scan_limit(user["id"], user["tier"])
    if not usage["allowed"]:
        raise HTTPException(
            status_code=429,
            detail=f"Scan limit reached. Your {user['tier']} plan allows {usage['limit']} scan(s)/month. Upgrade to scan more."
        )

    # 3. Fetch schema
    try:
        schema = engine.fetch_openapi_schema(body.target_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Engine crashed fetching schema: {str(e)}")

    if not schema:
        raise HTTPException(status_code=400, detail="Could not reach the target API or invalid OpenAPI schema.")

    # 4. Run analysis
    try:
        unsecured_routes, score = engine.find_unsecured_routes(schema)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Engine crashed during analysis: {str(e)}")

    # 5. Log the scan to DB
    database.log_scan(user["id"], body.target_url, score)

    # 6. Return report
    return {
        "target": body.target_url,
        "score": round(score, 1),
        "total_unsecured": len(unsecured_routes),
        "findings": unsecured_routes,
        "status": "Success",
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
        "scans_used_this_month": usage["used"],
        "scans_limit": usage["limit"],
        "scans_remaining": max(0, usage["limit"] - usage["used"])
    }