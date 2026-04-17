# main.py
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ─────────────────────────────────────────────
#  Safe Engine Import
#  If engine.py has a syntax error, app still
#  loads and uvicorn won't crash on startup
# ─────────────────────────────────────────────
try:
    import engine
    ENGINE_LOADED = True
except Exception as e:
    print(f"⚠️  WARNING: engine.py failed to load: {e}")
    ENGINE_LOADED = False

# ─────────────────────────────────────────────
#  Rate Limiter Setup
# ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ─────────────────────────────────────────────
#  App Init  ← uvicorn looks for this
# ─────────────────────────────────────────────
app = FastAPI(
    title="Shepherd AI - Scanner API",
    description="HIPAA Compliance Scanner for Health Tech APIs",
    version="0.3"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─────────────────────────────────────────────
#  CORS
# ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdashboard.com"],  # Replace with your real dashboard URL
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  Request Body Model
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str

# ─────────────────────────────────────────────
#  Valid API Keys (replace with DB lookup later)
# ─────────────────────────────────────────────
VALID_API_KEYS = {"your-free-key", "your-starter-key", "your-pro-key"}

# ─────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────
@app.get("/")
def home():
    return {
        "message": "Shepherd AI Scanner Engine is Online",
        "version": "0.3",
        "engine_loaded": ENGINE_LOADED  # tells you immediately if engine.py is broken
    }

@app.get("/health")
def health_check():
    """
    Quick endpoint to confirm the app and engine are both alive.
    Hit this first after every restart.
    """
    return {
        "status": "ok" if ENGINE_LOADED else "degraded",
        "engine": "loaded" if ENGINE_LOADED else "FAILED - check engine.py for errors",
    }

@app.post("/scan")
@limiter.limit("10/minute")
async def run_scan(
    request: Request,
    body: ScanRequest,
    x_api_key: str = Header(...),
):
    """
    Receives a target URL, validates the API key,
    runs the compliance brain, and returns the JSON report.
    """

    # 0. Guard — reject immediately if engine didn't load
    if not ENGINE_LOADED:
        raise HTTPException(
            status_code=503,
            detail="Scanner engine failed to load. Check server logs for engine.py errors."
        )

    # 1. Authenticate
    if x_api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")

    # 2. Fetch the OpenAPI schema from the target
    try:
        schema = engine.fetch_openapi_schema(body.target_url)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Engine crashed while fetching schema: {str(e)}"
        )

    if not schema:
        raise HTTPException(
            status_code=400,
            detail="Could not reach the target API or invalid OpenAPI schema."
        )

    # 3. Run the compliance analysis
    try:
        unsecured_routes, score = engine.find_unsecured_routes(schema)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Engine crashed during analysis: {str(e)}"
        )

    # 4. Return the structured report
    return {
        "target": body.target_url,
        "score": round(score, 1),
        "total_unsecured": len(unsecured_routes),
        "findings": unsecured_routes,
        "status": "Success"
    }