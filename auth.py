from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
# Import your existing authentication helpers & Supabase client
# e.g., from database import supabase; from auth_helpers import get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

class RegisterRequest(BaseModel):
    email: str
    password: str
    security_pin: str  # Add PIN requirement for user registration
    tier: str = "free"

class LoginRequest(BaseModel):
    email: str
    password: str

class RevealKeyRequest(BaseModel):
    pin: str


@router.post("/reveal-key")
async def reveal_key(data: RevealKeyRequest, current_user = Depends(get_current_user)):
    input_pin = str(data.pin).strip()
    
    # Fetch stored PIN and API key for the authenticated user from Supabase
    response = supabase.table("users").select("security_pin, api_key").eq("id", current_user["id"]).single().execute()
    user_data = response.data

    if not user_data or not user_data.get("security_pin"):
        raise HTTPException(status_code=400, detail="No Security PIN set for this account.")

    if str(user_data.get("security_pin")) == input_pin:
        return {"api_key": user_data.get("api_key")}
    
    raise HTTPException(status_code=401, detail="Incorrect Security PIN.")
