# auth.py
from pydantic import BaseModel
from typing import Optional

class RegisterRequest(BaseModel):
    email: str
    password: str
    tier: str = "free"
    security_pin: Optional[str] = "1234"

class LoginRequest(BaseModel):
    email: str
    password: str

class RevealKeyPayload(BaseModel):
    pin: str
