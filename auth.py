# auth.py
from pydantic import BaseModel

class RegisterRequest(BaseModel):
    email: str
    password: str
    tier: str = "free"   # default to free

class LoginRequest(BaseModel):
    email: str
    password: str