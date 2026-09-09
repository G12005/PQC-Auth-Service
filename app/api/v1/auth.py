from fastapi import APIRouter, HTTPException, Depends
from app.schemas.auth import LoginRequest, TokenResponse
from app.crypto.pqc_signer import PQCSigner
import time

router = APIRouter(prefix="/auth", tags=["Authentication"])
pqc_core = PQCSigner()

@router.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest):
    if credentials.username != "admin" or credentials.password != "supersecret":
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    payload = {
        "sub": credentials.username,
        "iss": "pqc-auth-service",
        "exp": int(time.time()) + 3600
    }
    
    token = pqc_core.create_pqc_token(payload)
    return TokenResponse(access_token=token)

@router.post("/verify")
async def verify(token: str):
    try:
        claims = pqc_core.verify_pqc_token(token, pqc_core.public_key)
        return {"valid": True, "claims": claims}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))