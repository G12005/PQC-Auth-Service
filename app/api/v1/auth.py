from fastapi import APIRouter, HTTPException, Depends, status
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, MessageResponse
from app.core.security import pqc_core
from app.services.auth_service import AuthService
from app.api.deps import get_auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    req: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Register a new user:
    Stores user record (userId, hashedPassword, publicKey) in Google Sheets via Apps Script.
    Returns a post-quantum signed token.
    """
    token, _ = await auth_service.register_user(req.username, req.password)
    return TokenResponse(access_token=token, user_id=req.username)

@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Authenticate user against stored credentials in Google Sheets via Apps Script.
    Returns a post-quantum signed token.
    """
    token = await auth_service.authenticate_user(credentials.username, credentials.password)
    return TokenResponse(access_token=token, user_id=credentials.username)

@router.post("/verify")
async def verify(token: str):
    """
    Verify post-quantum signed token signature and claims.
    """
    try:
        claims = pqc_core.verify_pqc_token(token, pqc_core.public_key)
        return {"valid": True, "claims": claims}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))