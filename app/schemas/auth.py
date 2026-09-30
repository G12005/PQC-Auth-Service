from pydantic import BaseModel, Field
from typing import Optional

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Unique user identifier")
    password: str = Field(..., min_length=4, description="User password")

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Unique user identifier")
    password: str = Field(..., min_length=1, description="User password")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: Optional[str] = None

class UserResponse(BaseModel):
    userId: str
    publicKey: Optional[str] = ""

class MessageResponse(BaseModel):
    success: bool
    message: str