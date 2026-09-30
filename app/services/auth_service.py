import base64
import time
from typing import Tuple
from fastapi import HTTPException, status
from app.core.security import hash_password, verify_password, pqc_core
from app.crypto.pqc_signer import PQCSigner
from app.services.google_sheets_service import (
    GoogleSheetsService,
    GoogleSheetsServiceError,
    UserAlreadyExistsError
)

class AuthService:
    def __init__(self, sheets_service: GoogleSheetsService = None, pqc_signer: PQCSigner = None):
        self.sheets_service = sheets_service or GoogleSheetsService()
        self.pqc_signer = pqc_signer or pqc_core

    async def register_user(self, username: str, password: str) -> Tuple[str, str]:
        """
        Register a new user:
        1. Hashes password using bcrypt.
        2. Exports PQC public key as base64 string.
        3. Saves userId, hashedPassword, and publicKey to Google Sheets via Apps Script.
        4. Generates a signed PQC token.
        
        Returns (access_token, public_key_b64)
        """
        username = username.strip()
        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username and password are required"
            )

        # Check if user already exists
        try:
            if await self.sheets_service.user_exists(username):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"User '{username}' already exists"
                )
        except GoogleSheetsServiceError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(e)
            )

        # Hash password securely (bcrypt)
        hashed_pwd = hash_password(password)

        # Base64 encode the public key for storage
        pub_key_b64 = base64.urlsafe_b64encode(self.pqc_signer.public_key).decode().rstrip("=")

        # Create user record in Google Sheets DB
        try:
            await self.sheets_service.create_user(
                user_id=username,
                hashed_password=hashed_pwd,
                public_key=pub_key_b64
            )
        except UserAlreadyExistsError as err:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(err)
            )
        except GoogleSheetsServiceError as err:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(err)
            )
        except Exception as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(err)
            )

        # Generate signed PQC authentication token
        payload = {
            "sub": username,
            "iss": "pqc-auth-service",
            "exp": int(time.time()) + 3600
        }
        token = self.pqc_signer.create_pqc_token(payload)
        return token, pub_key_b64

    async def authenticate_user(self, username: str, password: str) -> str:
        """
        Authenticate user against Google Sheets database:
        1. Fetches user record from Google Sheets via Apps Script.
        2. Verifies submitted password against stored hashedPassword.
        3. Generates and returns signed PQC token.
        """
        username = username.strip()
        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        try:
            user = await self.sheets_service.get_user(username)
        except GoogleSheetsServiceError as err:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(err)
            )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        # Verify password hash
        if not verify_password(password, user.hashedPassword):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        # Generate signed PQC token
        payload = {
            "sub": username,
            "iss": "pqc-auth-service",
            "exp": int(time.time()) + 3600
        }
        return self.pqc_signer.create_pqc_token(payload)
