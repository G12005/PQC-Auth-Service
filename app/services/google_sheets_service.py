import logging
from typing import Optional
import httpx
from app.core.config import settings
from app.models.user import UserRecord

logger = logging.getLogger(__name__)

class GoogleSheetsServiceError(Exception):
    """Base exception for Google Sheets Service errors."""
    pass

class UserAlreadyExistsError(GoogleSheetsServiceError):
    """Raised when trying to create a user that already exists."""
    pass

class GoogleSheetsService:
    def __init__(self, script_url: Optional[str] = None, api_key: Optional[str] = None):
        self.script_url = script_url or settings.GOOGLE_APPS_SCRIPT_URL
        self.api_key = api_key or settings.GOOGLE_APPS_SCRIPT_API_KEY

    def _ensure_configured(self):
        if not self.script_url or "YOUR_SCRIPT_ID_HERE" in self.script_url:
            raise GoogleSheetsServiceError(
                "Google Apps Script Web App URL is not configured. "
                "Please set GOOGLE_APPS_SCRIPT_URL in your .env file."
            )

    async def create_user(self, user_id: str, hashed_password: str, public_key: str = "") -> bool:
        """
        Create a new user entry in Google Sheets via Apps Script Web App.
        """
        self._ensure_configured()
        
        payload = {
            "action": "createUser",
            "userId": user_id,
            "hashedPassword": hashed_password,
            "publicKey": public_key,
            "apiKey": self.api_key
        }

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                response = await client.post(self.script_url, json=payload)
                
                try:
                    data = response.json()
                except Exception:
                    data = {}

                if response.status_code == 409 or data.get("message") == "User already exists":
                    raise UserAlreadyExistsError(f"User '{user_id}' already exists")

                if response.status_code not in (200, 201):
                    msg = data.get("message") or f"Apps Script returned status {response.status_code}"
                    logger.error(f"Apps Script error ({response.status_code}): {msg}")
                    raise GoogleSheetsServiceError(msg)

                if not data.get("success"):
                    msg = data.get("message", "Failed to create user")
                    if msg == "User already exists":
                        raise UserAlreadyExistsError(f"User '{user_id}' already exists")
                    raise GoogleSheetsServiceError(msg)

                return True

            except httpx.HTTPError as err:
                logger.error(f"HTTP connection error to Apps Script: {err}")
                raise GoogleSheetsServiceError("Service unavailable: Could not communicate with Google Sheets database")

    async def get_user(self, user_id: str) -> Optional[UserRecord]:
        """
        Retrieve user record by userId from Google Sheets via Apps Script Web App.
        """
        self._ensure_configured()

        payload = {
            "action": "getUser",
            "userId": user_id,
            "apiKey": self.api_key
        }

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                response = await client.post(self.script_url, json=payload)
                if response.status_code == 404:
                    return None
                
                try:
                    data = response.json()
                except Exception:
                    data = {}

                if not data.get("success") or "user" not in data:
                    if data.get("message") == "User not found":
                        return None
                    return None

                user_data = data["user"]
                return UserRecord(
                    userId=user_data["userId"],
                    hashedPassword=user_data["hashedPassword"],
                    publicKey=user_data.get("publicKey", "")
                )
            except httpx.HTTPError as err:
                logger.error(f"HTTP error fetching user: {err}")
                raise GoogleSheetsServiceError("Service unavailable: Could not communicate with Google Sheets database")

    async def user_exists(self, user_id: str) -> bool:
        """
        Check if user exists in Google Sheets via Apps Script Web App.
        """
        self._ensure_configured()
        
        payload = {
            "action": "userExists",
            "userId": user_id,
            "apiKey": self.api_key
        }

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                response = await client.post(self.script_url, json=payload)
                if response.status_code != 200:
                    return False
                data = response.json()
                return bool(data.get("exists", False))
            except Exception:
                return False
