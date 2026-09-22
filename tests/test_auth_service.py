import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException
from app.services.auth_service import AuthService
from app.services.google_sheets_service import GoogleSheetsService
from app.models.user import UserRecord
from app.core.security import hash_password

@pytest.mark.asyncio
async def test_register_user_success():
    mock_sheets = MagicMock(spec=GoogleSheetsService)
    mock_sheets.user_exists = AsyncMock(return_value=False)
    mock_sheets.create_user = AsyncMock(return_value=True)

    service = AuthService(sheets_service=mock_sheets)
    token, pub_key = await service.register_user("testuser", "securepass123")

    assert token is not None
    assert len(token.split(".")) == 3
    assert pub_key != ""
    mock_sheets.user_exists.assert_called_once_with("testuser")
    mock_sheets.create_user.assert_called_once()

@pytest.mark.asyncio
async def test_register_duplicate_user_fails():
    mock_sheets = MagicMock(spec=GoogleSheetsService)
    mock_sheets.user_exists = AsyncMock(return_value=True)

    service = AuthService(sheets_service=mock_sheets)
    with pytest.raises(HTTPException) as exc_info:
        await service.register_user("testuser", "password")

    assert exc_info.value.status_code == 409
    assert "already exists" in exc_info.value.detail

@pytest.mark.asyncio
async def test_authenticate_user_success():
    hashed_pwd = hash_password("mysecretpassword")
    mock_user = UserRecord(
        userId="testuser",
        hashedPassword=hashed_pwd,
        publicKey="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ..."
    )

    mock_sheets = MagicMock(spec=GoogleSheetsService)
    mock_sheets.get_user = AsyncMock(return_value=mock_user)

    service = AuthService(sheets_service=mock_sheets)
    token = await service.authenticate_user("testuser", "mysecretpassword")

    assert token is not None
    assert len(token.split(".")) == 3
    mock_sheets.get_user.assert_called_once_with("testuser")

@pytest.mark.asyncio
async def test_authenticate_user_invalid_password_fails():
    hashed_pwd = hash_password("correctpassword")
    mock_user = UserRecord(
        userId="testuser",
        hashedPassword=hashed_pwd,
        publicKey="key"
    )

    mock_sheets = MagicMock(spec=GoogleSheetsService)
    mock_sheets.get_user = AsyncMock(return_value=mock_user)

    service = AuthService(sheets_service=mock_sheets)
    with pytest.raises(HTTPException) as exc_info:
        await service.authenticate_user("testuser", "wrongpassword")

    assert exc_info.value.status_code == 401
    assert "Invalid username or password" in exc_info.value.detail

@pytest.mark.asyncio
async def test_authenticate_nonexistent_user_fails():
    mock_sheets = MagicMock(spec=GoogleSheetsService)
    mock_sheets.get_user = AsyncMock(return_value=None)

    service = AuthService(sheets_service=mock_sheets)
    with pytest.raises(HTTPException) as exc_info:
        await service.authenticate_user("nonexistent", "password")

    assert exc_info.value.status_code == 401
