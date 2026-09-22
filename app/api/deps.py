from app.services.auth_service import AuthService

def get_auth_service() -> AuthService:
    return AuthService()
