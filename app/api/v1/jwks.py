import base64
from fastapi import APIRouter
from app.core.security import pqc_core

router = APIRouter(prefix="/.well-known", tags=["JWKS"])

@router.get("/pqc-jwks.json")
async def get_jwks():
    pub_k_b64 = base64.urlsafe_b64encode(pqc_core.public_key).decode().rstrip("=")
    return {
        "keys": [
            {
                "kty": "PQC",
                "alg": "ML-DSA-65",
                "use": "sig",
                "kid": "pqc-key-v1",
                "pub": pub_k_b64
            }
        ]
    }