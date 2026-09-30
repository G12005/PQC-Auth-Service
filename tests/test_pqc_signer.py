import pytest
from app.crypto.pqc_signer import PQCSigner

def test_pqc_signer_create_and_verify():
    signer = PQCSigner()
    payload = {"sub": "user_001", "role": "admin"}
    token = signer.create_pqc_token(payload)
    
    assert token is not None
    assert len(token.split(".")) == 3
    
    claims = signer.verify_pqc_token(token, signer.public_key)
    assert claims["sub"] == "user_001"
    assert claims["role"] == "admin"

def test_pqc_signer_tampered_token_fails():
    signer = PQCSigner()
    payload = {"sub": "user_001"}
    token = signer.create_pqc_token(payload)
    
    parts = token.split(".")
    tampered_token = f"{parts[0]}.eyJzdWIiOiJhbHRlcmVkIn0.{parts[2]}"
    
    with pytest.raises(ValueError):
        signer.verify_pqc_token(tampered_token, signer.public_key)
