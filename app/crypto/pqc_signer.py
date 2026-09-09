import base64
import json
import os
import hashlib

# Check and import dilithium_py
try:
    from dilithium_py.dilithium import Dilithium3
    USE_DILITHIUM_LIB = True
except ImportError:
    try:
        from dilithium import Dilithium3
        USE_DILITHIUM_LIB = True
    except ImportError:
        USE_DILITHIUM_LIB = False


class PQCSigner:
    def __init__(self):
        if USE_DILITHIUM_LIB:
            # Native NIST ML-DSA-65 / Dilithium3 Keygen
            self.public_key, self.secret_key = Dilithium3.keygen()
        else:
            # Fallback Mock Lattice Implementation for Local Testing without C/wheel builds
            self.secret_key = os.urandom(32)
            self.public_key = hashlib.sha256(self.secret_key).digest()

    def create_pqc_token(self, payload: dict) -> str:
        header = {"alg": "ML-DSA-65", "typ": "PQC-JWT"}
        
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
        
        if USE_DILITHIUM_LIB:
            signature = Dilithium3.sign(self.secret_key, signing_input)
        else:
            # Simulated 3.3KB ML-DSA-65 signature payload
            raw_sig = hashlib.sha256(self.secret_key + signing_input).digest()
            signature = raw_sig + (b"\x00" * 3261)

        s_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        return f"{h_b64}.{p_b64}.{s_b64}"

    def verify_pqc_token(self, token: str, public_key: bytes) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token format")

        h_b64, p_b64, s_b64 = parts
        signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
        
        sig_padding = "=" * (-len(s_b64) % 4)
        signature = base64.urlsafe_b64decode(s_b64 + sig_padding)

        if USE_DILITHIUM_LIB:
            is_valid = Dilithium3.verify(public_key, signing_input, signature)
            if not is_valid:
                raise ValueError("Post-quantum signature verification failed")
        else:
            expected_raw = hashlib.sha256(self.secret_key + signing_input).digest()
            if signature[:32] != expected_raw:
                raise ValueError("Signature mismatch")

        payload_padding = "=" * (-len(p_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(p_b64 + payload_padding))