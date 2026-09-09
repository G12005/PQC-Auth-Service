from fastapi import FastAPI
from app.api.v1.auth import router as auth_router
from app.api.v1.jwks import router as jwks_router

app = FastAPI(
    title="Post-Quantum Authentication Service",
    version="1.0.0",
    description="Quantum-safe authentication engine using ML-DSA-65"
)

app.include_router(auth_router)
app.include_router(jwks_router)

@app.get("/")
async def root():
    return {"message": "PQC Authentication Service Running"}