from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from app.api.v1.auth import router as auth_router
from app.api.v1.jwks import router as jwks_router

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="Post-Quantum Authentication Service",
    version="1.0.0",
    description="Quantum-safe authentication engine using ML-DSA-65"
)

app.include_router(auth_router)
app.include_router(jwks_router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def root():
    return FileResponse(STATIC_DIR / "index.html")