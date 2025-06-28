from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.scan import router as scan_router
from app.routes.dashboard import router as dashboard_router
from app.routes.pentest import router as pentest_router
from app.routes.live_scan import router as live_scan_router
from app.routes.deep_scan import router as deep_scan_router
from app.routes.clean_scan import router as clean_scan_router
from app.services.realtime_monitor import realtime_monitor
import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv
from loguru import logger

# Cargar variables de entorno
load_dotenv()

# Solo crear directorios necesarios para PDFs sin logging excesivo
try:
    Path("results/reports").mkdir(parents=True, exist_ok=True)
    Path("results/pdf_reports").mkdir(parents=True, exist_ok=True)
except:
    pass

app = FastAPI(
    title="Vigilant WebGuard",
    description="Plataforma avanzada de análisis ofensivo web",
    version="1.0.0"
)

# Middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enrutadores
app.include_router(scan_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api/dashboard")
app.include_router(pentest_router, prefix="/api/pentest")
app.include_router(live_scan_router, prefix="/api/live")
app.include_router(deep_scan_router, prefix="/api/deep-scan")
app.include_router(clean_scan_router, prefix="/api")

@app.on_event("startup")
async def startup_event():
    """Iniciar servicios en el arranque"""
    # Monitor de tiempo real desactivado para evitar alertas falsas
    logger.info("🚀 Vigilant WebGuard iniciado sin monitor de tiempo real")

@app.get("/")
async def root():
    return {"message": "Vigilant WebGuard API v1.0 - Advanced Security Platform"}
