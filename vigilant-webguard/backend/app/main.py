from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.scan import router as scan_router
from app.routes.dashboard import router as dashboard_router
from app.routes.pentest import router as pentest_router
from app.routes.live_scan import router as live_scan_router
from app.services.realtime_monitor import realtime_monitor
import asyncio
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

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

@app.on_event("startup")
async def startup_event():
    """Iniciar servicios en el arranque"""
    # Iniciar monitoreo en tiempo real en background
    asyncio.create_task(realtime_monitor.start_monitoring())

@app.get("/")
async def root():
    return {"message": "Vigilant WebGuard API v1.0 - Advanced Security Platform"}
