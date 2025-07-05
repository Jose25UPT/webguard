from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response as FastAPIResponse
from app.routes.scan import router as scan_router
from app.routes.dashboard import router as dashboard_router
from app.routes.pentest import router as pentest_router
from app.routes.live_scan import router as live_scan_router
from app.routes.deep_scan import router as deep_scan_router
from app.routes.clean_scan import router as clean_scan_router
from app.routes.enhanced_security import router as enhanced_security_router
from app.services.realtime_monitor import realtime_monitor
from app.services.metrics_service import metrics_service
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import time
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

# Métricas de Prometheus
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')

# Middleware para métricas
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.time()
    
    response = await call_next(request)
    
    # Registrar métricas
    duration = time.time() - start_time
    endpoint = request.url.path
    method = request.method
    status_code = response.status_code
    
    # Métricas de Prometheus
    REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=str(status_code)).inc()
    REQUEST_DURATION.observe(duration)
    
    # Métricas de InfluxDB
    user_agent = request.headers.get('user-agent', 'unknown')
    metrics_service.write_request_metric(
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        response_time=duration,
        user_agent=user_agent
    )
    
    return response

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
app.include_router(enhanced_security_router, prefix="/api/enhanced")

# Endpoints de métricas
@app.get("/metrics")
async def prometheus_metrics():
    """Endpoint para métricas de Prometheus"""
    return FastAPIResponse(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

@app.get("/api/metrics/real-time")
async def get_real_time_metrics():
    """Obtener métricas en tiempo real"""
    return metrics_service.get_real_time_metrics()

@app.get("/api/metrics/vulnerabilities")
async def get_vulnerability_metrics():
    """Obtener métricas de vulnerabilidades"""
    return metrics_service.get_vulnerability_summary()

@app.get("/api/metrics/scans")
async def get_scan_metrics():
    """Obtener métricas de escaneos"""
    return metrics_service.get_scan_summary()

@app.get("/api/metrics/attacks")
async def get_attack_metrics():
    """Obtener métricas de ataques"""
    return metrics_service.get_attack_summary()

@app.get("/api/metrics/system")
async def get_system_metrics():
    """Obtener métricas del sistema"""
    return metrics_service.get_system_metrics()

@app.on_event("startup")
async def startup_event():
    """Iniciar servicios en el arranque"""
    # Iniciar recolección de métricas en segundo plano
    metrics_service.start_background_metrics_collection()
    logger.info("🚀 Vigilant WebGuard iniciado con métricas en tiempo real")

@app.on_event("shutdown")
async def shutdown_event():
    """Cerrar servicios al apagar"""
    metrics_service.close()
    logger.info("🔴 Vigilant WebGuard apagado")

@app.get("/")
async def root():
    return {"message": "Vigilant WebGuard API v1.0 - Advanced Security Platform"}
