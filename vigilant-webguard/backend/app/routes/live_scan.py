from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from typing import Dict, List
import json
import asyncio
from loguru import logger

from app.services.live_analysis_service import live_analysis_service
from app.services.enhanced_security_service import enhanced_security_service

router = APIRouter()

# Almacenar conexiones WebSocket activas
active_connections: Dict[str, WebSocket] = {}


@router.post("/start-live-scan")
async def start_live_scan(request_data: dict):
    """Iniciar análisis progresivo en tiempo real"""
    try:
        url = request_data.get('url')
        if not url:
            raise HTTPException(status_code=400, detail="URL requerida")
        
        # Iniciar análisis progresivo
        scan_id = await live_analysis_service.start_progressive_scan(url)
        
        return JSONResponse(content={
            "scan_id": scan_id,
            "target_url": url,
            "status": "iniciado",
            "message": "Análisis progresivo iniciado correctamente"
        })
        
    except Exception as e:
        logger.error(f"Error iniciando análisis live: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/live-scan-progress/{scan_id}")
async def get_live_scan_progress(scan_id: str):
    """Obtener progreso actual del análisis"""
    try:
        progress = live_analysis_service.get_scan_progress(scan_id)
        
        if not progress:
            raise HTTPException(status_code=404, detail="Análisis no encontrado")
        
        return JSONResponse(content={
            "scan_id": progress.scan_id,
            "target_url": progress.target_url,
            "status": progress.status,
            "progress": progress.progress,
            "current_step": progress.current_step,
            "vulnerabilities_found": progress.vulnerabilities_found,
            "critical_issues": progress.critical_issues,
            "recommendations": progress.recommendations,
            "started_at": progress.started_at,
            "updated_at": progress.updated_at
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo progreso: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/live-scan-results/{scan_id}")
async def get_live_scan_results(scan_id: str):
    """Obtener resultados completos del análisis"""
    try:
        progress = live_analysis_service.get_scan_progress(scan_id)
        
        if not progress:
            raise HTTPException(status_code=404, detail="Análisis no encontrado")
        
        return JSONResponse(content={
            "scan_id": progress.scan_id,
            "target_url": progress.target_url,
            "status": progress.status,
            "progress": progress.progress,
            "results": progress.results,
            "vulnerabilities_found": progress.vulnerabilities_found,
            "critical_issues": progress.critical_issues,
            "recommendations": progress.recommendations,
            "started_at": progress.started_at,
            "updated_at": progress.updated_at
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo resultados: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/live-scan-websocket/{scan_id}")
async def websocket_live_scan(websocket: WebSocket, scan_id: str):
    """WebSocket para actualizaciones en tiempo real del análisis"""
    await websocket.accept()
    active_connections[scan_id] = websocket
    
    try:
        # Callback para notificar actualizaciones
        async def progress_callback(progress):
            try:
                await websocket.send_text(json.dumps({
                    "type": "progress_update",
                    "scan_id": progress.scan_id,
                    "status": progress.status,
                    "progress": progress.progress,
                    "current_step": progress.current_step,
                    "vulnerabilities_found": progress.vulnerabilities_found,
                    "critical_issues": progress.critical_issues,
                    "recommendations": progress.recommendations[-3:],  # Últimas 3
                    "updated_at": progress.updated_at
                }))
            except Exception as e:
                logger.error(f"Error enviando update por WebSocket: {e}")
        
        # Registrar callback
        if scan_id in live_analysis_service.callbacks:
            live_analysis_service.callbacks[scan_id].append(progress_callback)
        else:
            live_analysis_service.callbacks[scan_id] = [progress_callback]
        
        # Mantener conexión activa
        while True:
            try:
                # Recibir mensajes del cliente (ping/pong)
                message = await websocket.receive_text()
                if message == "ping":
                    await websocket.send_text("pong")
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error en WebSocket: {e}")
                break
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket desconectado para scan {scan_id}")
    finally:
        # Limpiar conexión
        if scan_id in active_connections:
            del active_connections[scan_id]


@router.get("/active-scans")
async def get_active_scans():
    """Obtener todos los análisis activos"""
    try:
        active_scans = live_analysis_service.get_active_scans()
        
        return JSONResponse(content={
            "active_scans": [
                {
                    "scan_id": scan.scan_id,
                    "target_url": scan.target_url,
                    "status": scan.status,
                    "progress": scan.progress,
                    "current_step": scan.current_step,
                    "vulnerabilities_found": scan.vulnerabilities_found,
                    "critical_issues": scan.critical_issues,
                    "started_at": scan.started_at
                }
                for scan in active_scans
            ],
            "total_active": len(active_scans)
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo análisis activos: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enhanced-analysis")
async def start_enhanced_analysis(request_data: dict):
    """Iniciar análisis completo con todas las herramientas mejoradas"""
    try:
        url = request_data.get('url')
        if not url:
            raise HTTPException(status_code=400, detail="URL requerida")
        
        # Usar el servicio mejorado de seguridad
        analysis_result = await enhanced_security_service.complete_security_analysis(url)
        
        return JSONResponse(content=analysis_result)
        
    except Exception as e:
        logger.error(f"Error en análisis mejorado: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/remove-scan/{scan_id}")
async def remove_completed_scan(scan_id: str):
    """Remover análisis completado del cache"""
    try:
        live_analysis_service.remove_completed_scan(scan_id)
        
        return JSONResponse(content={
            "message": f"Análisis {scan_id} removido correctamente"
        })
        
    except Exception as e:
        logger.error(f"Error removiendo análisis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan-statistics")
async def get_scan_statistics():
    """Obtener estadísticas generales de análisis"""
    try:
        active_scans = live_analysis_service.get_active_scans()
        
        total_vulns = sum(scan.vulnerabilities_found for scan in active_scans)
        total_critical = sum(scan.critical_issues for scan in active_scans)
        
        status_counts = {}
        for scan in active_scans:
            status = scan.status
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return JSONResponse(content={
            "total_active_scans": len(active_scans),
            "total_vulnerabilities_found": total_vulns,
            "total_critical_issues": total_critical,
            "status_breakdown": status_counts,
            "scans_by_status": {
                "iniciando": len([s for s in active_scans if s.status == "iniciando"]),
                "ejecutando": len([s for s in active_scans if s.status == "ejecutando"]),
                "completado": len([s for s in active_scans if s.status == "completado"]),
                "error": len([s for s in active_scans if s.status == "error"])
            }
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {e}")
        raise HTTPException(status_code=500, detail=str(e))
