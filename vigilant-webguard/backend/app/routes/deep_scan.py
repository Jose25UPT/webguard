"""
Rutas para análisis profundo de seguridad con múltiples herramientas
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import json
from datetime import datetime
from pathlib import Path
from loguru import logger

from app.services.deep_analysis_service import deep_analysis_service
from app.utils.simple_pdf_generator import simple_pdf_generator

router = APIRouter()

# Modelos Pydantic
class ScanRequest(BaseModel):
    target_url: str
    selected_tools: List[str] = ["wapiti3", "nikto", "custom"]
    deep_scan: bool = True

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: int
    current_phase: str
    message: str

# Almacén en memoria para resultados de escaneo (en producción usar Redis o base de datos)
scan_results_store = {}
scan_status_store = {}

@router.post("/start-deep-scan")
async def start_deep_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Iniciar análisis profundo de seguridad con herramientas seleccionadas
    """
    try:
        logger.info(f"Iniciando análisis profundo para: {request.target_url}")
        logger.info(f"Herramientas seleccionadas: {request.selected_tools}")
        
        # Validar URL
        if not request.target_url.startswith(('http://', 'https://')):
            raise HTTPException(status_code=400, detail="URL debe comenzar con http:// o https://")
        
        # Validar herramientas seleccionadas
        valid_tools = ["wapiti3", "nikto", "custom"]
        for tool in request.selected_tools:
            if tool not in valid_tools:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Herramienta inválida: {tool}. Válidas: {valid_tools}"
                )
        
        if not request.selected_tools:
            raise HTTPException(status_code=400, detail="Debe seleccionar al menos una herramienta")
        
        # Iniciar escaneo en background
        background_tasks.add_task(
            run_deep_scan, 
            request.target_url, 
            request.selected_tools
        )
        
        return {
            "message": "Análisis profundo iniciado",
            "target_url": request.target_url,
            "selected_tools": request.selected_tools,
            "status": "iniciado",
            "estimated_time": "15-30 minutos dependiendo de las herramientas seleccionadas"
        }
        
    except Exception as e:
        logger.error(f"Error iniciando análisis profundo: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def run_deep_scan(target_url: str, selected_tools: List[str]):
    """
    Ejecutar análisis profundo en background
    """
    try:
        # Ejecutar análisis profundo
        results = await deep_analysis_service.comprehensive_deep_scan(
            target_url, 
            selected_tools
        )
        
        scan_id = results.get('scan_id')
        
        # Guardar resultados
        scan_results_store[scan_id] = results
        scan_status_store[scan_id] = {
            "status": "completed",
            "progress": 100,
            "current_phase": "completed",
            "message": "Análisis profundo completado exitosamente"
        }
        
        logger.info(f"Análisis profundo completado para {target_url} (ID: {scan_id})")
        
    except Exception as e:
        logger.error(f"Error en análisis profundo: {e}")
        # En caso de error, aún necesitamos un scan_id para el manejo de errores
        error_scan_id = f"error_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_status_store[error_scan_id] = {
            "status": "error",
            "progress": 0,
            "current_phase": "error",
            "message": f"Error en análisis: {str(e)}"
        }

@router.get("/scan-status")
async def get_scan_status():
    """
    Obtener estado de todos los escaneos activos
    """
    try:
        active_scans = []
        
        for scan_id, status in scan_status_store.items():
            scan_info = {
                "scan_id": scan_id,
                **status
            }
            
            # Agregar información adicional si está disponible
            if scan_id in scan_results_store:
                results = scan_results_store[scan_id]
                scan_info.update({
                    "target_url": results.get('target_url', 'N/A'),
                    "selected_tools": results.get('selected_tools', []),
                    "scan_date": results.get('scan_date', 'N/A'),
                    "vulnerabilities_found": results.get('statistics', {}).get('total_vulnerabilities', 0),
                    "critical_issues": results.get('statistics', {}).get('critical_issues', 0)
                })
            
            active_scans.append(scan_info)
        
        return {
            "active_scans": active_scans,
            "total_scans": len(active_scans)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estado de escaneos: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan-results/{scan_id}")
async def get_scan_results(scan_id: str):
    """
    Obtener resultados de un escaneo específico
    """
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        results = scan_results_store[scan_id]
        
        # Preparar respuesta con información resumida
        response = {
            "scan_id": scan_id,
            "target_url": results.get('target_url'),
            "scan_date": results.get('scan_date'),
            "status": results.get('status'),
            "selected_tools": results.get('selected_tools', []),
            "statistics": results.get('statistics', {}),
            "phases": results.get('phases', {}),
            "recommendations": results.get('recommendations', [])[:10],  # Top 10
            "discovered_assets": results.get('discovered_assets', {}),
            "security_findings": results.get('security_findings', {})
        }
        
        # Incluir resumen de vulnerabilidades
        vuln_analysis = results.get('results', {}).get('vulnerability_analysis', {})
        response['vulnerability_summary'] = {
            "critical_vulnerabilities": len(vuln_analysis.get('critical_vulnerabilities', [])),
            "high_vulnerabilities": len(vuln_analysis.get('high_vulnerabilities', [])),
            "medium_vulnerabilities": len(vuln_analysis.get('medium_vulnerabilities', [])),
            "low_vulnerabilities": len(vuln_analysis.get('low_vulnerabilities', []))
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo resultados: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan-details/{scan_id}")
async def get_scan_details(scan_id: str):
    """
    Obtener detalles completos de un escaneo
    """
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        # Retornar resultados completos
        return scan_results_store[scan_id]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo detalles: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/latest-scan")
async def get_latest_scan():
    """
    Obtener el escaneo más reciente
    """
    try:
        if not scan_results_store:
            raise HTTPException(status_code=404, detail="No hay escaneos disponibles")
        
        # Obtener el escaneo más reciente por fecha
        latest_scan_id = max(
            scan_results_store.keys(),
            key=lambda x: scan_results_store[x].get('scan_date', '')
        )
        
        return await get_scan_results(latest_scan_id)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo último escaneo: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/generate-pdf/{scan_id}")
async def generate_pdf_report(scan_id: str):
    """
    Generar reporte PDF de un escaneo
    """
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        scan_data = scan_results_store[scan_id]
        
        # Generar PDF
        pdf_path = simple_pdf_generator.generate_comprehensive_report(scan_data)
        
        # Verificar que se generó correctamente
        if not Path(pdf_path).exists():
            raise HTTPException(status_code=500, detail="Error generando reporte PDF")
        
        return {
            "message": "Reporte PDF generado exitosamente",
            "pdf_path": pdf_path,
            "scan_id": scan_id,
            "download_url": f"/api/deep-scan/download-pdf/{scan_id}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generando PDF: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download-pdf/{scan_id}")
async def download_pdf_report(scan_id: str):
    """
    Descargar reporte PDF
    """
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        scan_data = scan_results_store[scan_id]
        
        # Buscar PDF existente o generar uno nuevo
        pdf_files = list(Path("results/pdf_reports").glob(f"*{scan_id}*.pdf"))
        
        if pdf_files:
            pdf_path = str(pdf_files[0])  # Usar el primero encontrado
        else:
            # Generar nuevo PDF si no existe
            pdf_path = simple_pdf_generator.generate_comprehensive_report(scan_data)
        
        # Verificar que existe
        if not Path(pdf_path).exists():
            raise HTTPException(status_code=404, detail="Archivo PDF no encontrado")
        
        # Generar nombre amigable para descarga
        target_url = scan_data.get('target_url', 'unknown')
        safe_url = target_url.replace('://', '_').replace('/', '_').replace('.', '_')
        scan_date = scan_data.get('scan_date', '').split('T')[0] if 'T' in scan_data.get('scan_date', '') else 'unknown'
        filename = f"security_report_{safe_url}_{scan_date}.pdf"
        
        return FileResponse(
            path=pdf_path,
            filename=filename,
            media_type='application/pdf'
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error descargando PDF: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/available-tools")
async def get_available_tools():
    """
    Obtener lista de herramientas disponibles
    """
    return {
        "tools": [
            {
                "id": "wapiti3",
                "name": "Wapiti3",
                "description": "Escáner de vulnerabilidades web (XSS, SQL Injection, etc.)",
                "type": "vulnerability_scanner",
                "estimated_time": "10-20 minutos"
            },
            {
                "id": "nikto",
                "name": "Nikto",
                "description": "Escáner de configuración de servidores web",
                "type": "configuration_scanner", 
                "estimated_time": "5-15 minutos"
            },
            {
                "id": "custom",
                "name": "Análisis Personalizado",
                "description": "Reconocimiento, búsqueda de credenciales y análisis profundo",
                "type": "comprehensive_analysis",
                "estimated_time": "5-10 minutos"
            }
        ],
        "recommendations": [
            "Para análisis completo, se recomienda seleccionar todas las herramientas",
            "Wapiti3 + Custom proporcionan cobertura de vulnerabilidades web",
            "Nikto + Custom son ideales para análisis de configuración",
            "Solo Custom es más rápido para reconocimiento básico"
        ]
    }

@router.delete("/scan-results/{scan_id}")
async def delete_scan_results(scan_id: str):
    """
    Eliminar resultados de un escaneo
    """
    try:
        if scan_id not in scan_results_store:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        
        # Eliminar de almacenes
        del scan_results_store[scan_id]
        if scan_id in scan_status_store:
            del scan_status_store[scan_id]
        
        # Eliminar archivos PDF asociados
        pdf_files = list(Path("results/pdf_reports").glob(f"*{scan_id}*.pdf"))
        for pdf_file in pdf_files:
            try:
                pdf_file.unlink()
            except Exception as e:
                logger.warning(f"No se pudo eliminar PDF {pdf_file}: {e}")
        
        return {
            "message": "Resultados de escaneo eliminados exitosamente",
            "scan_id": scan_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error eliminando resultados: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/statistics")
async def get_scan_statistics():
    """
    Obtener estadísticas generales de escaneos
    """
    try:
        total_scans = len(scan_results_store)
        completed_scans = len([s for s in scan_results_store.values() if s.get('status') == 'completed'])
        
        # Estadísticas agregadas
        total_vulnerabilities = sum(
            s.get('statistics', {}).get('total_vulnerabilities', 0) 
            for s in scan_results_store.values()
        )
        
        total_critical = sum(
            s.get('statistics', {}).get('critical_issues', 0) 
            for s in scan_results_store.values()
        )
        
        total_credentials = sum(
            s.get('statistics', {}).get('credentials_found', 0) 
            for s in scan_results_store.values()
        )
        
        # Herramientas más usadas
        tool_usage = {}
        for scan in scan_results_store.values():
            for tool in scan.get('selected_tools', []):
                tool_usage[tool] = tool_usage.get(tool, 0) + 1
        
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_vulnerabilities_found": total_vulnerabilities,
            "total_critical_issues": total_critical,
            "total_credentials_found": total_credentials,
            "tool_usage": tool_usage,
            "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {e}")
        raise HTTPException(status_code=500, detail=str(e))
