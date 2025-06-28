from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from app.services.clean_scanner_service import clean_scanner
from app.utils.simple_pdf_generator import simple_pdf_generator
import json
import os
import tempfile
from pathlib import Path
from loguru import logger

router = APIRouter()

# Variable global para almacenar el último resultado
last_scan_result = None

@router.post("/clean-scan")
async def clean_scan_endpoint(request_data: dict):
    """Endpoint de escaneo limpio que funciona correctamente"""
    global last_scan_result
    
    try:
        target_url = request_data.get('url')
        if not target_url:
            raise HTTPException(status_code=400, detail="URL requerida")
        
        logger.info(f"🚀 Iniciando escaneo limpio para: {target_url}")
        
        # Ejecutar escaneo
        result = await clean_scanner.scan_url(target_url)
        
        # Guardar resultado en memoria temporal
        last_scan_result = result
        
        logger.info(f"✅ Escaneo completado para: {target_url}")
        
        return JSONResponse(content={
            "scan_id": result['scan_id'],
            "target_url": result['target_url'],
            "status": result['status'],
            "duration": result.get('duration', 0),
            "total_vulnerabilities": result['scan_metadata']['total_vulnerabilities'],
            "critical_vulnerabilities": result['scan_metadata']['critical_vulnerabilities'],
            "message": "Escaneo completado exitosamente"
        })
        
    except Exception as e:
        logger.error(f"❌ Error en escaneo limpio: {e}")
        raise HTTPException(status_code=500, detail=f"Error en escaneo: {str(e)}")

@router.get("/clean-scan/last-result")
async def get_last_scan_result():
    """Obtener el último resultado de escaneo"""
    global last_scan_result
    
    if not last_scan_result:
        raise HTTPException(status_code=404, detail="No hay resultados de escaneo disponibles")
    
    return JSONResponse(content=last_scan_result)

@router.get("/clean-scan/download-pdf")
async def download_clean_pdf():
    """Descargar PDF del último escaneo y limpiar todo"""
    global last_scan_result
    
    try:
        if not last_scan_result:
            raise HTTPException(status_code=404, detail="No hay resultados para generar PDF")
        
        logger.info("📄 Generando PDF temporal...")
        
        # Crear archivo temporal para el PDF
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_json:
            json.dump(last_scan_result, temp_json, indent=2, ensure_ascii=False)
            temp_json_path = temp_json.name
        
        try:
            # Generar PDF usando el generador simple que funciona
            pdf_path = simple_pdf_generator.generate_comprehensive_report(last_scan_result)
            
            if not os.path.exists(pdf_path):
                raise HTTPException(status_code=500, detail="No se pudo generar el PDF")
            
            # Preparar respuesta
            response = FileResponse(
                pdf_path,
                media_type="application/pdf",
                filename=f"security_report_{last_scan_result.get('scan_id', 'unknown')}.pdf",
                headers={"Content-Disposition": f"attachment; filename=security_report_{last_scan_result.get('scan_id', 'unknown')}.pdf"}
            )
            
            # Programar limpieza después de la descarga
            import asyncio
            asyncio.create_task(cleanup_after_download(pdf_path, temp_json_path))
            
            logger.info("✅ PDF generado y enviado para descarga")
            return response
            
        except Exception as e:
            # Limpiar archivo temporal en caso de error
            if os.path.exists(temp_json_path):
                os.unlink(temp_json_path)
            raise e
            
    except Exception as e:
        logger.error(f"❌ Error generando PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error generando PDF: {str(e)}")

async def cleanup_after_download(pdf_path: str, temp_json_path: str):
    """Limpiar archivos y datos después de la descarga"""
    global last_scan_result
    
    try:
        # Esperar un poco para que termine la descarga
        await asyncio.sleep(5)
        
        # Limpiar archivos
        if os.path.exists(pdf_path):
            os.unlink(pdf_path)
            logger.info(f"🧹 PDF eliminado: {pdf_path}")
        
        if os.path.exists(temp_json_path):
            os.unlink(temp_json_path)
            logger.info(f"🧹 JSON temporal eliminado: {temp_json_path}")
        
        # Limpiar datos en memoria
        last_scan_result = None
        
        # Limpiar todos los archivos temporales del scanner
        clean_scanner.cleanup_all_temp()
        
        # Limpiar directorio de reportes
        reports_dir = Path("results/reports")
        if reports_dir.exists():
            for file in reports_dir.glob("*.pdf"):
                try:
                    file.unlink()
                except:
                    pass
        
        logger.info("🧹 Limpieza completa realizada")
        
    except Exception as e:
        logger.error(f"Error en limpieza: {e}")

@router.post("/clean-scan/reset")
async def reset_scanner():
    """Resetear completamente el scanner"""
    global last_scan_result
    
    try:
        # Limpiar datos en memoria
        last_scan_result = None
        
        # Limpiar archivos temporales
        clean_scanner.cleanup_all_temp()
        
        # Limpiar directorios de resultados
        directories_to_clean = [
            "results",
            "results/reports", 
            "results/real_scans",
            "results/opensource_tools",
            "results/live_analysis",
            "temp_scans"
        ]
        
        for dir_path in directories_to_clean:
            dir_obj = Path(dir_path)
            if dir_obj.exists():
                import shutil
                try:
                    shutil.rmtree(dir_obj)
                    dir_obj.mkdir(parents=True, exist_ok=True)
                except:
                    pass
        
        logger.info("🧹 Scanner completamente reseteado")
        
        return JSONResponse(content={
            "status": "success",
            "message": "Scanner reseteado correctamente"
        })
        
    except Exception as e:
        logger.error(f"Error reseteando scanner: {e}")
        raise HTTPException(status_code=500, detail=f"Error reseteando: {str(e)}")

import asyncio
