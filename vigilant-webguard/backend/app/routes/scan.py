from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from fastapi.responses import FileResponse
from app.models.scan import ScanResult
from app.utils.pdf_generator import generate_pdf_from_json
from app.core.real_scanner import scan_target_async, cleanup_old_reports
from fastapi.responses import JSONResponse
import glob
import os
import uuid
import json
from pathlib import Path

router = APIRouter()

async def tu_funcion_de_escaneo(scan_id: str, target: str, tool: str):
    try:
        result = await scan_target_async(target)
        print(f"Escaneo completado para {target} con ID {scan_id}")
        return result
    except Exception as e:
        print(f"Error en escaneo {scan_id}: {e}")
        return None

@router.post("/scan", response_model=ScanResult)
async def start_scan(request: Request, background_tasks: BackgroundTasks):
    data = await request.json()
    target = data.get("target")
    tool = data.get("engine", "wapiti")

    if not target:
        raise HTTPException(status_code=400, detail="Missing target")

    scan_id = str(uuid.uuid4())
    background_tasks.add_task(tu_funcion_de_escaneo, scan_id, target, tool)

    return ScanResult(
        scan_id=scan_id,
        target=target,
        tool=tool,
        status="pending"
    )

@router.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Obtiene el estado de un escaneo específico"""
    try:
        # Buscar archivo de resultado por scan_id
        files = glob.glob(f"results/scan_*{scan_id}*.json")
        if files:
            return {"scan_id": scan_id, "status": "completed", "result_file": files[0]}
        else:
            return {"scan_id": scan_id, "status": "pending"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@router.get("/last-scan-json")
async def get_last_scan_json():
    try:
        files = sorted(glob.glob("results/scan_*.json"), key=os.path.getmtime, reverse=True)
        if not files:
            raise HTTPException(status_code=404, detail="No hay reportes disponibles.")
        
        with open(files[0], "r", encoding="utf-8") as f:
            data = json.load(f)
        
        return JSONResponse(content=data)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@router.post("/scan-to-pdf")
async def generate_pdf_endpoint():

    resultados_dir = Path("results")
    json_files = sorted(resultados_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)

    if not json_files:
        raise HTTPException(status_code=404, detail="No se encontraron archivos JSON en la carpeta resultados.")

    latest_json_path = json_files[0]  # El más reciente
    try:
        with open(latest_json_path, "r", encoding="utf-8") as f:
            json_data = json.load(f)
        pdf_path = generate_pdf_from_json(json_data)
        return FileResponse(pdf_path, media_type="application/pdf", filename="reporte_seguridad.pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
