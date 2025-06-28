# report.py
# app/routes/report.py
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import json

router = APIRouter()

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"

@router.get("/api/last-scan-json")
async def get_last_scan_json():
    try:
        files = list(RESULTS_DIR.glob("*.json"))
        if not files:
            raise FileNotFoundError("No se encontraron archivos JSON en /results")

        latest_file = max(files, key=lambda f: f.stat().st_mtime)
        with open(latest_file, "r") as f:
            data = json.load(f)

        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
