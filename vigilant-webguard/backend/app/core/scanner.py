import uuid
import subprocess
import glob
import os
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from loguru import logger

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def cleanup_old_reports():
    """Elimina reportes antiguos manteniendo solo los últimos 5"""
    try:
        report_files = glob.glob(str(RESULTS_DIR / "scan_*.json"))
        if len(report_files) > 5:
            # Ordenar por fecha de modificación y mantener solo los 5 más recientes
            report_files.sort(key=os.path.getmtime)
            for file_path in report_files[:-5]:
                os.remove(file_path)
                logger.info(f"Eliminado archivo antiguo: {file_path}")
    except Exception as e:
        logger.error(f"Error al limpiar archivos: {e}")

def get_scan_id():
    """Generar ID único para el escaneo"""
    return datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4().hex)[:8]

async def scan_target_async(target_url: str):
    """Escaneo asíncrono usando Wapiti y Nikto"""
    commands = [
        {
            "tool": "wapiti",
            "cmd": [
                "wapiti", "-u", target_url,
                "-f", "json",
                "-o", str(get_output_path("wapiti", str(uuid.uuid4().hex))),
                "--max-depth", "1",
                "--max-files-per-dir", "20",
                "--max-links-per-page", "50",
                "--timeout", "5",
                "--verify-ssl", "0",
                "--max-scan-time", "180",
                "-v", "1"
            ]
        },
        {
            "tool": "nikto",
            "cmd": [
                "nikto", "-h", target_url,
                "-o", str(get_output_path("nikto", str(uuid.uuid4().hex))),
                "-Format", "txt",
                "-Tuning", "1,2,3,4,5",
                "-timeout", "10"
            ]
        }
    ]
    
    # Ejecutar ambos escaneos en paralelo
    results = await asyncio.gather(
        *(run_tool_async(tool_cmd["tool"], tool_cmd["cmd"]) for tool_cmd in commands),
        return_exceptions=True
    )
    
    # compilar resultados
    return {result["tool"]: result for result in results if not isinstance(result, Exception)}

async def run_tool_async(tool: str, cmd: list):
    """Ejecutar herramienta de escaneo de forma asíncrona"""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return {
            "tool": tool,
            "status": "success" if process.returncode == 0 else "error",
            "output_file": None,
            "returncode": process.returncode,
            "stdout": stdout.decode(),
            "stderr": stderr.decode()
        }
    except Exception as e:
        return {"tool": tool, "status": "error", "error": str(e)}
