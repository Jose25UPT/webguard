import uuid
import subprocess
import glob
import os
import asyncio
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def cleanup_old_reports():
    """Elimina todos los archivos de reporte existentes para mantener solo el más reciente"""
    try:
        # Buscar todos los archivos JSON de reportes
        report_files = glob.glob(str(RESULTS_DIR / "scan_*.json"))
        for file_path in report_files:
            os.remove(file_path)
            print(f"Eliminado archivo anterior: {file_path}")
    except Exception as e:
        print(f"Error al limpiar archivos anteriores: {e}")

def get_output_path(tool: str, scan_id: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return RESULTS_DIR / f"scan_{tool}_{scan_id}_{timestamp}.json"

def run_tool(tool, cmd, scan_id):
    output_file = get_output_path(tool, scan_id)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {
            "scan_id": scan_id,
            "tool": tool,
            "status": "success" if res.returncode == 0 else "error",
            "output_file": str(output_file),
            "returncode": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr
        }
    except subprocess.TimeoutExpired:
        return {"scan_id": scan_id, "tool": tool, "status": "timeout", "output_file": None}
    except Exception as e:
        return {"scan_id": scan_id, "tool": tool, "status": "exception", "error": str(e)}

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
