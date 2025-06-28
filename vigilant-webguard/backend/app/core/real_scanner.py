import asyncio
import subprocess
import json
import os
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
from loguru import logger
import time

class RealWebScanner:
    """Scanner web real que funciona correctamente con Wapiti y genera reportes auténticos"""
    
    def __init__(self):
        self.results_dir = Path("results/real_scans")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.max_scan_time = 300  # 5 minutos máximo
        
    async def scan_url(self, target_url: str) -> Dict:
        """Escanear URL con tiempo límite de 5 minutos"""
        start_time = time.time()
        scan_id = self._generate_scan_id()
        
        logger.info(f"🚀 Iniciando escaneo real de {target_url} (ID: {scan_id})")
        
        # Crear directorio específico para este escaneo
        scan_dir = self.results_dir / f"scan_{scan_id}"
        scan_dir.mkdir(exist_ok=True)
        
        try:
            # Ejecutar Wapiti con configuración optimizada para 5 minutos
            wapiti_result = await self._run_wapiti_real(target_url, scan_dir)
            
            # Solo si hay tiempo restante, ejecutar Nikto
            elapsed_time = time.time() - start_time
            nikto_result = None
            
            if elapsed_time < self.max_scan_time - 60:  # Si quedan al menos 60 segundos
                nikto_result = await self._run_nikto_real(target_url, scan_dir)
            
            # Compilar resultados finales
            final_results = {
                'scan_id': scan_id,
                'target_url': target_url,
                'start_time': datetime.fromtimestamp(start_time).isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_duration': time.time() - start_time,
                'wapiti_results': wapiti_result,
                'nikto_results': nikto_result,
                'scan_directory': str(scan_dir)
            }
            
            # Guardar resumen del escaneo
            summary_file = scan_dir / "scan_summary.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(final_results, f, indent=2, ensure_ascii=False)
            
            # Guardar en formato legacy para compatibilidad
            legacy_file = self.results_dir.parent / f"scan_{scan_id}.json"
            self._create_legacy_format(final_results, legacy_file)
            
            logger.info(f"✅ Escaneo completado en {final_results['total_duration']:.2f} segundos")
            return final_results
            
        except Exception as e:
            logger.error(f"❌ Error en escaneo: {e}")
            return {
                'scan_id': scan_id,
                'target_url': target_url,
                'error': str(e),
                'status': 'failed'
            }
    
    async def _run_wapiti_real(self, target_url: str, output_dir: Path) -> Dict:
        """Ejecutar Wapiti con configuración real y optimizada"""
        try:
            json_output = output_dir / "wapiti_report.json"
            html_output = output_dir / "wapiti_report.html"
            
            # Comando Wapiti optimizado para 4 minutos máximo
            cmd = [
                'wapiti',
                '-u', target_url,
                '--scope', 'url',  # Solo la URL específica para ser más rápido
                '--max-depth', '2',  # Profundidad limitada
                '--max-links-per-page', '30',  # Menos enlaces por página
                '--max-files-per-dir', '30',  # Menos archivos por directorio
                '--timeout', '10',  # Timeout por request
                '--max-scan-time', '240',  # 4 minutos máximo para Wapiti
                '--verify-ssl', '0',  # No verificar SSL para ir más rápido
                '--level', '1',  # Nivel básico pero completo
                '--flush-session',  # Limpiar sesión anterior
                '--modules', 'backup,cookieflags,csrf,exec,file,htaccess,lfi,redirect,sql,xss',  # Módulos principales
                '-f', 'json',
                '-o', str(json_output)
            ]
            
            logger.info(f"🔍 Ejecutando Wapiti: {' '.join(cmd)}")
            
            # Ejecutar con timeout estricto
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(output_dir)
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=250  # 4 minutos + 10 segundos de margen
                )
                
                logger.info(f"Wapiti terminó con código: {process.returncode}")
                
                # Verificar si se generó el archivo JSON
                if json_output.exists() and json_output.stat().st_size > 10:
                    logger.info(f"✅ Archivo JSON de Wapiti generado: {json_output}")
                    
                    # Leer y procesar resultados
                    with open(json_output, 'r', encoding='utf-8') as f:
                        wapiti_data = json.load(f)
                    
                    processed_results = self._process_wapiti_results(wapiti_data)
                    processed_results['json_file'] = str(json_output)
                    processed_results['raw_stdout'] = stdout.decode() if stdout else ""
                    processed_results['raw_stderr'] = stderr.decode() if stderr else ""
                    
                    return processed_results
                    
                else:
                    logger.warning(f"⚠️ No se generó archivo JSON válido de Wapiti")
                    return {
                        'status': 'no_output',
                        'error': 'No se generó archivo JSON',
                        'stdout': stdout.decode() if stdout else "",
                        'stderr': stderr.decode() if stderr else ""
                    }
                    
            except asyncio.TimeoutError:
                logger.warning("⏰ Wapiti timeout - terminando proceso")
                process.kill()
                return {
                    'status': 'timeout',
                    'error': 'Timeout después de 4 minutos',
                    'partial_results': self._check_partial_results(json_output)
                }
                
        except Exception as e:
            logger.error(f"❌ Error ejecutando Wapiti: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def _run_nikto_real(self, target_url: str, output_dir: Path) -> Dict:
        """Ejecutar Nikto con configuración real"""
        try:
            txt_output = output_dir / "nikto_report.txt"
            
            cmd = [
                'nikto',
                '-h', target_url,
                '-timeout', '10',
                '-maxtime', '60',  # Máximo 1 minuto para Nikto
                '-Tuning', '123',  # Solo categorías básicas para ir más rápido
                '-output', str(txt_output),
                '-Format', 'txt'
            ]
            
            logger.info(f"🔧 Ejecutando Nikto: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=70  # 1 minuto + 10 segundos
                )
                
                # Nikto puede retornar códigos diferentes
                if txt_output.exists():
                    with open(txt_output, 'r', encoding='utf-8') as f:
                        nikto_output = f.read()
                    
                    processed_results = self._process_nikto_results(nikto_output)
                    processed_results['output_file'] = str(txt_output)
                    
                    return processed_results
                else:
                    return {
                        'status': 'no_output',
                        'stdout': stdout.decode() if stdout else "",
                        'stderr': stderr.decode() if stderr else ""
                    }
                    
            except asyncio.TimeoutError:
                logger.warning("⏰ Nikto timeout")
                process.kill()
                return {'status': 'timeout', 'error': 'Timeout en Nikto'}
                
        except Exception as e:
            logger.error(f"❌ Error ejecutando Nikto: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _process_wapiti_results(self, wapiti_data: Dict) -> Dict:
        """Procesar resultados reales de Wapiti"""
        try:
            vulnerabilities = wapiti_data.get('vulnerabilities', {})
            
            total_vulns = 0
            by_severity = {'High': 0, 'Medium': 0, 'Low': 0}
            by_category = {}
            
            processed_vulns = []
            
            for category, vulns in vulnerabilities.items():
                if isinstance(vulns, list) and vulns:
                    by_category[category] = len(vulns)
                    total_vulns += len(vulns)
                    
                    for vuln in vulns:
                        level = vuln.get('level', 1)
                        severity = 'High' if level >= 3 else 'Medium' if level == 2 else 'Low'
                        by_severity[severity] += 1
                        
                        processed_vulns.append({
                            'category': category,
                            'info': vuln.get('info', ''),
                            'level': level,
                            'severity': severity,
                            'method': vuln.get('method', 'GET'),
                            'path': vuln.get('path', '/'),
                            'parameter': vuln.get('parameter', ''),
                            'wstg': vuln.get('wstg', []),
                            'references': vuln.get('references', [])
                        })
            
            return {
                'status': 'completed',
                'tool': 'Wapiti3',
                'total_vulnerabilities': total_vulns,
                'vulnerabilities_by_severity': by_severity,
                'vulnerabilities_by_category': by_category,
                'detailed_vulnerabilities': processed_vulns,
                'target_info': wapiti_data.get('infos', {}),
                'classifications': wapiti_data.get('classifications', {})
            }
            
        except Exception as e:
            logger.error(f"Error procesando resultados Wapiti: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _process_nikto_results(self, nikto_output: str) -> Dict:
        """Procesar resultados reales de Nikto"""
        try:
            findings = []
            lines = nikto_output.split('\n')
            
            for line in lines:
                line = line.strip()
                if line.startswith('+') and ':' in line:
                    # Parsear línea de hallazgo
                    parts = line[1:].split(':', 1)
                    if len(parts) == 2:
                        path = parts[0].strip()
                        description = parts[1].strip()
                        
                        findings.append({
                            'path': path,
                            'description': description,
                            'severity': self._determine_nikto_severity(description)
                        })
            
            by_severity = {'High': 0, 'Medium': 0, 'Low': 0}
            for finding in findings:
                by_severity[finding['severity']] += 1
            
            return {
                'status': 'completed',
                'tool': 'Nikto',
                'total_findings': len(findings),
                'findings_by_severity': by_severity,
                'detailed_findings': findings,
                'raw_output': nikto_output
            }
            
        except Exception as e:
            logger.error(f"Error procesando resultados Nikto: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _determine_nikto_severity(self, description: str) -> str:
        """Determinar severidad basada en descripción de Nikto"""
        desc_lower = description.lower()
        
        if any(word in desc_lower for word in ['vulnerable', 'exploit', 'shell', 'injection', 'execute']):
            return 'High'
        elif any(word in desc_lower for word in ['admin', 'config', 'password', 'disclosure', 'access']):
            return 'Medium'
        else:
            return 'Low'
    
    def _check_partial_results(self, json_file: Path) -> Optional[Dict]:
        """Verificar si hay resultados parciales en caso de timeout"""
        try:
            if json_file.exists() and json_file.stat().st_size > 10:
                with open(json_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return None
    
    def _generate_scan_id(self) -> str:
        """Generar ID único para el escaneo"""
        return datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4().hex)[:8]
    
    def _create_legacy_format(self, results: Dict, output_file: Path):
        """Crear formato legacy para compatibilidad con el sistema existente"""
        try:
            legacy_format = {}
            
            # Extraer datos de Wapiti
            if results.get('wapiti_results'):
                wapiti = results['wapiti_results']
                if wapiti.get('status') == 'completed':
                    # Crear estructura compatible
                    vulnerabilities = {}
                    for vuln in wapiti.get('detailed_vulnerabilities', []):
                        category = vuln['category']
                        if category not in vulnerabilities:
                            vulnerabilities[category] = []
                        vulnerabilities[category].append({
                            'info': vuln['info'],
                            'level': vuln['level'],
                            'method': vuln['method'],
                            'path': vuln['path'],
                            'parameter': vuln['parameter'],
                            'wstg': vuln['wstg']
                        })
                    
                    legacy_format = {
                        'vulnerabilities': vulnerabilities,
                        'infos': wapiti.get('target_info', {}),
                        'classifications': wapiti.get('classifications', {}),
                        'scan_metadata': {
                            'scan_id': results['scan_id'],
                            'target_url': results['target_url'],
                            'total_vulnerabilities': wapiti.get('total_vulnerabilities', 0),
                            'scan_duration': results.get('total_duration', 0)
                        }
                    }
            
            # Guardar formato legacy
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(legacy_format, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ Archivo legacy guardado: {output_file}")
            
        except Exception as e:
            logger.error(f"Error creando formato legacy: {e}")

# Instancia global del scanner real
real_scanner = RealWebScanner()

# Función para compatibilidad con el código existente
async def scan_target_async(target_url: str) -> Dict:
    """Función de compatibilidad que usa el scanner real"""
    result = await real_scanner.scan_url(target_url)
    
    # Convertir a formato esperado por el código existente
    if result.get('wapiti_results'):
        return {
            'wapiti': {
                'status': 'success',
                'output_file': result['wapiti_results'].get('json_file'),
                'stdout': result['wapiti_results'].get('raw_stdout', ''),
                'stderr': result['wapiti_results'].get('raw_stderr', '')
            }
        }
    else:
        return {
            'wapiti': {
                'status': 'error',
                'error': result.get('error', 'Escaneo falló')
            }
        }

def cleanup_old_reports():
    """Limpiar reportes antiguos"""
    try:
        real_scanner.results_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Directorio de resultados preparado")
    except Exception as e:
        logger.error(f"Error preparando directorio: {e}")
