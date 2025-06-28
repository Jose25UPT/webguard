import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Callable
from loguru import logger
from dataclasses import dataclass, asdict

from app.core.scanner import scan_target_async
from app.services.real_security_apis import real_security_apis
from app.services.virustotal_service import virustotal_service
from app.services.opensource_tools_service import opensource_tools_service


@dataclass
class ScanProgress:
    scan_id: str
    target_url: str
    status: str
    progress: int
    current_step: str
    results: Dict
    vulnerabilities_found: int
    critical_issues: int
    recommendations: List[str]
    started_at: str
    updated_at: str


class LiveAnalysisService:
    """Servicio de análisis progresivo que actualiza resultados en tiempo real"""
    
    def __init__(self):
        self.active_scans: Dict[str, ScanProgress] = {}
        self.results_dir = Path("results/live_analysis")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.callbacks: Dict[str, List[Callable]] = {}
    
    async def start_progressive_scan(self, target_url: str, callback: Optional[Callable] = None) -> str:
        """Iniciar escaneo progresivo con actualizaciones en tiempo real"""
        scan_id = str(uuid.uuid4())
        
        # Inicializar progreso
        progress = ScanProgress(
            scan_id=scan_id,
            target_url=target_url,
            status="iniciando",
            progress=0,
            current_step="Preparando análisis...",
            results={},
            vulnerabilities_found=0,
            critical_issues=0,
            recommendations=[],
            started_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat()
        )
        
        self.active_scans[scan_id] = progress
        
        # Registrar callback si se proporciona
        if callback:
            if scan_id not in self.callbacks:
                self.callbacks[scan_id] = []
            self.callbacks[scan_id].append(callback)
        
        # Iniciar análisis en background
        asyncio.create_task(self._execute_progressive_analysis(scan_id))
        
        logger.info(f"Análisis progresivo iniciado: {scan_id} para {target_url}")
        return scan_id
    
    async def _execute_progressive_analysis(self, scan_id: str):
        """Ejecutar análisis progresivo paso a paso"""
        try:
            progress = self.active_scans[scan_id]
            
            # Paso 1: Análisis rápido inicial (5%)
            await self._update_progress(scan_id, 5, "Análisis inicial de URL...")
            initial_check = await self._quick_url_check(progress.target_url)
            progress.results['initial_check'] = initial_check
            
            # Paso 2: Escaneo con herramientas básicas (25%)
            await self._update_progress(scan_id, 25, "Ejecutando Wapiti y Nikto...")
            basic_scan = await scan_target_async(progress.target_url)
            progress.results['basic_scan'] = basic_scan
            await self._process_basic_scan_results(scan_id, basic_scan)
            
            # Paso 3: Análisis con APIs de seguridad (50%)
            await self._update_progress(scan_id, 50, "Consultando APIs de seguridad...")
            security_apis = await real_security_apis.comprehensive_security_audit(progress.target_url)
            progress.results['security_apis'] = security_apis
            await self._process_security_apis_results(scan_id, security_apis)
            
            # Paso 4: VirusTotal análisis (70%)
            await self._update_progress(scan_id, 70, "Analizando con VirusTotal...")
            vt_analysis = await virustotal_service.comprehensive_url_analysis(progress.target_url)
            progress.results['virustotal'] = vt_analysis
            await self._process_virustotal_results(scan_id, vt_analysis)
            
            # Paso 5: Herramientas adicionales (85%)
            await self._update_progress(scan_id, 85, "Ejecutando herramientas adicionales...")
            additional_tools = await opensource_tools_service.comprehensive_security_scan(progress.target_url)
            progress.results['additional_tools'] = additional_tools
            await self._process_additional_tools_results(scan_id, additional_tools)
            
            # Paso 6: Análisis final y recomendaciones (100%)
            await self._update_progress(scan_id, 100, "Generando reporte final...")
            await self._generate_final_recommendations(scan_id)
            
            # Marcar como completado
            progress.status = "completado"
            progress.current_step = "Análisis completado"
            await self._notify_callbacks(scan_id)
            
            # Guardar reporte final
            await self._save_final_report(scan_id)
            
        except Exception as e:
            logger.error(f"Error en análisis progresivo {scan_id}: {e}")
            await self._update_progress(scan_id, 0, f"Error: {str(e)}", status="error")
    
    async def _update_progress(self, scan_id: str, progress: int, step: str, status: str = "ejecutando"):
        """Actualizar progreso del escaneo"""
        if scan_id in self.active_scans:
            scan_progress = self.active_scans[scan_id]
            scan_progress.progress = progress
            scan_progress.current_step = step
            scan_progress.status = status
            scan_progress.updated_at = datetime.now().isoformat()
            
            # Notificar callbacks
            await self._notify_callbacks(scan_id)
    
    async def _notify_callbacks(self, scan_id: str):
        """Notificar a todos los callbacks registrados"""
        if scan_id in self.callbacks:
            for callback in self.callbacks[scan_id]:
                try:
                    await callback(self.active_scans[scan_id])
                except Exception as e:
                    logger.error(f"Error en callback para {scan_id}: {e}")
    
    async def _quick_url_check(self, url: str) -> Dict:
        """Verificación rápida inicial de la URL"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.head(url, timeout=10) as response:
                    return {
                        'accessible': True,
                        'status_code': response.status,
                        'server': response.headers.get('Server', 'Unknown'),
                        'content_type': response.headers.get('Content-Type', 'Unknown'),
                        'https_enabled': url.startswith('https://'),
                        'response_time': 'Normal'
                    }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e),
                'https_enabled': url.startswith('https://'),
                'response_time': 'Timeout'
            }
    
    async def _process_basic_scan_results(self, scan_id: str, basic_scan: Dict):
        """Procesar resultados del escaneo básico"""
        progress = self.active_scans[scan_id]
        vuln_count = 0
        critical_count = 0
        
        for tool, result in basic_scan.items():
            if isinstance(result, dict):
                try:
                    # Procesar resultados específicos por herramienta
                    if tool == 'wapiti' and result.get('json_file'):
                        wapiti_stats = await self._process_wapiti_json_for_live(result['json_file'])
                        vuln_count += wapiti_stats['total_vulnerabilities']
                        critical_count += wapiti_stats['critical_vulnerabilities']
                        
                        # Añadir recomendaciones específicas de Wapiti
                        if wapiti_stats['sql_injection_found']:
                            progress.recommendations.append("🚨 CRÍTICO: Inyección SQL detectada por Wapiti")
                        if wapiti_stats['xss_found']:
                            progress.recommendations.append("⚠️ Vulnerabilidades XSS encontradas")
                            
                    elif tool == 'nikto' and result.get('json_file'):
                        nikto_stats = await self._process_nikto_json_for_live(result['json_file'])
                        vuln_count += nikto_stats['total_vulnerabilities']
                        critical_count += nikto_stats['critical_vulnerabilities']
                        
                        # Añadir recomendaciones específicas de Nikto
                        if nikto_stats['admin_directories_found']:
                            progress.recommendations.append("📁 Directorios administrativos expuestos")
                        if nikto_stats['config_files_found']:
                            progress.recommendations.append("⚠️ Archivos de configuración accesibles")
                    
                    # Procesar estadísticas generales de la herramienta
                    elif 'statistics' in result:
                        stats = result['statistics']
                        vuln_count += stats.get('total_vulnerabilities', 0)
                        critical_count += stats.get('by_severity', {}).get('High', 0)
                        
                except Exception as e:
                    logger.error(f"Error procesando resultados de {tool}: {e}")
        
        progress.vulnerabilities_found += vuln_count
        progress.critical_issues += critical_count
        
        # Añadir recomendaciones generales si hay vulnerabilidades
        if vuln_count > 0:
            progress.recommendations.append(f"🔍 Total: {vuln_count} vulnerabilidades detectadas")
        if critical_count > 0:
            progress.recommendations.append(f"🚨 URGENTE: {critical_count} vulnerabilidades críticas requieren atención inmediata")
        if vuln_count == 0:
            progress.recommendations.append("✅ No se detectaron vulnerabilidades en el escaneo básico")
    
    async def _process_security_apis_results(self, scan_id: str, security_apis: Dict):
        """Procesar resultados de APIs de seguridad"""
        progress = self.active_scans[scan_id]
        
        # VirusTotal URL analysis
        vt_url = security_apis.get('virustotal_url', {})
        if vt_url.get('positives', 0) > 0:
            progress.critical_issues += vt_url['positives']
            progress.recommendations.append(f"🦠 VirusTotal detectó {vt_url['positives']} motores de seguridad")
        
        # AbuseIPDB
        abuse_check = security_apis.get('abuseipdb_check', {})
        if abuse_check.get('abuse_confidence', 0) > 25:
            progress.recommendations.append(f"⚡ IP con {abuse_check['abuse_confidence']}% confianza de abuso")
        
        # SSL Certificate
        ssl_cert = security_apis.get('ssl_certificate', {})
        if ssl_cert.get('is_expired') or ssl_cert.get('error'):
            progress.recommendations.append("🔒 Certificado SSL expirado o inválido")
        
        # Shodan
        shodan = security_apis.get('shodan_analysis', {})
        if shodan.get('vulns'):
            vuln_count = len(shodan['vulns'])
            progress.vulnerabilities_found += vuln_count
            progress.recommendations.append(f"🔍 Shodan detectó {vuln_count} vulnerabilidades")
    
    async def _process_virustotal_results(self, scan_id: str, vt_analysis: Dict):
        """Procesar resultados de VirusTotal"""
        progress = self.active_scans[scan_id]
        
        risk_assessment = vt_analysis.get('risk_assessment', {})
        risk_level = risk_assessment.get('level', 'MÍNIMO')
        
        if risk_level in ['CRÍTICO', 'ALTO']:
            progress.critical_issues += 5
            progress.recommendations.append(f"🚨 VirusTotal: Nivel de riesgo {risk_level}")
        elif risk_level == 'MEDIO':
            progress.recommendations.append(f"⚠️ VirusTotal: Riesgo moderado detectado")
        
        # Archivos descargables maliciosos
        files = vt_analysis.get('downloadable_files', {})
        if files.get('analyses'):
            malicious_files = [f for f in files['analyses'] if f.get('is_malicious')]
            if malicious_files:
                progress.critical_issues += len(malicious_files)
                progress.recommendations.append(f"📁 {len(malicious_files)} archivos maliciosos detectados")
    
    async def _process_additional_tools_results(self, scan_id: str, additional_tools: Dict):
        """Procesar resultados de herramientas adicionales"""
        progress = self.active_scans[scan_id]
        
        summary = additional_tools.get('summary', {})
        total_vulns = summary.get('total_vulnerabilities', 0)
        critical_issues = summary.get('critical_issues', 0)
        
        progress.vulnerabilities_found += total_vulns
        progress.critical_issues += critical_issues
        
        if total_vulns > 0:
            progress.recommendations.append(f"🔧 Herramientas adicionales: {total_vulns} vulnerabilidades")
        
        # Añadir recomendaciones específicas de las herramientas
        tool_recommendations = additional_tools.get('recommendations', [])
        progress.recommendations.extend(tool_recommendations[:3])  # Top 3
    
    async def _generate_final_recommendations(self, scan_id: str):
        """Generar recomendaciones finales basadas en todos los hallazgos"""
        progress = self.active_scans[scan_id]
        
        # Recomendaciones basadas en criticidad
        if progress.critical_issues > 5:
            progress.recommendations.insert(0, "🚨 URGENTE: Múltiples vulnerabilidades críticas - Requiere acción inmediata")
        elif progress.critical_issues > 0:
            progress.recommendations.insert(0, f"⚠️ ALTA PRIORIDAD: {progress.critical_issues} problemas críticos detectados")
        
        # Recomendaciones generales de seguridad
        general_recommendations = [
            "🔐 Implementar autenticación multifactor",
            "🛡️ Configurar Web Application Firewall (WAF)",
            "🔄 Mantener software actualizado",
            "📊 Implementar monitoreo continuo",
            "🔒 Revisar configuración de headers de seguridad"
        ]
        
        # Añadir solo si no están ya incluidas
        for rec in general_recommendations:
            if not any(similar in existing for existing in progress.recommendations for similar in [rec[:10]]):
                progress.recommendations.append(rec)
        
        # Limitar a 10 recomendaciones más importantes
        progress.recommendations = progress.recommendations[:10]
    
    async def _save_final_report(self, scan_id: str):
        """Guardar reporte final"""
        try:
            progress = self.active_scans[scan_id]
            report_file = self.results_dir / f"live_analysis_{scan_id}.json"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(progress), f, indent=2, ensure_ascii=False)
            
            logger.info(f"Reporte final guardado: {report_file}")
        except Exception as e:
            logger.error(f"Error guardando reporte final: {e}")
    
    def get_scan_progress(self, scan_id: str) -> Optional[ScanProgress]:
        """Obtener progreso actual de un escaneo"""
        return self.active_scans.get(scan_id)
    
    def get_active_scans(self) -> List[ScanProgress]:
        """Obtener todos los escaneos activos"""
        return list(self.active_scans.values())
    
    async def _process_wapiti_json_for_live(self, json_file_path: str) -> Dict:
        """Procesar archivo JSON de Wapiti para análisis en vivo"""
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                wapiti_data = json.load(f)
            
            stats = {
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'sql_injection_found': False,
                'xss_found': False,
                'categories': {}
            }
            
            # Procesar vulnerabilidades
            vulnerabilities = wapiti_data.get('vulnerabilities', {})
            for category, vulns in vulnerabilities.items():
                if isinstance(vulns, list) and vulns:
                    stats['categories'][category] = len(vulns)
                    stats['total_vulnerabilities'] += len(vulns)
                    
                    # Detectar tipos específicos
                    if 'sql' in category.lower() or 'injection' in category.lower():
                        stats['sql_injection_found'] = True
                    if 'xss' in category.lower() or 'cross site scripting' in category.lower():
                        stats['xss_found'] = True
                    
                    # Contar vulnerabilidades críticas (nivel 3+)
                    for vuln in vulns:
                        if vuln.get('level', 0) >= 3:
                            stats['critical_vulnerabilities'] += 1
            
            logger.info(f"Wapiti procesado: {stats['total_vulnerabilities']} vulnerabilidades, {stats['critical_vulnerabilities']} críticas")
            return stats
            
        except Exception as e:
            logger.error(f"Error procesando JSON de Wapiti {json_file_path}: {e}")
            return {
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'sql_injection_found': False,
                'xss_found': False,
                'categories': {}
            }
    
    async def _process_nikto_json_for_live(self, json_file_path: str) -> Dict:
        """Procesar archivo JSON de Nikto para análisis en vivo"""
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Nikto puede generar múltiples líneas JSON
                json_lines = [line for line in content.strip().split('\n') if line.strip()]
                if json_lines:
                    nikto_data = json.loads(json_lines[-1])  # Tomar el último
                else:
                    raise ValueError("No se encontraron datos JSON válidos")
            
            stats = {
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'admin_directories_found': False,
                'config_files_found': False,
                'categories': {}
            }
            
            # Procesar vulnerabilidades
            vulnerabilities = nikto_data.get('vulnerabilities', [])
            if vulnerabilities:
                stats['total_vulnerabilities'] = len(vulnerabilities)
                
                for vuln in vulnerabilities:
                    msg = vuln.get('msg', '').lower()
                    vuln_id = vuln.get('id', '')
                    
                    # Detectar tipos específicos
                    if 'admin' in msg or 'administrative' in msg:
                        stats['admin_directories_found'] = True
                    if 'config' in msg or 'configuration' in msg or '.conf' in msg:
                        stats['config_files_found'] = True
                    
                    # Clasificar severidad
                    if any(keyword in msg for keyword in ['vulnerable', 'exploit', 'shell', 'injection']):
                        stats['critical_vulnerabilities'] += 1
                    
                    # Categorizar por tipo
                    category = vuln_id.split('-')[0] if vuln_id else 'general'
                    stats['categories'][category] = stats['categories'].get(category, 0) + 1
            
            logger.info(f"Nikto procesado: {stats['total_vulnerabilities']} vulnerabilidades, {stats['critical_vulnerabilities']} críticas")
            return stats
            
        except Exception as e:
            logger.error(f"Error procesando JSON de Nikto {json_file_path}: {e}")
            return {
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'admin_directories_found': False,
                'config_files_found': False,
                'categories': {}
            }
    
    def remove_completed_scan(self, scan_id: str):
        """Remover escaneo completado del cache"""
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
        if scan_id in self.callbacks:
            del self.callbacks[scan_id]


# Instancia global
live_analysis_service = LiveAnalysisService()
