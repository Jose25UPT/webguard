import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from loguru import logger

from app.core.scanner import scan_target_async
from app.services.security_apis import SecurityAPIsService
from app.services.virustotal_service import virustotal_service
from app.services.opensource_tools_service import opensource_tools_service
from app.utils.advanced_pdf_generator import advanced_pdf_generator


class EnhancedSecurityService:
    """Servicio coordinador para análisis completo de seguridad web"""
    
    def __init__(self):
        self.security_apis = SecurityAPIsService()
        self.results_dir = Path("results/enhanced_scans")
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    async def complete_security_analysis(self, target_url: str) -> Dict:
        """Análisis completo de seguridad integrando todas las herramientas"""
        try:
            session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            logger.info(f"🚀 Iniciando análisis completo para {target_url} (Sesión: {session_id})")
            
            # 1. Análisis básico con herramientas existentes (Wapiti + Nikto)
            logger.info("📡 Ejecutando escaneo con Wapiti y Nikto...")
            basic_scan_task = scan_target_async(target_url)
            
            # 2. Análisis con VirusTotal
            logger.info("🦠 Ejecutando análisis VirusTotal...")
            virustotal_task = virustotal_service.comprehensive_url_analysis(target_url)
            
            # 3. Análisis con herramientas de código abierto adicionales
            logger.info("🔧 Ejecutando análisis con herramientas adicionales...")
            opensource_task = opensource_tools_service.comprehensive_security_scan(target_url)
            
            # 4. Análisis de APIs de seguridad
            logger.info("🌐 Ejecutando análisis de APIs de seguridad...")
            security_apis_task = self.security_apis.analyze_url_comprehensive(target_url)
            
            # Ejecutar todos los análisis en paralelo
            results = await asyncio.gather(
                basic_scan_task,
                virustotal_task,
                opensource_task,
                security_apis_task,
                return_exceptions=True
            )
            
            # Compilar resultados
            comprehensive_report = {
                'session_id': session_id,
                'target_url': target_url,
                'scan_timestamp': datetime.now().isoformat(),
                'analysis_results': {
                    'basic_scan': results[0] if not isinstance(results[0], Exception) else {'error': str(results[0])},
                    'virustotal_analysis': results[1] if not isinstance(results[1], Exception) else {'error': str(results[1])},
                    'opensource_tools': results[2] if not isinstance(results[2], Exception) else {'error': str(results[2])},
                    'security_apis': results[3] if not isinstance(results[3], Exception) else {'error': str(results[3])}
                },
                'threat_assessment': self._generate_threat_assessment(results),
                'recommendations': self._generate_comprehensive_recommendations(results),
                'executive_summary': self._generate_executive_summary(results, target_url),
                'security_score': self._calculate_security_score(results)
            }
            
            # Guardar reporte
            report_file = self.results_dir / f"comprehensive_report_{session_id}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(comprehensive_report, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"✅ Análisis completo finalizado. Reporte guardado en: {report_file}")
            return comprehensive_report
            
        except Exception as e:
            logger.error(f"❌ Error en análisis completo: {e}")
            return {
                'error': str(e),
                'target_url': target_url,
                'scan_timestamp': datetime.now().isoformat()
            }
    
    def _generate_threat_assessment(self, results: List) -> Dict:
        """Generar evaluación de amenazas basada en todos los resultados"""
        threat_level = "LOW"
        threat_indicators = []
        confidence_score = 0
        
        try:
            # Análisis de VirusTotal
            virustotal_result = results[1] if len(results) > 1 and not isinstance(results[1], Exception) else {}
            if virustotal_result and not virustotal_result.get('error'):
                risk_assessment = virustotal_result.get('risk_assessment', {})
                vt_risk_level = risk_assessment.get('level', 'MÍNIMO')
                
                if vt_risk_level in ['CRÍTICO', 'ALTO']:
                    threat_level = "CRITICAL"
                    threat_indicators.extend(risk_assessment.get('factors', []))
                    confidence_score += 40
                elif vt_risk_level == 'MEDIO':
                    threat_level = max(threat_level, "MEDIUM", key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x))
                    confidence_score += 20
            
            # Análisis de herramientas de código abierto
            opensource_result = results[2] if len(results) > 2 and not isinstance(results[2], Exception) else {}
            if opensource_result and not opensource_result.get('error'):
                summary = opensource_result.get('summary', {})
                critical_issues = summary.get('critical_issues', 0)
                
                if critical_issues > 5:
                    threat_level = "CRITICAL"
                    threat_indicators.append(f"Múltiples vulnerabilidades críticas detectadas ({critical_issues})")
                    confidence_score += 30
                elif critical_issues > 0:
                    threat_level = max(threat_level, "HIGH", key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x))
                    confidence_score += 20
            
            # Análisis básico (Wapiti/Nikto)
            basic_result = results[0] if len(results) > 0 and not isinstance(results[0], Exception) else {}
            if basic_result:
                for tool, tool_result in basic_result.items():
                    if isinstance(tool_result, dict) and 'vulnerabilities' in tool_result:
                        vulns = tool_result['vulnerabilities']
                        if isinstance(vulns, dict):
                            total_vulns = sum(len(v) if isinstance(v, list) else 0 for v in vulns.values())
                        else:
                            total_vulns = len(vulns) if isinstance(vulns, list) else 0
                        
                        if total_vulns > 10:
                            threat_level = max(threat_level, "HIGH", key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x))
                            confidence_score += 15
                        elif total_vulns > 0:
                            threat_level = max(threat_level, "MEDIUM", key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x))
                            confidence_score += 10
            
        except Exception as e:
            logger.error(f"Error generando evaluación de amenazas: {e}")
        
        return {
            'threat_level': threat_level,
            'confidence_score': min(confidence_score, 100),
            'threat_indicators': threat_indicators,
            'recommendation': self._get_threat_recommendation(threat_level)
        }
    
    def _generate_comprehensive_recommendations(self, results: List) -> List[str]:
        """Generar recomendaciones comprehensivas"""
        recommendations = []
        
        # Recomendaciones de alta prioridad
        recommendations.extend([
            "🔒 CRÍTICO: Implementar autenticación multifactor en todas las cuentas administrativas",
            "🛡️ ALTO: Configurar Web Application Firewall (WAF) para filtrar tráfico malicioso",
            "🔄 ALTO: Establecer proceso de actualización automática de seguridad",
            "📊 MEDIO: Implementar monitoreo continuo de seguridad y alertas"
        ])
        
        try:
            # Recomendaciones basadas en VirusTotal
            virustotal_result = results[1] if len(results) > 1 and not isinstance(results[1], Exception) else {}
            if virustotal_result and not virustotal_result.get('error'):
                risk_assessment = virustotal_result.get('risk_assessment', {})
                if risk_assessment.get('level') in ['CRÍTICO', 'ALTO']:
                    recommendations.append("🚨 URGENTE: Aislar sistema - detectadas amenazas activas")
                    recommendations.append("🔍 Realizar análisis forense completo del sistema")
            
            # Recomendaciones basadas en herramientas opensource
            opensource_result = results[2] if len(results) > 2 and not isinstance(results[2], Exception) else {}
            if opensource_result and not opensource_result.get('error'):
                tool_recommendations = opensource_result.get('recommendations', [])
                recommendations.extend(tool_recommendations[:5])  # Agregar top 5
            
            # Recomendaciones específicas por vulnerabilidades encontradas
            basic_result = results[0] if len(results) > 0 and not isinstance(results[0], Exception) else {}
            if basic_result:
                for tool, tool_result in basic_result.items():
                    if isinstance(tool_result, dict) and 'vulnerabilities' in tool_result:
                        vulns = tool_result['vulnerabilities']
                        if isinstance(vulns, dict):
                            if 'SQL Injection' in vulns and vulns['SQL Injection']:
                                recommendations.append("🛑 CRÍTICO: Corregir vulnerabilidades de inyección SQL inmediatamente")
                            if 'Cross Site Scripting' in vulns and vulns['Cross Site Scripting']:
                                recommendations.append("⚠️ ALTO: Implementar validación y escape de entrada para prevenir XSS")
                            if 'File Handling' in vulns and vulns['File Handling']:
                                recommendations.append("📁 MEDIO: Revisar manejo de archivos y permisos de directorio")
            
            # Recomendaciones adicionales de mejores prácticas
            recommendations.extend([
                "🔐 Implementar Content Security Policy (CSP) estricta",
                "🔒 Configurar headers de seguridad HTTP (HSTS, X-Frame-Options, etc.)",
                "📝 Establecer logging y auditoría de accesos administrativos",
                "🔄 Realizar respaldos seguros y pruebas de restauración periódicas",
                "👥 Capacitar al equipo en mejores prácticas de seguridad"
            ])
            
        except Exception as e:
            logger.error(f"Error generando recomendaciones: {e}")
        
        return list(dict.fromkeys(recommendations))  # Remover duplicados manteniendo orden
    
    def _generate_executive_summary(self, results: List, target_url: str) -> Dict:
        """Generar resumen ejecutivo"""
        try:
            # Contar herramientas utilizadas
            tools_used = []
            total_vulnerabilities = 0
            critical_issues = 0
            
            # Análisis básico
            if len(results) > 0 and not isinstance(results[0], Exception):
                tools_used.extend(['Wapiti', 'Nikto'])
                basic_result = results[0]
                for tool, tool_result in basic_result.items():
                    if isinstance(tool_result, dict) and 'vulnerabilities' in tool_result:
                        vulns = tool_result['vulnerabilities']
                        if isinstance(vulns, dict):
                            for category, vuln_list in vulns.items():
                                if isinstance(vuln_list, list):
                                    total_vulnerabilities += len(vuln_list)
                                    for vuln in vuln_list:
                                        if vuln.get('level', 1) >= 3:
                                            critical_issues += 1
            
            # VirusTotal
            if len(results) > 1 and not isinstance(results[1], Exception):
                tools_used.append('VirusTotal')
                vt_result = results[1]
                if vt_result.get('url_analysis', {}).get('positives', 0) > 0:
                    critical_issues += 1
            
            # Herramientas de código abierto
            if len(results) > 2 and not isinstance(results[2], Exception):
                opensource_result = results[2]
                available_tools = opensource_result.get('available_tools', [])
                if 'simulation_mode' not in available_tools:
                    tools_used.extend(available_tools)
                
                summary = opensource_result.get('summary', {})
                total_vulnerabilities += summary.get('total_vulnerabilities', 0)
                critical_issues += summary.get('critical_issues', 0)
            
            # APIs de seguridad
            if len(results) > 3 and not isinstance(results[3], Exception):
                tools_used.append('Security APIs')
            
            # Calcular nivel de riesgo general
            if critical_issues > 5:
                overall_risk = "CRÍTICO"
            elif critical_issues > 2:
                overall_risk = "ALTO"
            elif total_vulnerabilities > 10:
                overall_risk = "MEDIO"
            elif total_vulnerabilities > 0:
                overall_risk = "BAJO"
            else:
                overall_risk = "MÍNIMO"
            
            # Hallazgos clave
            key_findings = []
            if critical_issues > 0:
                key_findings.append(f"Se encontraron {critical_issues} vulnerabilidades críticas")
            if total_vulnerabilities > 0:
                key_findings.append(f"Total de {total_vulnerabilities} vulnerabilidades identificadas")
            
            # VirusTotal findings
            if len(results) > 1 and not isinstance(results[1], Exception):
                vt_result = results[1]
                if vt_result.get('url_analysis', {}).get('positives', 0) > 0:
                    positives = vt_result['url_analysis']['positives']
                    total = vt_result['url_analysis']['total']
                    key_findings.append(f"VirusTotal detectó amenazas: {positives}/{total} motores")
            
            if not key_findings:
                key_findings = ["No se detectaron vulnerabilidades críticas en el análisis inicial"]
            
            return {
                'overall_risk_level': overall_risk,
                'total_vulnerabilities_found': total_vulnerabilities,
                'critical_issues': critical_issues,
                'tools_used': list(set(tools_used)),  # Remover duplicados
                'key_findings': key_findings,
                'scan_coverage': f"{len(tools_used)} herramientas utilizadas",
                'risk_score': self._calculate_risk_score_simple(total_vulnerabilities, critical_issues)
            }
            
        except Exception as e:
            logger.error(f"Error generando resumen ejecutivo: {e}")
            return {
                'overall_risk_level': 'DESCONOCIDO',
                'total_vulnerabilities_found': 0,
                'critical_issues': 0,
                'tools_used': [],
                'key_findings': ['Error al generar resumen'],
                'scan_coverage': 'Error en análisis',
                'risk_score': 0
            }
    
    def _calculate_security_score(self, results: List) -> Dict:
        """Calcular puntuación de seguridad (0-100, donde 100 es más seguro)"""
        base_score = 100
        deductions = []
        
        try:
            # Deducciones por vulnerabilidades básicas
            if len(results) > 0 and not isinstance(results[0], Exception):
                basic_result = results[0]
                for tool, tool_result in basic_result.items():
                    if isinstance(tool_result, dict) and 'vulnerabilities' in tool_result:
                        vulns = tool_result['vulnerabilities']
                        if isinstance(vulns, dict):
                            for category, vuln_list in vulns.items():
                                if isinstance(vuln_list, list):
                                    for vuln in vuln_list:
                                        level = vuln.get('level', 1)
                                        if level == 3:  # Alto
                                            base_score -= 15
                                            deductions.append(f"Vulnerabilidad alta: {category}")
                                        elif level == 2:  # Medio
                                            base_score -= 10
                                        else:  # Bajo
                                            base_score -= 5
            
            # Deducciones por VirusTotal
            if len(results) > 1 and not isinstance(results[1], Exception):
                vt_result = results[1]
                risk_score = vt_result.get('risk_assessment', {}).get('score', 0)
                if risk_score > 50:
                    base_score -= 25
                    deductions.append("Amenazas detectadas por VirusTotal")
                elif risk_score > 20:
                    base_score -= 15
            
            # Bonificaciones por buenas prácticas
            if len(results) > 3 and not isinstance(results[3], Exception):
                security_apis_result = results[3]
                headers = security_apis_result.get('security_headers', {})
                if headers and not headers.get('error'):
                    security_score = headers.get('security_score', '0/7')
                    implemented = int(security_score.split('/')[0])
                    if implemented >= 5:
                        base_score += 5  # Bonus por buenas prácticas
            
        except Exception as e:
            logger.error(f"Error calculando puntuación de seguridad: {e}")
        
        final_score = max(0, min(100, base_score))
        
        if final_score >= 80:
            grade = "A"
            description = "Excelente nivel de seguridad"
        elif final_score >= 60:
            grade = "B"
            description = "Buen nivel de seguridad con mejoras menores"
        elif final_score >= 40:
            grade = "C"
            description = "Nivel de seguridad moderado, requiere atención"
        elif final_score >= 20:
            grade = "D"
            description = "Nivel de seguridad bajo, requiere acción inmediata"
        else:
            grade = "F"
            description = "Nivel de seguridad crítico, riesgo muy alto"
        
        return {
            'score': final_score,
            'grade': grade,
            'description': description,
            'deductions': deductions
        }
    
    def _calculate_risk_score_simple(self, total_vulns: int, critical_issues: int) -> int:
        """Calcular puntuación de riesgo simple"""
        risk_score = (critical_issues * 15) + (total_vulns * 2)
        return min(100, risk_score)
    
    def _get_threat_recommendation(self, threat_level: str) -> str:
        """Obtener recomendación basada en nivel de amenaza"""
        recommendations = {
            'CRITICAL': "🚨 ACCIÓN INMEDIATA: Aislar sistema y contactar equipo de respuesta a incidentes",
            'HIGH': "⚠️ URGENTE: Implementar medidas de mitigación en las próximas 24 horas",
            'MEDIUM': "⚡ ATENCIÓN: Planificar correcciones en la próxima semana",
            'LOW': "💡 MONITOREO: Mantener vigilancia y aplicar mejores prácticas"
        }
        return recommendations.get(threat_level, "Evaluar situación manualmente")
    
    async def generate_enhanced_pdf_report(self, report_data: Dict) -> str:
        """Generar reporte PDF mejorado"""
        try:
            return advanced_pdf_generator.generate_pentest_pdf(report_data)
        except Exception as e:
            logger.error(f"Error generando PDF mejorado: {e}")
            raise e


# Instancia global del servicio
enhanced_security_service = EnhancedSecurityService()
