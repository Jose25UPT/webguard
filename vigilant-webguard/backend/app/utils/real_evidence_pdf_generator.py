import json
import os
from datetime import datetime
from pathlib import Path
from jinja2 import Template
from weasyprint import HTML, CSS
from typing import Dict, List, Optional
from loguru import logger
import glob

class RealEvidencePDFGenerator:
    """Generador de PDF mejorado que usa evidencias reales de Wapiti y Nikto"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        
        # Asegurar que el directorio results/reports existe
        self.output_dir = Path("results/reports")
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"✅ Directorio creado/verificado: {self.output_dir.absolute()}")
        except Exception as e:
            logger.error(f"❌ Error creando directorio {self.output_dir}: {e}")
            # Usar directorio temporal como fallback
            import tempfile
            self.output_dir = Path(tempfile.gettempdir()) / "security_reports"
            self.output_dir.mkdir(parents=True, exist_ok=True)
            logger.warning(f"⚠️ Usando directorio temporal: {self.output_dir}")
        
        self.results_dir = Path("results")
    
    def generate_comprehensive_pdf(self, target_url: str = None) -> str:
        """Generar PDF completo con evidencias reales de todos los escaneos"""
        try:
            logger.info("🔍 Buscando archivos de resultados reales...")
            
            # Buscar archivos JSON reales de Wapiti y Nikto
            wapiti_data = self._find_latest_wapiti_results()
            nikto_data = self._find_latest_nikto_results()
            
            # Buscar datos de análisis en vivo si existen
            live_data = self._find_latest_live_analysis()
            
            # Buscar último reporte de pentesting
            pentest_data = self._find_latest_pentest_report()
            
            # Compilar todos los datos
            report_data = {
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'target_url': target_url or self._extract_target_url(wapiti_data, nikto_data, pentest_data),
                'wapiti_results': wapiti_data,
                'nikto_results': nikto_data,
                'live_analysis': live_data,
                'pentest_report': pentest_data,
                'summary': self._generate_real_summary(wapiti_data, nikto_data, live_data)
            }
            
            # Crear HTML desde template
            html_content = self._create_enhanced_html_report(report_data)
            
            # Generar PDF
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"security_audit_report_{timestamp}.pdf"
            pdf_path = self.output_dir / pdf_filename
            
            # Convertir HTML a PDF
            HTML(string=html_content).write_pdf(
                pdf_path,
                stylesheets=[CSS(string=self._get_enhanced_css_styles())]
            )
            
            logger.info(f"✅ PDF generado exitosamente: {pdf_path}")
            return str(pdf_path)
            
        except Exception as e:
            logger.error(f"❌ Error generando PDF: {e}")
            raise e
    
    def _find_latest_wapiti_results(self) -> Optional[Dict]:
        """Buscar los resultados más recientes de Wapiti"""
        try:
            # Buscar archivos JSON de Wapiti
            wapiti_patterns = [
                "results/opensource_tools/wapiti_*/report.json",
                "results/wapiti_*/report.json",
                "results/scan_*.json"
            ]
            
            latest_file = None
            latest_time = 0
            
            for pattern in wapiti_patterns:
                files = glob.glob(pattern)
                for file_path in files:
                    file_time = os.path.getmtime(file_path)
                    if file_time > latest_time:
                        latest_time = file_time
                        latest_file = file_path
            
            if latest_file:
                logger.info(f"📄 Archivo Wapiti encontrado: {latest_file}")
                with open(latest_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Si es un archivo de scan básico, extraer datos de Wapiti
                if 'wapiti' in data:
                    return data['wapiti']
                # Si es un archivo JSON directo de Wapiti
                elif 'vulnerabilities' in data:
                    return self._process_wapiti_json(data)
                
            logger.warning("⚠️ No se encontraron archivos de Wapiti")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error buscando resultados Wapiti: {e}")
            return None
    
    def _find_latest_nikto_results(self) -> Optional[Dict]:
        """Buscar los resultados más recientes de Nikto"""
        try:
            # Buscar archivos JSON de Nikto
            nikto_patterns = [
                "results/opensource_tools/nikto_*/nikto_report.json",
                "results/nikto_*/nikto_report.json"
            ]
            
            latest_file = None
            latest_time = 0
            
            for pattern in nikto_patterns:
                files = glob.glob(pattern)
                for file_path in files:
                    file_time = os.path.getmtime(file_path)
                    if file_time > latest_time:
                        latest_time = file_time
                        latest_file = file_path
            
            if latest_file:
                logger.info(f"📄 Archivo Nikto encontrado: {latest_file}")
                with open(latest_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Nikto puede generar múltiples líneas JSON
                    json_lines = [line for line in content.strip().split('\n') if line.strip()]
                    if json_lines:
                        data = json.loads(json_lines[-1])
                        return self._process_nikto_json(data)
                
            logger.warning("⚠️ No se encontraron archivos de Nikto")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error buscando resultados Nikto: {e}")
            return None
    
    def _find_latest_live_analysis(self) -> Optional[Dict]:
        """Buscar el análisis en vivo más reciente"""
        try:
            pattern = "results/live_analysis/live_analysis_*.json"
            files = glob.glob(pattern)
            
            if files:
                latest_file = max(files, key=os.path.getmtime)
                logger.info(f"📄 Análisis en vivo encontrado: {latest_file}")
                with open(latest_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            logger.warning("⚠️ No se encontraron análisis en vivo")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error buscando análisis en vivo: {e}")
            return None
    
    def _find_latest_pentest_report(self) -> Optional[Dict]:
        """Buscar el reporte de pentesting más reciente"""
        try:
            pattern = "results/pentest_report_*.json"
            files = glob.glob(pattern)
            
            if files:
                latest_file = max(files, key=os.path.getmtime)
                logger.info(f"📄 Reporte de pentesting encontrado: {latest_file}")
                with open(latest_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            logger.warning("⚠️ No se encontraron reportes de pentesting")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error buscando reportes de pentesting: {e}")
            return None
    
    def _process_wapiti_json(self, wapiti_data: Dict) -> Dict:
        """Procesar datos JSON de Wapiti"""
        try:
            vulnerabilities = wapiti_data.get('vulnerabilities', {})
            statistics = {
                'total_vulnerabilities': 0,
                'by_severity': {'High': 0, 'Medium': 0, 'Low': 0},
                'by_category': {}
            }
            
            processed_vulns = []
            
            for category, vulns in vulnerabilities.items():
                if isinstance(vulns, list) and vulns:
                    statistics['by_category'][category] = len(vulns)
                    statistics['total_vulnerabilities'] += len(vulns)
                    
                    for vuln in vulns:
                        level = vuln.get('level', 1)
                        severity = 'High' if level >= 3 else 'Medium' if level == 2 else 'Low'
                        statistics['by_severity'][severity] += 1
                        
                        processed_vulns.append({
                            'category': category,
                            'info': vuln.get('info', ''),
                            'method': vuln.get('method', 'GET'),
                            'path': vuln.get('path', '/'),
                            'parameter': vuln.get('parameter', ''),
                            'level': level,
                            'severity': severity,
                            'wstg': vuln.get('wstg', []),
                            'references': vuln.get('references', [])
                        })
            
            return {
                'status': 'completed',
                'tool': 'Wapiti3',
                'vulnerabilities': processed_vulns,
                'statistics': statistics,
                'infos': wapiti_data.get('infos', {}),
                'classifications': wapiti_data.get('classifications', {})
            }
            
        except Exception as e:
            logger.error(f"❌ Error procesando JSON Wapiti: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _process_nikto_json(self, nikto_data: Dict) -> Dict:
        """Procesar datos JSON de Nikto"""
        try:
            vulnerabilities = nikto_data.get('vulnerabilities', [])
            statistics = {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': {'High': 0, 'Medium': 0, 'Low': 0},
                'by_category': {}
            }
            
            processed_vulns = []
            
            for vuln in vulnerabilities:
                # Determinar severidad
                msg = vuln.get('msg', '').lower()
                if any(keyword in msg for keyword in ['vulnerable', 'exploit', 'shell', 'injection']):
                    severity = 'High'
                elif any(keyword in msg for keyword in ['admin', 'config', 'disclosure']):
                    severity = 'Medium'
                else:
                    severity = 'Low'
                
                statistics['by_severity'][severity] += 1
                
                # Categorizar
                vuln_id = vuln.get('id', '')
                category = vuln_id.split('-')[0] if vuln_id else 'general'
                statistics['by_category'][category] = statistics['by_category'].get(category, 0) + 1
                
                processed_vulns.append({
                    'id': vuln.get('id', ''),
                    'osvdb': vuln.get('osvdb', ''),
                    'url': vuln.get('url', ''),
                    'msg': vuln.get('msg', ''),
                    'method': vuln.get('method', 'GET'),
                    'severity': severity,
                    'category': category
                })
            
            return {
                'status': 'completed',
                'tool': 'Nikto',
                'vulnerabilities': processed_vulns,
                'statistics': statistics,
                'host_info': nikto_data.get('host', {}),
                'scan_details': nikto_data.get('scan_details', {})
            }
            
        except Exception as e:
            logger.error(f"❌ Error procesando JSON Nikto: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _extract_target_url(self, wapiti_data: Dict, nikto_data: Dict, pentest_data: Dict) -> str:
        """Extraer URL objetivo de los datos disponibles"""
        # Intentar de diferentes fuentes
        if pentest_data and 'target_url' in pentest_data:
            return pentest_data['target_url']
        
        if wapiti_data and 'infos' in wapiti_data:
            return wapiti_data['infos'].get('target', 'URL no disponible')
        
        if nikto_data and 'host_info' in nikto_data:
            return nikto_data['host_info'].get('target', 'URL no disponible')
        
        return 'URL no disponible'
    
    def _generate_real_summary(self, wapiti_data: Dict, nikto_data: Dict, live_data: Dict) -> Dict:
        """Generar resumen basado en datos reales"""
        summary = {
            'total_vulnerabilities': 0,
            'critical_issues': 0,
            'tools_executed': [],
            'risk_level': 'LOW',
            'key_findings': []
        }
        
        # Contar desde Wapiti
        if wapiti_data and wapiti_data.get('status') == 'completed':
            summary['tools_executed'].append('Wapiti3')
            stats = wapiti_data.get('statistics', {})
            summary['total_vulnerabilities'] += stats.get('total_vulnerabilities', 0)
            summary['critical_issues'] += stats.get('by_severity', {}).get('High', 0)
            
            if summary['total_vulnerabilities'] > 0:
                summary['key_findings'].append(f"Wapiti detectó {summary['total_vulnerabilities']} vulnerabilidades")
        
        # Contar desde Nikto
        if nikto_data and nikto_data.get('status') == 'completed':
            summary['tools_executed'].append('Nikto')
            stats = nikto_data.get('statistics', {})
            nikto_vulns = stats.get('total_vulnerabilities', 0)
            nikto_critical = stats.get('by_severity', {}).get('High', 0)
            
            summary['total_vulnerabilities'] += nikto_vulns
            summary['critical_issues'] += nikto_critical
            
            if nikto_vulns > 0:
                summary['key_findings'].append(f"Nikto identificó {nikto_vulns} problemas de seguridad")
        
        # Contar desde análisis en vivo
        if live_data:
            summary['tools_executed'].append('Análisis en Vivo')
            live_vulns = live_data.get('vulnerabilities_found', 0)
            live_critical = live_data.get('critical_issues', 0)
            
            summary['total_vulnerabilities'] += live_vulns
            summary['critical_issues'] += live_critical
        
        # Determinar nivel de riesgo
        if summary['critical_issues'] > 5:
            summary['risk_level'] = 'CRITICAL'
        elif summary['critical_issues'] > 2:
            summary['risk_level'] = 'HIGH'
        elif summary['critical_issues'] > 0:
            summary['risk_level'] = 'MEDIUM'
        elif summary['total_vulnerabilities'] > 0:
            summary['risk_level'] = 'LOW'
        else:
            summary['risk_level'] = 'MINIMAL'
            summary['key_findings'].append('No se detectaron vulnerabilidades críticas')
        
        return summary
    
    def _create_enhanced_html_report(self, report_data: Dict) -> str:
        """Crear contenido HTML mejorado del reporte"""
        template = Template(self._get_enhanced_html_template())
        return template.render(**report_data)
    
    def _get_enhanced_html_template(self) -> str:
        """Template HTML mejorado para el reporte"""
        return '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Auditoría de Seguridad Web - Vigilant WebGuard</title>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="logo">
            <h1>🛡️ Vigilant WebGuard</h1>
            <h2>Reporte de Auditoría de Seguridad Web con Evidencias Reales</h2>
        </div>
        <div class="report-info">
            <p><strong>🎯 URL Objetivo:</strong> {{ target_url }}</p>
            <p><strong>📅 Fecha de Generación:</strong> {{ generated_at }}</p>
            <p><strong>🔍 Herramientas Utilizadas:</strong> {{ summary.tools_executed | join(', ') }}</p>
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <h2>📊 Resumen Ejecutivo</h2>
        <div class="summary-grid">
            <div class="summary-item risk-{{ summary.risk_level.lower() }}">
                <h3>🚨 Nivel de Riesgo</h3>
                <p class="risk-level">{{ summary.risk_level }}</p>
            </div>
            <div class="summary-item">
                <h3>🔍 Total Vulnerabilidades</h3>
                <p class="number">{{ summary.total_vulnerabilities }}</p>
            </div>
            <div class="summary-item critical">
                <h3>⚠️ Problemas Críticos</h3>
                <p class="number">{{ summary.critical_issues }}</p>
            </div>
            <div class="summary-item">
                <h3>🛠️ Herramientas</h3>
                <p class="number">{{ summary.tools_executed | length }}</p>
            </div>
        </div>
        
        <h3>🎯 Hallazgos Principales</h3>
        <ul class="findings-list">
            {% for finding in summary.key_findings %}
            <li>{{ finding }}</li>
            {% endfor %}
        </ul>
    </div>

    <!-- Wapiti Results -->
    {% if wapiti_results and wapiti_results.status == 'completed' %}
    <div class="section">
        <h2>🔍 Resultados de Wapiti3 - Evidencias Reales</h2>
        
        <div class="tool-info">
            <p><strong>Estado:</strong> ✅ Completado exitosamente</p>
            <p><strong>Vulnerabilidades encontradas:</strong> {{ wapiti_results.statistics.total_vulnerabilities }}</p>
            <p><strong>Categorías analizadas:</strong> {{ wapiti_results.statistics.by_category | length }}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-item high">
                <h4>🔴 Severidad Alta</h4>
                <p>{{ wapiti_results.statistics.by_severity.High }}</p>
            </div>
            <div class="stat-item medium">
                <h4>🟡 Severidad Media</h4>
                <p>{{ wapiti_results.statistics.by_severity.Medium }}</p>
            </div>
            <div class="stat-item low">
                <h4>🟢 Severidad Baja</h4>
                <p>{{ wapiti_results.statistics.by_severity.Low }}</p>
            </div>
        </div>
        
        {% if wapiti_results.vulnerabilities %}
        <h3>🔍 Vulnerabilidades Detectadas por Wapiti</h3>
        {% for vuln in wapiti_results.vulnerabilities %}
        <div class="vulnerability-item level-{{ vuln.level }}">
            <div class="vuln-header">
                <h4>{{ vuln.category }} - {{ vuln.severity }}</h4>
                <span class="level-badge level-{{ vuln.level }}">Nivel {{ vuln.level }}</span>
            </div>
            <div class="vuln-details">
                <p><strong>📝 Descripción:</strong> {{ vuln.info }}</p>
                <p><strong>🌐 Método:</strong> {{ vuln.method }} - <strong>📍 Ruta:</strong> {{ vuln.path }}</p>
                {% if vuln.parameter %}
                <p><strong>🔧 Parámetro:</strong> {{ vuln.parameter }}</p>
                {% endif %}
                {% if vuln.wstg %}
                <p><strong>📚 OWASP WSTG:</strong> {{ vuln.wstg | join(', ') }}</p>
                {% endif %}
            </div>
        </div>
        {% endfor %}
        {% else %}
        <div class="no-vulns">
            <p>✅ Wapiti no encontró vulnerabilidades en este análisis.</p>
        </div>
        {% endif %}
    </div>
    {% endif %}

    <!-- Nikto Results -->
    {% if nikto_results and nikto_results.status == 'completed' %}
    <div class="section">
        <h2>🔧 Resultados de Nikto - Evidencias Reales</h2>
        
        <div class="tool-info">
            <p><strong>Estado:</strong> ✅ Completado exitosamente</p>
            <p><strong>Problemas encontrados:</strong> {{ nikto_results.statistics.total_vulnerabilities }}</p>
            <p><strong>Categorías analizadas:</strong> {{ nikto_results.statistics.by_category | length }}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-item high">
                <h4>🔴 Severidad Alta</h4>
                <p>{{ nikto_results.statistics.by_severity.High }}</p>
            </div>
            <div class="stat-item medium">
                <h4>🟡 Severidad Media</h4>
                <p>{{ nikto_results.statistics.by_severity.Medium }}</p>
            </div>
            <div class="stat-item low">
                <h4>🟢 Severidad Baja</h4>
                <p>{{ nikto_results.statistics.by_severity.Low }}</p>
            </div>
        </div>
        
        {% if nikto_results.vulnerabilities %}
        <h3>🔍 Hallazgos de Nikto</h3>
        {% for vuln in nikto_results.vulnerabilities %}
        <div class="nikto-finding severity-{{ vuln.severity.lower() }}">
            <div class="finding-header">
                <h4>{{ vuln.category|upper }} - {{ vuln.severity }}</h4>
                {% if vuln.id %}
                <span class="osvdb-badge">ID: {{ vuln.id }}</span>
                {% endif %}
            </div>
            <div class="finding-details">
                <p><strong>📝 Descripción:</strong> {{ vuln.msg }}</p>
                <p><strong>🌐 URL:</strong> {{ vuln.url }}</p>
                <p><strong>🔧 Método:</strong> {{ vuln.method }}</p>
                {% if vuln.osvdb %}
                <p><strong>📚 OSVDB:</strong> {{ vuln.osvdb }}</p>
                {% endif %}
            </div>
        </div>
        {% endfor %}
        {% else %}
        <div class="no-vulns">
            <p>✅ Nikto no encontró problemas en este análisis.</p>
        </div>
        {% endif %}
    </div>
    {% endif %}

    <!-- Live Analysis Results -->
    {% if live_analysis %}
    <div class="section">
        <h2>⚡ Resultados del Análisis en Vivo</h2>
        
        <div class="live-stats">
            <p><strong>Estado:</strong> {{ live_analysis.status }}</p>
            <p><strong>Progreso:</strong> {{ live_analysis.progress }}%</p>
            <p><strong>Vulnerabilidades encontradas:</strong> {{ live_analysis.vulnerabilities_found }}</p>
            <p><strong>Problemas críticos:</strong> {{ live_analysis.critical_issues }}</p>
        </div>
        
        {% if live_analysis.recommendations %}
        <h3>💡 Recomendaciones del Análisis en Vivo</h3>
        <ul class="recommendations-list">
            {% for rec in live_analysis.recommendations %}
            <li>{{ rec }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>
    {% endif %}

    <!-- Error Sections -->
    {% if wapiti_results and wapiti_results.status == 'error' %}
    <div class="section error-section">
        <h2>❌ Error en Wapiti</h2>
        <p class="error">{{ wapiti_results.error }}</p>
    </div>
    {% endif %}

    {% if nikto_results and nikto_results.status == 'error' %}
    <div class="section error-section">
        <h2>❌ Error en Nikto</h2>
        <p class="error">{{ nikto_results.error }}</p>
    </div>
    {% endif %}

    <!-- Recommendations -->
    <div class="section">
        <h2>💡 Recomendaciones de Seguridad</h2>
        <div class="recommendations">
            {% if summary.critical_issues > 0 %}
            <div class="urgent-recommendations">
                <h3>🚨 Acciones Urgentes</h3>
                <ul>
                    <li>Corregir inmediatamente las {{ summary.critical_issues }} vulnerabilidades críticas identificadas</li>
                    <li>Implementar monitoreo continuo de seguridad</li>
                    <li>Realizar pruebas de penetración adicionales</li>
                </ul>
            </div>
            {% endif %}
            
            <div class="general-recommendations">
                <h3>🔧 Recomendaciones Generales</h3>
                <ul>
                    <li>🔐 Implementar autenticación multifactor en todas las cuentas administrativas</li>
                    <li>🛡️ Configurar Web Application Firewall (WAF) para filtrar tráfico malicioso</li>
                    <li>🔄 Mantener todas las librerías y frameworks actualizados</li>
                    <li>📊 Implementar logging y monitoreo de seguridad detallado</li>
                    <li>🔒 Revisar y configurar headers de seguridad HTTP</li>
                    <li>🧪 Realizar auditorías de seguridad periódicas</li>
                    <li>👥 Capacitar al equipo de desarrollo en buenas prácticas de seguridad</li>
                </ul>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        <div class="disclaimer">
            <h3>⚠️ Disclaimer</h3>
            <p>Este reporte contiene evidencias reales obtenidas mediante herramientas de análisis de seguridad. 
               Los resultados deben ser verificados y las vulnerabilidades corregidas por personal técnico calificado.</p>
        </div>
        <div class="contact">
            <p><strong>Reporte generado por:</strong> Vigilant WebGuard - Plataforma de Auditoría de Seguridad</p>
            <p><strong>Herramientas utilizadas:</strong> Wapiti3, Nikto, APIs de Seguridad</p>
            <p><strong>Fecha:</strong> {{ generated_at }}</p>
        </div>
    </div>
</body>
</html>
        '''
    
    def _get_enhanced_css_styles(self) -> str:
        """Estilos CSS mejorados para el PDF"""
        return '''
        @page {
            size: A4;
            margin: 15mm;
        }
        
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            color: #333;
            font-size: 11px;
        }
        
        .header {
            border-bottom: 4px solid #2563eb;
            padding-bottom: 20px;
            margin-bottom: 30px;
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            padding: 20px;
            border-radius: 8px;
        }
        
        .header h1 {
            color: #2563eb;
            font-size: 26px;
            margin: 0;
            text-align: center;
        }
        
        .header h2 {
            color: #64748b;
            font-size: 16px;
            margin: 5px 0;
            font-weight: normal;
            text-align: center;
        }
        
        .report-info {
            background: #ffffff;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            border-left: 4px solid #3b82f6;
        }
        
        .section {
            margin-bottom: 35px;
            page-break-inside: avoid;
        }
        
        .section h2 {
            color: #1e40af;
            border-bottom: 3px solid #e2e8f0;
            padding-bottom: 10px;
            font-size: 20px;
            margin-bottom: 20px;
        }
        
        .tool-info {
            background: #f0f9ff;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #0ea5e9;
            margin-bottom: 20px;
        }
        
        .summary-grid, .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        
        .summary-item, .stat-item {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            border: 2px solid #e2e8f0;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .summary-item h3, .stat-item h4 {
            margin: 0 0 10px 0;
            font-size: 13px;
            color: #64748b;
            font-weight: bold;
        }
        
        .number, .risk-level {
            font-size: 28px;
            font-weight: bold;
            margin: 0;
        }
        
        .risk-critical { color: #dc2626; border-color: #dc2626; background: #fef2f2; }
        .risk-high { color: #ea580c; border-color: #ea580c; background: #fff7ed; }
        .risk-medium { color: #d97706; border-color: #d97706; background: #fffbeb; }
        .risk-low { color: #16a34a; border-color: #16a34a; background: #f0fdf4; }
        .risk-minimal { color: #059669; border-color: #059669; background: #ecfdf5; }
        
        .critical { color: #dc2626; }
        .high { color: #ea580c; border-color: #ea580c; }
        .medium { color: #d97706; border-color: #d97706; }
        .low { color: #16a34a; border-color: #16a34a; }
        
        .vulnerability-item {
            background: #fff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            border-left: 5px solid #3b82f6;
        }
        
        .vulnerability-item.level-3 {
            border-left-color: #dc2626;
            background: #fef2f2;
        }
        
        .vulnerability-item.level-2 {
            border-left-color: #ea580c;
            background: #fff7ed;
        }
        
        .vulnerability-item.level-1 {
            border-left-color: #16a34a;
            background: #f0fdf4;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .vuln-header h4 {
            margin: 0;
            color: #1e40af;
            font-size: 14px;
        }
        
        .level-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            color: white;
        }
        
        .level-badge.level-3 { background: #dc2626; }
        .level-badge.level-2 { background: #ea580c; }
        .level-badge.level-1 { background: #16a34a; }
        
        .nikto-finding {
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 12px;
            margin: 12px 0;
        }
        
        .nikto-finding.severity-high {
            border-left: 5px solid #dc2626;
            background: #fef2f2;
        }
        
        .nikto-finding.severity-medium {
            border-left: 5px solid #ea580c;
            background: #fff7ed;
        }
        
        .nikto-finding.severity-low {
            border-left: 5px solid #16a34a;
            background: #f0fdf4;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .finding-header h4 {
            margin: 0;
            color: #1e40af;
            font-size: 13px;
        }
        
        .osvdb-badge {
            background: #64748b;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 9px;
        }
        
        .no-vulns {
            background: #f0fdf4;
            border: 2px solid #16a34a;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
            color: #16a34a;
            font-weight: bold;
        }
        
        .error-section {
            background: #fef2f2;
            border: 2px solid #dc2626;
            border-radius: 8px;
            padding: 20px;
        }
        
        .error {
            color: #dc2626;
            font-weight: bold;
        }
        
        .recommendations {
            background: #f0f9ff;
            padding: 20px;
            border-radius: 8px;
            border: 2px solid #0ea5e9;
        }
        
        .urgent-recommendations {
            background: #fef2f2;
            border: 2px solid #dc2626;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .urgent-recommendations h3 {
            color: #dc2626;
            margin-top: 0;
        }
        
        .general-recommendations h3 {
            color: #0ea5e9;
            margin-top: 0;
        }
        
        .recommendations ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        
        .recommendations li {
            margin: 8px 0;
            line-height: 1.5;
        }
        
        .footer {
            border-top: 3px solid #e2e8f0;
            padding-top: 20px;
            margin-top: 40px;
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
        }
        
        .disclaimer {
            background: #fffbeb;
            border: 2px solid #d97706;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .disclaimer h3 {
            color: #d97706;
            margin-top: 0;
            font-size: 14px;
        }
        
        .contact {
            text-align: center;
            color: #64748b;
            font-size: 10px;
        }
        
        .live-stats {
            background: #f0fdf4;
            border: 2px solid #16a34a;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
        }
        '''

# Instancia global
real_evidence_pdf_generator = RealEvidencePDFGenerator()
