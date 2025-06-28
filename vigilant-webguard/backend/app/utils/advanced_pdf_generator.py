import json
import os
from datetime import datetime
from pathlib import Path
from jinja2 import Template
from weasyprint import HTML, CSS
from typing import Dict
from loguru import logger

class AdvancedPDFGenerator:
    """Generador avanzado de PDF para reportes de pentesting"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        self.output_dir = Path("results/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_pentest_pdf(self, report_data: Dict) -> str:
        """Generar PDF completo del reporte de pentesting"""
        try:
            # Crear HTML desde template
            html_content = self._create_html_report(report_data)
            
            # Generar PDF
            pdf_filename = f"pentest_report_{report_data.get('session_id', 'unknown')}.pdf"
            pdf_path = self.output_dir / pdf_filename
            
            # Convertir HTML a PDF
            HTML(string=html_content).write_pdf(
                pdf_path,
                stylesheets=[CSS(string=self._get_css_styles())]
            )
            
            logger.info(f"PDF generado exitosamente: {pdf_path}")
            return str(pdf_path)
            
        except Exception as e:
            logger.error(f"Error generando PDF: {e}")
            raise e
    
    def _create_html_report(self, report_data: Dict) -> str:
        """Crear contenido HTML del reporte"""
        template = Template(self._get_html_template())
        
        # Preparar datos para el template
        context = {
            'report': report_data,
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target_url': report_data.get('target_url', 'N/A'),
            'session_id': report_data.get('session_id', 'N/A'),
            'executive_summary': report_data.get('executive_summary', {}),
            'scan_tools': report_data.get('scan_tools', {}),
            'security_apis': report_data.get('security_apis', {}),
            'recommendations': report_data.get('recommendations', [])
        }
        
        return template.render(**context)
    
    def _get_html_template(self) -> str:
        """Template HTML para el reporte de pentesting"""
        return '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Pentesting - Vigilant WebGuard</title>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="logo">
            <h1>🛡️ Vigilant WebGuard</h1>
            <h2>Reporte de Pentesting y Auditoría de Seguridad</h2>
        </div>
        <div class="report-info">
            <p><strong>URL Objetivo:</strong> {{ target_url }}</p>
            <p><strong>ID de Sesión:</strong> {{ session_id }}</p>
            <p><strong>Fecha de Generación:</strong> {{ generated_date }}</p>
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <h2>📊 Resumen Ejecutivo</h2>
        <div class="summary-grid">
            <div class="summary-item critical">
                <h3>Nivel de Riesgo</h3>
                <p class="risk-{{ executive_summary.overall_risk_level|lower }}">{{ executive_summary.overall_risk_level }}</p>
            </div>
            <div class="summary-item">
                <h3>Vulnerabilidades Totales</h3>
                <p class="number">{{ executive_summary.total_vulnerabilities_found }}</p>
            </div>
            <div class="summary-item">
                <h3>Problemas Críticos</h3>
                <p class="number critical">{{ executive_summary.critical_issues }}</p>
            </div>
            <div class="summary-item">
                <h3>Puntuación de Riesgo</h3>
                <p class="number">{{ executive_summary.risk_score }}/100</p>
            </div>
        </div>
        
        <h3>🔍 Herramientas Utilizadas</h3>
        <ul class="tools-list">
            {% for tool in executive_summary.tools_used %}
            <li>{{ tool }}</li>
            {% endfor %}
        </ul>
        
        <h3>🎯 Hallazgos Clave</h3>
        <ul class="findings-list">
            {% for finding in executive_summary.key_findings %}
            <li>{{ finding }}</li>
            {% endfor %}
        </ul>
    </div>

    <!-- Wapiti Results -->
    {% if scan_tools.wapiti %}
    <div class="section">
        <h2>🔍 Resultados de Wapiti</h2>
        {% if scan_tools.wapiti.status == 'completed' %}
            <div class="stats-grid">
                <div class="stat-item">
                    <h4>Total Vulnerabilidades</h4>
                    <p>{{ scan_tools.wapiti.statistics.total_vulnerabilities }}</p>
                </div>
                <div class="stat-item high">
                    <h4>Severidad Alta</h4>
                    <p>{{ scan_tools.wapiti.statistics.severity_breakdown.high }}</p>
                </div>
                <div class="stat-item medium">
                    <h4>Severidad Media</h4>
                    <p>{{ scan_tools.wapiti.statistics.severity_breakdown.medium }}</p>
                </div>
                <div class="stat-item low">
                    <h4>Severidad Baja</h4>
                    <p>{{ scan_tools.wapiti.statistics.severity_breakdown.low }}</p>
                </div>
            </div>
            
            <h3>Vulnerabilidades Detectadas</h3>
            {% for category, vulns in scan_tools.wapiti.vulnerabilities.items() %}
                {% if vulns|length > 0 %}
                <div class="vulnerability-category">
                    <h4>{{ category }} ({{ vulns|length }})</h4>
                    {% for vuln in vulns %}
                    <div class="vulnerability-item">
                        <p><strong>Info:</strong> {{ vuln.info }}</p>
                        <p><strong>Módulo:</strong> {{ vuln.module }}</p>
                        <p><strong>Método:</strong> {{ vuln.method }} - <strong>Ruta:</strong> {{ vuln.path }}</p>
                        <p><strong>Nivel:</strong> 
                            <span class="level-{{ vuln.level }}">
                                {% if vuln.level == 3 %}Alto{% elif vuln.level == 2 %}Medio{% else %}Bajo{% endif %}
                            </span>
                        </p>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            {% endfor %}
        {% else %}
            <p class="error">Error en escaneo Wapiti: {{ scan_tools.wapiti.error }}</p>
        {% endif %}
    </div>
    {% endif %}

    <!-- Nikto Results -->
    {% if scan_tools.nikto %}
    <div class="section">
        <h2>🔧 Resultados de Nikto</h2>
        {% if scan_tools.nikto.status == 'completed' %}
            <div class="stats-grid">
                <div class="stat-item">
                    <h4>Total Hallazgos</h4>
                    <p>{{ scan_tools.nikto.statistics.total_findings }}</p>
                </div>
                <div class="stat-item high">
                    <h4>Severidad Alta</h4>
                    <p>{{ scan_tools.nikto.statistics.severity_breakdown.high }}</p>
                </div>
                <div class="stat-item medium">
                    <h4>Severidad Media</h4>
                    <p>{{ scan_tools.nikto.statistics.severity_breakdown.medium }}</p>
                </div>
                <div class="stat-item low">
                    <h4>Severidad Baja</h4>
                    <p>{{ scan_tools.nikto.statistics.severity_breakdown.low }}</p>
                </div>
            </div>
            
            <h3>Hallazgos de Nikto</h3>
            {% for finding in scan_tools.nikto.findings %}
            <div class="nikto-finding">
                <p><strong>Ruta:</strong> {{ finding.path }}</p>
                <p><strong>Descripción:</strong> {{ finding.description }}</p>
            </div>
            {% endfor %}
        {% else %}
            <p class="error">Error en escaneo Nikto: {{ scan_tools.nikto.error }}</p>
        {% endif %}
    </div>
    {% endif %}

    <!-- Security APIs Results -->
    <div class="section">
        <h2>🌐 Análisis de APIs de Seguridad</h2>
        
        <!-- VirusTotal -->
        {% if security_apis.virustotal_url %}
        <div class="subsection">
            <h3>🦠 VirusTotal - Análisis de URL</h3>
            {% if not security_apis.virustotal_url.error %}
                <div class="virustotal-result">
                    <p><strong>Detecciones:</strong> {{ security_apis.virustotal_url.positives }}/{{ security_apis.virustotal_url.total }}</p>
                    <p><strong>Fecha de Escaneo:</strong> {{ security_apis.virustotal_url.scan_date }}</p>
                    {% if security_apis.virustotal_url.permalink %}
                    <p><strong>Enlace Permanente:</strong> <a href="{{ security_apis.virustotal_url.permalink }}">Ver en VirusTotal</a></p>
                    {% endif %}
                </div>
            {% else %}
                <p class="error">{{ security_apis.virustotal_url.error }}</p>
            {% endif %}
        </div>
        {% endif %}
        
        <!-- Shodan -->
        {% if security_apis.shodan_analysis %}
        <div class="subsection">
            <h3>🔍 Shodan - Análisis de Host</h3>
            {% if not security_apis.shodan_analysis.error %}
                <div class="shodan-result">
                    <p><strong>IP:</strong> {{ security_apis.shodan_analysis.ip }}</p>
                    <p><strong>País:</strong> {{ security_apis.shodan_analysis.country }}</p>
                    <p><strong>Organización:</strong> {{ security_apis.shodan_analysis.org }}</p>
                    <p><strong>Puertos Abiertos:</strong> {{ security_apis.shodan_analysis.ports|join(', ') }}</p>
                    {% if security_apis.shodan_analysis.vulns %}
                    <p><strong>Vulnerabilidades:</strong> {{ security_apis.shodan_analysis.vulns|length }} encontradas</p>
                    {% endif %}
                </div>
            {% else %}
                <p class="error">{{ security_apis.shodan_analysis.error }}</p>
            {% endif %}
        </div>
        {% endif %}
        
        <!-- SSL Certificate -->
        {% if security_apis.ssl_certificate %}
        <div class="subsection">
            <h3>🔒 Certificado SSL</h3>
            {% if not security_apis.ssl_certificate.error %}
                <div class="ssl-result">
                    <p><strong>Emisor:</strong> {{ security_apis.ssl_certificate.issuer.organizationName }}</p>
                    <p><strong>Válido hasta:</strong> {{ security_apis.ssl_certificate.not_after }}</p>
                    <p><strong>Estado:</strong> 
                        {% if security_apis.ssl_certificate.is_expired %}
                            <span class="expired">Expirado</span>
                        {% else %}
                            <span class="valid">Válido</span>
                        {% endif %}
                    </p>
                </div>
            {% else %}
                <p class="error">{{ security_apis.ssl_certificate.error }}</p>
            {% endif %}
        </div>
        {% endif %}
    </div>

    <!-- Recommendations -->
    <div class="section">
        <h2>💡 Recomendaciones de Seguridad</h2>
        <ol class="recommendations-list">
            {% for recommendation in recommendations %}
            <li>{{ recommendation }}</li>
            {% endfor %}
        </ol>
    </div>

    <!-- Footer -->
    <div class="footer">
        <p>Reporte generado por Vigilant WebGuard - Plataforma de Auditoría y Pentesting</p>
        <p>Para más información, contacte al equipo de seguridad.</p>
    </div>
</body>
</html>
        '''
    
    def _get_css_styles(self) -> str:
        """Estilos CSS para el PDF"""
        return '''
        @page {
            size: A4;
            margin: 20mm;
        }
        
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            color: #333;
            font-size: 12px;
        }
        
        .header {
            border-bottom: 3px solid #2563eb;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #2563eb;
            font-size: 24px;
            margin: 0;
        }
        
        .header h2 {
            color: #64748b;
            font-size: 16px;
            margin: 5px 0;
            font-weight: normal;
        }
        
        .report-info {
            background: #f1f5f9;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        
        .section {
            margin-bottom: 30px;
            page-break-inside: avoid;
        }
        
        .section h2 {
            color: #1e40af;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
            font-size: 18px;
        }
        
        .subsection {
            margin: 20px 0;
            padding: 15px;
            background: #f8fafc;
            border-left: 4px solid #3b82f6;
        }
        
        .summary-grid, .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        
        .summary-item, .stat-item {
            background: #fff;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #e2e8f0;
            text-align: center;
        }
        
        .summary-item h3, .stat-item h4 {
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #64748b;
        }
        
        .number {
            font-size: 24px;
            font-weight: bold;
            margin: 0;
        }
        
        .risk-critical { color: #dc2626; }
        .risk-high { color: #ea580c; }
        .risk-medium { color: #d97706; }
        .risk-low { color: #16a34a; }
        .risk-minimal { color: #059669; }
        
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
        .medium { color: #d97706; }
        .low { color: #16a34a; }
        
        .tools-list, .findings-list {
            background: #f8fafc;
            padding: 15px;
            border-radius: 5px;
        }
        
        .vulnerability-category {
            margin: 20px 0;
            border: 1px solid #e2e8f0;
            border-radius: 5px;
            padding: 15px;
        }
        
        .vulnerability-category h4 {
            color: #1e40af;
            margin-top: 0;
        }
        
        .vulnerability-item {
            background: #f8fafc;
            padding: 10px;
            margin: 10px 0;
            border-left: 3px solid #3b82f6;
        }
        
        .level-3 { color: #dc2626; font-weight: bold; }
        .level-2 { color: #ea580c; font-weight: bold; }
        .level-1 { color: #16a34a; font-weight: bold; }
        
        .nikto-finding {
            background: #f1f5f9;
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
        }
        
        .error {
            color: #dc2626;
            background: #fef2f2;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #fecaca;
        }
        
        .valid { color: #16a34a; }
        .expired { color: #dc2626; }
        
        .recommendations-list {
            background: #f0f9ff;
            padding: 20px;
            border-radius: 5px;
        }
        
        .recommendations-list li {
            margin: 10px 0;
        }
        
        .footer {
            border-top: 2px solid #e2e8f0;
            padding-top: 20px;
            margin-top: 40px;
            text-align: center;
            color: #64748b;
            font-size: 10px;
        }
        '''

# Instancia global
advanced_pdf_generator = AdvancedPDFGenerator()

