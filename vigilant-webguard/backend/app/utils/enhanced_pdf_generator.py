"""
"""Generador de PDF simplificado para reportes de seguridad
Versión sin conflictos de estilos
"""
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import tempfile
import os
from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.colors import HexColor, black, red, orange, green, blue
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.frames import Frame
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from loguru import logger


class EnhancedPDFGenerator:
    """Generador de PDF mejorado para reportes de seguridad"""
    
    def __init__(self):
        self.output_dir = Path("results/pdf_reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurar estilos
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # Colores para severidad
        self.severity_colors = {
            'critical': HexColor('#DC2626'),  # Rojo
            'high': HexColor('#EA580C'),      # Naranja oscuro
            'medium': HexColor('#D97706'),    # Naranja
            'low': HexColor('#65A30D'),       # Verde
            'info': HexColor('#2563EB')       # Azul
        }
    
    def _setup_custom_styles(self):
        """Configurar estilos personalizados"""
        # Verificar y agregar estilos solo si no existen
        custom_styles = {
            'MainTitle': ParagraphStyle(
                name='MainTitle',
                parent=self.styles['Title'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=HexColor('#1F2937'),
                fontName='Helvetica-Bold'
            ),
            'SectionTitle': ParagraphStyle(
                name='SectionTitle',
                parent=self.styles['Heading1'],
                fontSize=16,
                spaceBefore=20,
                spaceAfter=10,
                textColor=HexColor('#374151'),
                fontName='Helvetica-Bold'
            ),
            'SubSectionTitle': ParagraphStyle(
                name='SubSectionTitle',
                parent=self.styles['Heading2'],
                fontSize=14,
                spaceBefore=15,
                spaceAfter=8,
                textColor=HexColor('#4B5563'),
                fontName='Helvetica-Bold'
            ),
            'CustomBodyText': ParagraphStyle(
                name='CustomBodyText',
                parent=self.styles['Normal'],
                fontSize=10,
                spaceBefore=3,
                spaceAfter=6,
                alignment=TA_JUSTIFY,
                fontName='Helvetica'
            ),
            'CriticalText': ParagraphStyle(
                name='CriticalText',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=HexColor('#DC2626'),
                fontName='Helvetica-Bold'
            ),
            'RecommendationText': ParagraphStyle(
                name='RecommendationText',
                parent=self.styles['Normal'],
                fontSize=10,
                spaceBefore=3,
                spaceAfter=3,
                leftIndent=20,
                fontName='Helvetica'
            ),
            'CodeText': ParagraphStyle(
                name='CodeText',
                parent=self.styles['Normal'],
                fontSize=9,
                fontName='Courier',
                backColor=HexColor('#F3F4F6'),
                leftIndent=10,
                rightIndent=10,
                spaceBefore=3,
                spaceAfter=3
            )
        }
        
        # Agregar estilos solo si no existen
        for style_name, style in custom_styles.items():
            if style_name not in self.styles:
                self.styles.add(style)
    
    def generate_comprehensive_report(self, scan_data: Dict[str, Any]) -> str:
        """
        Generar reporte PDF comprehensivo
        
        Args:
            scan_data: Datos del escaneo de seguridad
            
        Returns:
            str: Ruta del archivo PDF generado
        """
        try:
            # Generar nombre único para el PDF
            report_id = str(uuid.uuid4())[:8]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}_{report_id}.pdf"
            output_path = self.output_dir / filename
            
            # Crear documento PDF
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            # Construir contenido del reporte
            story = []
            
            # Página de título
            story.extend(self._build_title_page(scan_data))
            story.append(PageBreak())
            
            # Resumen ejecutivo
            story.extend(self._build_executive_summary(scan_data))
            story.append(PageBreak())
            
            # Metodología
            story.extend(self._build_methodology_section(scan_data))
            
            # Hallazgos de seguridad
            story.extend(self._build_security_findings(scan_data))
            
            # Análisis de vulnerabilidades
            story.extend(self._build_vulnerability_analysis(scan_data))
            
            # Recomendaciones
            story.extend(self._build_recommendations(scan_data))
            story.append(PageBreak())
            
            # Apéndices técnicos
            story.extend(self._build_technical_appendix(scan_data))
            
            # Generar PDF
            doc.build(story)
            
            logger.info(f"Reporte PDF generado exitosamente: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generando reporte PDF: {e}")
            raise
    
    def _build_title_page(self, scan_data: Dict) -> list:
        """Construir página de título"""
        story = []
        
        # Título principal
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("REPORTE DE ANÁLISIS DE SEGURIDAD", self.styles['MainTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Información del objetivo
        target_url = scan_data.get('target_url', 'N/A')
        story.append(Paragraph(f"<b>Objetivo:</b> {target_url}", self.styles['SectionTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Información del escaneo
        scan_date = scan_data.get('scan_date', datetime.now().isoformat())
        if 'T' in scan_date:
            scan_date = scan_date.split('T')[0]
        
        info_data = [
            ['Fecha del Análisis', scan_date],
            ['ID del Escaneo', scan_data.get('scan_id', 'N/A')],
            ['Estado', scan_data.get('status', 'N/A').title()],
            ['Herramientas Utilizadas', ', '.join(scan_data.get('selected_tools', []))]
        ]
        
        info_table = Table(info_data, colWidths=[2.5*inch, 3*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#F3F4F6')),
            ('TEXTCOLOR', (0, 0), (0, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 1*inch))
        
        # Resumen de hallazgos
        stats = scan_data.get('statistics', {})
        summary_data = [
            ['Vulnerabilidades Totales', str(stats.get('total_vulnerabilities', 0))],
            ['Problemas Críticos', str(stats.get('critical_issues', 0))],
            ['Credenciales Expuestas', str(stats.get('credentials_found', 0))],
            ['Directorios Descubiertos', str(stats.get('directories_discovered', 0))],
            ['Archivos Sensibles', str(stats.get('files_discovered', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#EFF6FF')),
            ('BACKGROUND', (1, 0), (1, -1), HexColor('#DBEAFE')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        story.append(Paragraph("Resumen de Hallazgos", self.styles['SectionTitle']))
        story.append(summary_table)
        
        # Pie de página
        story.append(Spacer(1, 1*inch))
        story.append(Paragraph(
            "Generado por Vigilant WebGuard - Plataforma de Análisis de Seguridad",
            self.styles['CustomBodyText']
        ))
        
        return story
    
    def _build_executive_summary(self, scan_data: Dict) -> list:
        """Construir resumen ejecutivo"""
        story = []
        
        story.append(Paragraph("RESUMEN EJECUTIVO", self.styles['MainTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Descripción del análisis
        story.append(Paragraph("Descripción del Análisis", self.styles['SectionTitle']))
        story.append(Paragraph(
            f"Se realizó un análisis comprehensivo de seguridad web del objetivo "
            f"{scan_data.get('target_url', 'N/A')} utilizando múltiples herramientas especializadas "
            f"y técnicas de análisis profundo. El escaneo se ejecutó el "
            f"{scan_data.get('scan_date', 'fecha no disponible').split('T')[0]} con el objetivo de "
            "identificar vulnerabilidades de seguridad, exposición de datos sensibles y "
            "configuraciones incorrectas.",
            self.styles['CustomBodyText']
        ))
        story.append(Spacer(1, 0.2*inch))
        
        # Hallazgos principales
        story.append(Paragraph("Hallazgos Principales", self.styles['SectionTitle']))
        
        stats = scan_data.get('statistics', {})
        total_vulns = stats.get('total_vulnerabilities', 0)
        critical_issues = stats.get('critical_issues', 0)
        credentials_found = stats.get('credentials_found', 0)
        
        # Determinar nivel de riesgo general
        if critical_issues > 0 or credentials_found > 0:
            risk_level = "ALTO"
            risk_color = 'CriticalText'
        elif total_vulns > 5:
            risk_level = "MEDIO"
            risk_color = 'CustomBodyText'
        else:
            risk_level = "BAJO"
            risk_color = 'CustomBodyText'
        
        story.append(Paragraph(
            f"<b>Nivel de Riesgo General:</b> <font color='red'>{risk_level}</font>",
            self.styles[risk_color]
        ))
        story.append(Spacer(1, 0.1*inch))
        
        findings_summary = []
        if total_vulns > 0:
            findings_summary.append(f"• Se identificaron {total_vulns} vulnerabilidades de seguridad")
        if critical_issues > 0:
            findings_summary.append(f"• {critical_issues} problemas clasificados como críticos requieren atención inmediata")
        if credentials_found > 0:
            findings_summary.append(f"• Se encontraron {credentials_found} credenciales expuestas")
        if stats.get('directories_discovered', 0) > 0:
            findings_summary.append(f"• {stats.get('directories_discovered', 0)} directorios accesibles descubiertos")
        
        if not findings_summary:
            findings_summary.append("• No se identificaron vulnerabilidades críticas en el análisis inicial")
        
        for finding in findings_summary:
            story.append(Paragraph(finding, self.styles['CustomBodyText']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Recomendaciones principales
        story.append(Paragraph("Recomendaciones Prioritarias", self.styles['SectionTitle']))
        
        recommendations = scan_data.get('recommendations', [])[:5]  # Top 5
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                # Limpiar emojis para PDF
                clean_rec = rec.replace('🚨', '').replace('🔒', '').replace('🛡️', '').replace('⚠️', '').replace('🔐', '').strip()
                story.append(Paragraph(f"{i}. {clean_rec}", self.styles['RecommendationText']))
        else:
            story.append(Paragraph("• Mantener las buenas prácticas de seguridad actuales", self.styles['RecommendationText']))
            story.append(Paragraph("• Realizar escaneos periódicos de seguridad", self.styles['RecommendationText']))
        
        return story
    
    def _build_methodology_section(self, scan_data: Dict) -> list:
        """Construir sección de metodología"""
        story = []
        
        story.append(Paragraph("METODOLOGÍA", self.styles['SectionTitle']))
        story.append(Spacer(1, 0.1*inch))
        
        # Herramientas utilizadas
        story.append(Paragraph("Herramientas y Técnicas Utilizadas", self.styles['SubSectionTitle']))
        
        selected_tools = scan_data.get('selected_tools', [])
        tool_descriptions = {
            'wapiti3': 'Wapiti3: Escáner de vulnerabilidades web que detecta XSS, inyecciones SQL, inclusión de archivos y otras vulnerabilidades comunes.',
            'nikto': 'Nikto: Escáner de servidores web que identifica configuraciones peligrosas, archivos y programas obsoletos.',
            'custom': 'Análisis Personalizado: Técnicas propias de reconocimiento, fuerza bruta de directorios y búsqueda de credenciales.'
        }
        
        for tool in selected_tools:
            if tool in tool_descriptions:
                story.append(Paragraph(f"• {tool_descriptions[tool]}", self.styles['CustomBodyText']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Fases del análisis
        story.append(Paragraph("Fases del Análisis", self.styles['SubSectionTitle']))
        
        phases = [
            "1. <b>Reconocimiento:</b> Recopilación de información sobre el objetivo (DNS, SSL, tecnologías)",
            "2. <b>Escaneo de Vulnerabilidades:</b> Análisis automatizado con herramientas especializadas",
            "3. <b>Análisis Personalizado:</b> Fuerza bruta de directorios, búsqueda de archivos sensibles",
            "4. <b>Búsqueda de Credenciales:</b> Detección de información sensible expuesta",
            "5. <b>Análisis de Resultados:</b> Consolidación y clasificación de hallazgos"
        ]
        
        for phase in phases:
            story.append(Paragraph(phase, self.styles['CustomBodyText']))
        
        story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _build_security_findings(self, scan_data: Dict) -> list:
        """Construir sección de hallazgos de seguridad"""
        story = []
        
        story.append(Paragraph("HALLAZGOS DE SEGURIDAD", self.styles['SectionTitle']))
        story.append(Spacer(1, 0.1*inch))
        
        # Vulnerabilidades por herramienta
        results = scan_data.get('results', {})
        tools_results = results.get('tools', {})
        
        for tool_name, tool_data in tools_results.items():
            if tool_name == 'wapiti3':
                story.extend(self._build_wapiti_findings(tool_data))
            elif tool_name == 'nikto':
                story.extend(self._build_nikto_findings(tool_data))
        
        # Credenciales expuestas
        cred_results = results.get('credentials', {})
        if cred_results.get('exposed_credentials'):
            story.extend(self._build_credential_findings(cred_results))
        
        # Archivos y directorios descubiertos
        custom_results = results.get('custom_analysis', {})
        if custom_results:
            story.extend(self._build_discovery_findings(custom_results))
        
        return story
    
    def _build_wapiti_findings(self, wapiti_data: Dict) -> list:
        """Construir hallazgos de Wapiti3"""
        story = []
        
        story.append(Paragraph("Vulnerabilidades Detectadas por Wapiti3", self.styles['SubSectionTitle']))
        
        vulnerabilities = wapiti_data.get('vulnerabilities', [])
        if not vulnerabilities:
            story.append(Paragraph("No se detectaron vulnerabilidades específicas.", self.styles['CustomBodyText']))
            story.append(Spacer(1, 0.1*inch))
            return story
        
        # Agrupar por categoría
        vuln_by_category = {}
        for vuln in vulnerabilities:
            category = vuln.get('category', 'Otros')
            if category not in vuln_by_category:
                vuln_by_category[category] = []
            vuln_by_category[category].append(vuln)
        
        for category, vulns in vuln_by_category.items():
            story.append(Paragraph(f"<b>{category}</b>", self.styles['BodyText']))
            
            for vuln in vulns:
                level = vuln.get('level', 1)
                severity = "Crítica" if level == 3 else "Media" if level == 2 else "Baja"
                
                vuln_text = f"• <b>{vuln.get('info', 'Sin descripción')}</b> (Severidad: {severity})"
                if vuln.get('path'):
                    vuln_text += f"<br/>   Ruta: {vuln.get('path')}"
                if vuln.get('parameter'):
                    vuln_text += f"<br/>   Parámetro: {vuln.get('parameter')}"
                
                story.append(Paragraph(vuln_text, self.styles['BodyText']))
            
            story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _build_nikto_findings(self, nikto_data: Dict) -> list:
        """Construir hallazgos de Nikto"""
        story = []
        
        story.append(Paragraph("Hallazgos de Configuración de Nikto", self.styles['SubSectionTitle']))
        
        findings = nikto_data.get('findings', [])
        if not findings:
            story.append(Paragraph("No se detectaron problemas de configuración específicos.", self.styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
            return story
        
        # Agrupar por severidad
        findings_by_severity = {'High': [], 'Medium': [], 'Low': []}
        for finding in findings:
            severity = finding.get('severity', 'Low')
            if severity in findings_by_severity:
                findings_by_severity[severity].append(finding)
        
        for severity in ['High', 'Medium', 'Low']:
            if findings_by_severity[severity]:
                severity_es = {"High": "Alta", "Medium": "Media", "Low": "Baja"}[severity]
                story.append(Paragraph(f"<b>Severidad {severity_es}:</b>", self.styles['BodyText']))
                
                for finding in findings_by_severity[severity]:
                    finding_text = finding.get('finding', 'Sin descripción')
                    # Limpiar texto para PDF
                    finding_text = finding_text.replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(f"• {finding_text}", self.styles['BodyText']))
                
                story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _build_credential_findings(self, cred_data: Dict) -> list:
        """Construir hallazgos de credenciales"""
        story = []
        
        story.append(Paragraph("Credenciales y Datos Sensibles Expuestos", self.styles['SubSectionTitle']))
        
        exposed_creds = cred_data.get('exposed_credentials', [])
        config_files = cred_data.get('configuration_files', [])
        
        if exposed_creds:
            story.append(Paragraph("<b>⚠️ CRÍTICO: Credenciales Expuestas</b>", self.styles['CriticalText']))
            
            for cred in exposed_creds:
                cred_text = f"• Tipo: {cred.get('type', 'N/A')} en archivo {cred.get('file', 'N/A')}"
                story.append(Paragraph(cred_text, self.styles['CriticalText']))
            
            story.append(Spacer(1, 0.1*inch))
        
        if config_files:
            story.append(Paragraph("<b>Archivos de Configuración Accesibles:</b>", self.styles['BodyText']))
            
            for config_file in config_files:
                file_text = f"• {config_file.get('file', 'N/A')}"
                story.append(Paragraph(file_text, self.styles['BodyText']))
            
            story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _build_discovery_findings(self, custom_data: Dict) -> list:
        """Construir hallazgos de descubrimiento"""
        story = []
        
        # Directorios descubiertos
        dir_data = custom_data.get('directory_brute_force', {})
        found_dirs = dir_data.get('found_directories', [])
        
        if found_dirs:
            story.append(Paragraph("Directorios Accesibles Descubiertos", self.styles['SubSectionTitle']))
            
            for directory in found_dirs[:10]:  # Mostrar solo los primeros 10
                dir_text = f"• {directory.get('directory', 'N/A')} (Código: {directory.get('status_code', 'N/A')})"
                story.append(Paragraph(dir_text, self.styles['BodyText']))
            
            if len(found_dirs) > 10:
                story.append(Paragraph(f"... y {len(found_dirs) - 10} directorios más.", self.styles['BodyText']))
            
            story.append(Spacer(1, 0.1*inch))
        
        # Archivos sensibles
        file_data = custom_data.get('file_discovery', {})
        found_files = file_data.get('found_files', [])
        
        if found_files:
            story.append(Paragraph("Archivos Sensibles Encontrados", self.styles['SubSectionTitle']))
            
            for file_info in found_files:
                file_text = f"• {file_info.get('file', 'N/A')} ({file_info.get('content_type', 'N/A')})"
                story.append(Paragraph(file_text, self.styles['BodyText']))
            
            story.append(Spacer(1, 0.1*inch))
        
        # Paneles de administración
        admin_data = custom_data.get('admin_panel_search', {})
        found_panels = admin_data.get('found_panels', [])
        
        if found_panels:
            story.append(Paragraph("Paneles de Administración Detectados", self.styles['SubSectionTitle']))
            
            for panel in found_panels:
                panel_text = f"• {panel.get('path', 'N/A')} - {panel.get('title', 'Sin título')}"
                story.append(Paragraph(panel_text, self.styles['BodyText']))
            
            story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _build_vulnerability_analysis(self, scan_data: Dict) -> list:
        """Construir análisis de vulnerabilidades"""
        story = []
        
        story.append(PageBreak())
        story.append(Paragraph("ANÁLISIS DE VULNERABILIDADES", self.styles['SectionTitle']))
        story.append(Spacer(1, 0.1*inch))
        
        # Análisis consolidado
        vuln_analysis = scan_data.get('results', {}).get('vulnerability_analysis', {})
        
        # Vulnerabilidades críticas
        critical_vulns = vuln_analysis.get('critical_vulnerabilities', [])
        if critical_vulns:
            story.append(Paragraph("Vulnerabilidades Críticas", self.styles['SubSectionTitle']))
            story.append(Paragraph(
                "Las siguientes vulnerabilidades requieren atención inmediata debido a su alto riesgo:",
                self.styles['BodyText']
            ))
            
            for vuln in critical_vulns:
                vuln_text = f"• {vuln.get('info', vuln.get('category', 'Vulnerabilidad crítica'))}"
                story.append(Paragraph(vuln_text, self.styles['CriticalText']))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Vulnerabilidades de severidad alta
        high_vulns = vuln_analysis.get('high_vulnerabilities', [])
        if high_vulns:
            story.append(Paragraph("Vulnerabilidades de Severidad Alta", self.styles['SubSectionTitle']))
            
            for vuln in high_vulns[:5]:  # Mostrar las primeras 5
                vuln_text = f"• {vuln.get('info', vuln.get('finding', 'Vulnerabilidad de alta severidad'))}"
                story.append(Paragraph(vuln_text, self.styles['BodyText']))
            
            if len(high_vulns) > 5:
                story.append(Paragraph(f"... y {len(high_vulns) - 5} vulnerabilidades más de severidad alta.", self.styles['BodyText']))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Resumen de impacto
        story.append(Paragraph("Resumen de Impacto", self.styles['SubSectionTitle']))
        
        stats = scan_data.get('statistics', {})
        impact_text = f"""
        El análisis reveló un total de {stats.get('total_vulnerabilities', 0)} vulnerabilidades, 
        de las cuales {stats.get('critical_issues', 0)} son clasificadas como críticas. 
        """
        
        if stats.get('credentials_found', 0) > 0:
            impact_text += f"Adicionalmente, se encontraron {stats.get('credentials_found', 0)} credenciales expuestas, lo que representa un riesgo de seguridad inmediato. "
        
        if stats.get('directories_discovered', 0) > 0:
            impact_text += f"Se descubrieron {stats.get('directories_discovered', 0)} directorios accesibles que podrían contener información sensible. "
        
        story.append(Paragraph(impact_text, self.styles['BodyText']))
        
        return story
    
    def _build_recommendations(self, scan_data: Dict) -> list:
        """Construir sección de recomendaciones"""
        story = []
        
        story.append(Paragraph("RECOMENDACIONES", self.styles['SectionTitle']))
        story.append(Spacer(1, 0.1*inch))
        
        story.append(Paragraph("Acciones Inmediatas", self.styles['SubSectionTitle']))
        
        # Recomendaciones prioritarias
        recommendations = scan_data.get('recommendations', [])
        stats = scan_data.get('statistics', {})
        
        # Recomendaciones basadas en hallazgos críticos
        immediate_actions = []
        
        if stats.get('credentials_found', 0) > 0:
            immediate_actions.append("Rotar inmediatamente todas las credenciales expuestas identificadas")
            immediate_actions.append("Mover archivos de configuración fuera del directorio web público")
        
        if stats.get('critical_issues', 0) > 0:
            immediate_actions.append("Corregir las vulnerabilidades críticas identificadas")
            immediate_actions.append("Implementar validación de entrada en formularios vulnerables")
        
        # Agregar recomendaciones del análisis
        for rec in recommendations[:5]:
            # Limpiar emojis
            clean_rec = rec.replace('🚨', '').replace('🔒', '').replace('🛡️', '').replace('⚠️', '').replace('🔐', '').strip()
            if clean_rec not in immediate_actions:
                immediate_actions.append(clean_rec)
        
        if not immediate_actions:
            immediate_actions.append("Continuar manteniendo las buenas prácticas de seguridad")
        
        for i, action in enumerate(immediate_actions[:8], 1):
            story.append(Paragraph(f"{i}. {action}", self.styles['RecommendationText']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Recomendaciones a largo plazo
        story.append(Paragraph("Mejoras a Largo Plazo", self.styles['SubSectionTitle']))
        
        long_term_recs = [
            "Implementar un programa de escaneos de seguridad regulares",
            "Establecer políticas de desarrollo seguro",
            "Configurar monitoreo de seguridad continuo",
            "Implementar un Web Application Firewall (WAF)",
            "Realizar capacitación en seguridad para el equipo de desarrollo",
            "Establecer un programa de divulgación responsable de vulnerabilidades"
        ]
        
        for i, rec in enumerate(long_term_recs, 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['RecommendationText']))
        
        return story
    
    def _build_technical_appendix(self, scan_data: Dict) -> list:
        """Construir apéndice técnico"""
        story = []
        
        story.append(Paragraph("APÉNDICE TÉCNICO", self.styles['SectionTitle']))
        story.append(Spacer(1, 0.1*inch))
        
        # Información de reconocimiento
        results = scan_data.get('results', {})
        recon_data = results.get('reconnaissance', {})
        
        if recon_data:
            story.append(Paragraph("Información de Reconocimiento", self.styles['SubSectionTitle']))
            
            # Información de dominio
            domain_info = recon_data.get('domain_info', {})
            if domain_info and not domain_info.get('error'):
                story.append(Paragraph("<b>Información del Dominio:</b>", self.styles['BodyText']))
                story.append(Paragraph(f"Registrador: {domain_info.get('registrar', 'N/A')}", self.styles['CodeText']))
                story.append(Paragraph(f"Fecha de creación: {domain_info.get('creation_date', 'N/A')}", self.styles['CodeText']))
            
            # Tecnologías detectadas
            tech_info = recon_data.get('technology_detection', {})
            if tech_info and not tech_info.get('error'):
                story.append(Paragraph("<b>Tecnologías Detectadas:</b>", self.styles['BodyText']))
                story.append(Paragraph(f"Servidor: {tech_info.get('server', 'N/A')}", self.styles['CodeText']))
                
                frameworks = tech_info.get('detected_frameworks', [])
                if frameworks:
                    story.append(Paragraph(f"Frameworks: {', '.join(frameworks)}", self.styles['CodeText']))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Estadísticas detalladas
        story.append(Paragraph("Estadísticas Detalladas", self.styles['SubSectionTitle']))
        
        stats = scan_data.get('statistics', {})
        stats_data = [
            ['Métrica', 'Valor'],
            ['Vulnerabilidades Totales', str(stats.get('total_vulnerabilities', 0))],
            ['Problemas Críticos', str(stats.get('critical_issues', 0))],
            ['Credenciales Expuestas', str(stats.get('credentials_found', 0))],
            ['Directorios Descubiertos', str(stats.get('directories_discovered', 0))],
            ['Archivos Sensibles', str(stats.get('files_discovered', 0))],
            ['Subdominios Encontrados', str(stats.get('subdomains_found', 0))],
            ['Puertos Abiertos', str(stats.get('open_ports', 0))]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#E5E7EB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Información del escaneo
        story.append(Paragraph("Detalles del Escaneo", self.styles['SubSectionTitle']))
        story.append(Paragraph(f"ID del Escaneo: {scan_data.get('scan_id', 'N/A')}", self.styles['CodeText']))
        story.append(Paragraph(f"Fecha: {scan_data.get('scan_date', 'N/A')}", self.styles['CodeText']))
        story.append(Paragraph(f"Herramientas: {', '.join(scan_data.get('selected_tools', []))}", self.styles['CodeText']))
        story.append(Paragraph(f"Estado: {scan_data.get('status', 'N/A')}", self.styles['CodeText']))
        
        return story


# Instancia global del generador
enhanced_pdf_generator = EnhancedPDFGenerator()
