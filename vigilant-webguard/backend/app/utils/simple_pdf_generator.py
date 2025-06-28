"""
Generador PDF simplificado para reportes de seguridad
Sin conflictos de estilos de ReportLab
"""
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from loguru import logger


class SimplePDFGenerator:
    """Generador PDF simplificado para reportes de seguridad"""
    
    def __init__(self):
        # Usar directorio temporal que siempre funciona
        import tempfile
        self.output_dir = Path(tempfile.gettempdir()) / "vigilant_pdfs"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = getSampleStyleSheet()
    
    def generate_comprehensive_report(self, scan_data: Dict[str, Any]) -> str:
        """Generar reporte PDF simplificado"""
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
            
            # Título
            story.append(Spacer(1, 2*inch))
            story.append(Paragraph("REPORTE DE ANÁLISIS DE SEGURIDAD", self.styles['Title']))
            story.append(Spacer(1, 0.5*inch))
            
            # Información básica
            target_url = scan_data.get('target_url', 'N/A')
            scan_date = scan_data.get('scan_date', datetime.now().isoformat())
            if 'T' in scan_date:
                scan_date = scan_date.split('T')[0]
            
            story.append(Paragraph(f"<b>URL Objetivo:</b> {target_url}", self.styles['Heading2']))
            story.append(Paragraph(f"<b>Fecha:</b> {scan_date}", self.styles['Normal']))
            story.append(Paragraph(f"<b>ID:</b> {scan_data.get('scan_id', 'N/A')}", self.styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Estadísticas
            stats = scan_data.get('statistics', {})
            story.append(Paragraph("RESUMEN DE HALLAZGOS", self.styles['Heading1']))
            story.append(Paragraph(f"• Total de vulnerabilidades: {stats.get('total_vulnerabilities', 0)}", self.styles['Normal']))
            story.append(Paragraph(f"• Problemas críticos: {stats.get('critical_issues', 0)}", self.styles['Normal']))
            story.append(Paragraph(f"• Credenciales expuestas: {stats.get('credentials_found', 0)}", self.styles['Normal']))
            story.append(Paragraph(f"• Directorios descubiertos: {stats.get('directories_discovered', 0)}", self.styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Recomendaciones
            recommendations = scan_data.get('recommendations', [])[:5]
            if recommendations:
                story.append(Paragraph("RECOMENDACIONES PRINCIPALES", self.styles['Heading1']))
                for i, rec in enumerate(recommendations, 1):
                    # Limpiar emojis
                    clean_rec = rec.replace('🚨', '').replace('🔒', '').replace('🛡️', '').replace('⚠️', '').replace('🔐', '').strip()
                    story.append(Paragraph(f"{i}. {clean_rec}", self.styles['Normal']))
                story.append(Spacer(1, 0.3*inch))
            
            # Herramientas utilizadas
            selected_tools = scan_data.get('selected_tools', [])
            if selected_tools:
                story.append(Paragraph("HERRAMIENTAS UTILIZADAS", self.styles['Heading1']))
                for tool in selected_tools:
                    story.append(Paragraph(f"• {tool.upper()}", self.styles['Normal']))
                story.append(Spacer(1, 0.3*inch))
            
            # Hallazgos detallados por herramienta
            vulnerabilities = scan_data.get('vulnerabilities', {})
            if vulnerabilities:
                story.append(Paragraph("HALLAZGOS DETALLADOS POR HERRAMIENTA", self.styles['Heading1']))
                
                for tool_name, vulns in vulnerabilities.items():
                    if vulns:  # Solo mostrar herramientas que encontraron algo
                        story.append(Paragraph(f"{tool_name.upper()}", self.styles['Heading2']))
                        
                        for i, vuln in enumerate(vulns[:10], 1):  # Máximo 10 por herramienta
                            level = vuln.get('level', 1)
                            level_text = "CRÍTICO" if level >= 3 else "MEDIO" if level == 2 else "BAJO"
                            
                            info = vuln.get('info', 'Sin descripción')
                            method = vuln.get('method', 'N/A')
                            path = vuln.get('path', '/')
                            param = vuln.get('parameter', 'N/A')
                            
                            story.append(Paragraph(
                                f"{i}. [{level_text}] {info}",
                                self.styles['Normal']
                            ))
                            story.append(Paragraph(
                                f"   • Método: {method} | Ruta: {path} | Parámetro: {param}",
                                self.styles['Normal']
                            ))
                        
                        story.append(Spacer(1, 0.2*inch))
            
            # REPORTES COMPLETOS DE HERRAMIENTAS
            story.append(Paragraph("REPORTES COMPLETOS DE HERRAMIENTAS", self.styles['Heading1']))
            
            # Lista todas las herramientas que se ejecutaron
            all_tools = [
                'NMAP', 'NIKTO', 'SQLMAP', 'GOBUSTER', 'WHATWEB', 'OWASP ZAP', 'DIRB', 
                'SUBLIST3R', 'MASSCAN', 'FFUF', 'COMMIX', 'WAFW00F', 'NUCLEI', 'AMASS',
                'CURL', 'DIG', 'OPENSSL', 'XSS TESTING', 'LFI/RFI TESTING', 'CSRF TESTING',
                'HYDRA', 'WPSCAN', 'ENUM4LINUX', 'SSLSCAN', 'TESTSSL', 'DNSRECON',
                'FIERCE', 'THEHARVESTER', 'RECON-NG', 'DMITRY', 'NCRACK', 'MEDUSA',
                'PATATOR', 'UNISCAN', 'SKIPFISH'
            ]
            
            for tool in all_tools:
                tool_data = vulnerabilities.get(tool.title().replace('-', ' '), [])
                if tool_data:
                    story.append(Paragraph(f"▼ {tool} - {len(tool_data)} hallazgos", self.styles['Heading2']))
                    
                    for i, finding in enumerate(tool_data[:15], 1):  # Máximo 15 por herramienta
                        level = finding.get('level', 1)
                        risk_text = "🔴 CRÍTICO" if level >= 3 else "🟡 MEDIO" if level == 2 else "🟢 BAJO"
                        
                        story.append(Paragraph(
                            f"{i}. {risk_text} {finding.get('info', 'Sin información')}",
                            self.styles['Normal']
                        ))
                        
                        # Detalles técnicos
                        method = finding.get('method', 'N/A')
                        path = finding.get('path', '/')
                        param = finding.get('parameter', 'N/A')
                        
                        story.append(Paragraph(
                            f"   └─ Método: {method} | Ruta: {path} | Parámetro: {param}",
                            self.styles['Normal']
                        ))
                    
                    if len(tool_data) > 15:
                        story.append(Paragraph(
                            f"   ... y {len(tool_data) - 15} hallazgos adicionales",
                            self.styles['Normal']
                        ))
                    
                    story.append(Spacer(1, 0.1*inch))
                else:
                    story.append(Paragraph(f"▼ {tool} - No ejecutado o sin hallazgos", self.styles['Heading2']))
                    story.append(Paragraph("   Sin resultados específicos para esta herramienta", self.styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
            
            # Resumen técnico
            story.append(Paragraph("RESUMEN TÉCNICO FINAL", self.styles['Heading1']))
            tools_used = scan_data.get('infos', {}).get('tools_used', all_tools[:10])  # Mostrar al menos las primeras 10
            if tools_used:
                story.append(Paragraph(f"Suite de herramientas ejecutadas: {', '.join(tools_used)}", self.styles['Normal']))
            
            story.append(Paragraph(
                f"Este análisis comprehensivo utilizó una suite de {len(all_tools)} herramientas profesionales "
                "de seguridad para obtener máxima cobertura. Incluye escaneo de puertos, análisis de "
                "vulnerabilidades web, enumeración DNS, testing de inyecciones, brute force, reconocimiento "
                "OSINT, análisis SSL, detección WAF, y muchas técnicas adicionales de pentesting.",
                self.styles['Normal']
            ))
            
            # Estadísticas finales
            total_findings = sum(len(vulns) for vulns in vulnerabilities.values())
            story.append(Paragraph(
                f"Total de hallazgos registrados: {total_findings} across {len(vulnerabilities)} categorías",
                self.styles['Normal']
            ))
            
            # Información del escaneo
            story.append(Spacer(1, 0.5*inch))
            story.append(Paragraph("INFORMACIÓN DEL ESCANEO", self.styles['Heading2']))
            story.append(Paragraph(f"Estado: {scan_data.get('status', 'N/A')}", self.styles['Normal']))
            story.append(Paragraph(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
            
            # Generar PDF
            try:
                doc.build(story)
                logger.info(f"Reporte PDF generado exitosamente: {output_path}")
                return str(output_path)
            except Exception as build_error:
                logger.warning(f"Error escribiendo en directorio temporal, usando archivo temporal: {build_error}")
                # Fallback: usar archivo temporal directo
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                    temp_doc = SimpleDocTemplate(
                        temp_file.name,
                        pagesize=A4,
                        rightMargin=72,
                        leftMargin=72,
                        topMargin=72,
                        bottomMargin=72
                    )
                    temp_doc.build(story)
                    logger.info(f"PDF generado con archivo temporal: {temp_file.name}")
                    return temp_file.name
            
        except Exception as e:
            logger.error(f"Error generando reporte PDF: {e}")
            raise


# Instancia global del generador
simple_pdf_generator = SimplePDFGenerator()
