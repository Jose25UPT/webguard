"""
Generador de reportes PDF para escaneos de seguridad
"""
import os
import json
from datetime import datetime
from pathlib import Path
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from loguru import logger
from typing import Dict, Any


class PDFReportGenerator:
    """Generador de reportes PDF para escaneos de seguridad"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.reports_dir = Path("results/reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_comprehensive_report(self, scan_result: Dict[str, Any]) -> str:
        """Generar reporte PDF completo"""
        try:
            # Nombre del archivo
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{scan_result.get('scan_id', 'unknown')}_{timestamp}.pdf"
            filepath = self.reports_dir / filename
            
            # Crear documento
            doc = SimpleDocTemplate(str(filepath), pagesize=A4)
            story = []
            
            # Título
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue,
                alignment=1  # Centrado
            )
            story.append(Paragraph("Reporte de Seguridad WebGuard", title_style))
            story.append(Spacer(1, 12))
            
            # Información del escaneo
            info_data = [
                ["URL Objetivo:", scan_result.get('target_url', 'N/A')],
                ["ID de Escaneo:", scan_result.get('scan_id', 'N/A')],
                ["Fecha:", scan_result.get('timestamp', 'N/A')],
                ["Duración:", f"{scan_result.get('duration', 0):.2f} segundos"],
                ["Estado:", scan_result.get('status', 'N/A')]
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(Paragraph("Información del Escaneo", self.styles['Heading2']))
            story.append(info_table)
            story.append(Spacer(1, 20))
            
            # Resumen de vulnerabilidades
            metadata = scan_result.get('scan_metadata', {})
            summary_data = [
                ["Total de Vulnerabilidades:", str(metadata.get('total_vulnerabilities', 0))],
                ["Vulnerabilidades Críticas:", str(metadata.get('critical_vulnerabilities', 0))],
                ["Scanner Utilizado:", metadata.get('scanner', 'N/A')]
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(Paragraph("Resumen de Vulnerabilidades", self.styles['Heading2']))
            story.append(summary_table)
            story.append(Spacer(1, 20))
            
            # Detalles de vulnerabilidades
            story.append(Paragraph("Detalles de Vulnerabilidades", self.styles['Heading2']))
            
            vulnerabilities = scan_result.get('vulnerabilities', {})
            if vulnerabilities:
                for category, vulns in vulnerabilities.items():
                    if vulns:
                        story.append(Paragraph(f"Categoría: {category.replace('_', ' ').title()}", self.styles['Heading3']))
                        
                        for i, vuln in enumerate(vulns, 1):
                            vuln_data = [
                                [f"Vulnerabilidad #{i}"],
                                ["URL:", vuln.get('url', 'N/A')],
                                ["Parámetro:", vuln.get('parameter', 'N/A')],
                                ["Nivel:", str(vuln.get('level', 'N/A'))],
                                ["Descripción:", vuln.get('description', 'N/A')]
                            ]
                            
                            vuln_table = Table(vuln_data, colWidths=[1*inch, 5*inch])
                            vuln_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                                ('FONTSIZE', (0, 0), (-1, -1), 9),
                                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                                ('GRID', (0, 0), (-1, -1), 1, colors.black)
                            ]))
                            
                            story.append(vuln_table)
                            story.append(Spacer(1, 10))
                        
                        story.append(Spacer(1, 15))
            else:
                story.append(Paragraph("No se encontraron vulnerabilidades.", self.styles['Normal']))
            
            # Generar PDF
            doc.build(story)
            
            logger.info(f"Reporte PDF generado: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error generando PDF: {e}")
            raise e


# Instancia global
pdf_generator = PDFReportGenerator()
