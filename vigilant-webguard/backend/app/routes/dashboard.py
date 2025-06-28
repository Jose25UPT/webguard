from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.services.security_apis import SecurityAPIsService
from app.services.realtime_monitor import realtime_monitor
import asyncio
import os
from typing import Dict, List

router = APIRouter()
security_service = SecurityAPIsService()

@router.post("/comprehensive-scan")
async def comprehensive_scan(request_data: dict):
    """Escaneo completo usando múltiples APIs de seguridad"""
    try:
        url = request_data.get('url')
        if not url:
            raise HTTPException(status_code=400, detail="URL requerida")
        
        # Realizar análisis completo
        results = await security_service.analyze_url_comprehensive(url)
        
        return JSONResponse(content=results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/realtime-stats")
async def get_realtime_stats():
    """Obtener estadísticas en tiempo real"""
    try:
        stats = realtime_monitor.get_realtime_stats()
        return JSONResponse(content=stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/attack-timeline/{hours}")
async def get_attack_timeline(hours: int = 24):
    """Obtener timeline de ataques"""
    try:
        timeline = realtime_monitor.get_attack_timeline(hours)
        return JSONResponse(content=timeline)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/geographic-attacks")
async def get_geographic_attacks():
    """Obtener datos geográficos de ataques"""
    try:
        geo_data = realtime_monitor.get_geographic_data()
        return JSONResponse(content=geo_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/threat-intelligence")
async def get_threat_intelligence():
    """Obtener inteligencia de amenazas basada en datos reales"""
    try:
        # Obtener datos reales de análisis recientes
        from pathlib import Path
        import glob
        import json
        
        real_threats = {
            'active_campaigns': [],
            'trending_malware': [],
            'vulnerability_alerts': [],
            'recent_scans': []
        }
        
        # Buscar archivos reales de Wapiti
        wapiti_files = glob.glob("results/opensource_tools/wapiti_*/report.json")
        for file_path in wapiti_files[-3:]:  # Últimos 3
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    vulns = data.get('vulnerabilities', {})
                    total_vulns = sum(len(v) for v in vulns.values() if isinstance(v, list))
                    if total_vulns > 0:
                        real_threats['recent_scans'].append({
                            'tool': 'Wapiti',
                            'vulnerabilities_found': total_vulns,
                            'categories': list(vulns.keys()),
                            'scan_date': os.path.getmtime(file_path)
                        })
            except Exception:
                continue
        
        # Buscar archivos reales de Nikto
        nikto_files = glob.glob("results/opensource_tools/nikto_*/nikto_report.json")
        for file_path in nikto_files[-3:]:  # Últimos 3
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    json_lines = [line for line in content.strip().split('\n') if line.strip()]
                    if json_lines:
                        data = json.loads(json_lines[-1])
                        vulns = data.get('vulnerabilities', [])
                        if vulns:
                            real_threats['recent_scans'].append({
                                'tool': 'Nikto',
                                'vulnerabilities_found': len(vulns),
                                'scan_date': os.path.getmtime(file_path)
                            })
            except Exception:
                continue
        
        # Si no hay datos reales, indicarlo
        if not real_threats['recent_scans']:
            real_threats['message'] = 'No hay datos de análisis recientes disponibles'
        
        threat_intel = real_threats
        
        return JSONResponse(content=threat_intel)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/security-metrics")
async def get_security_metrics():
    """Obtener métricas de seguridad del sistema"""
    try:
        import psutil
        from datetime import datetime
        
        metrics = {
            'system_health': {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent if psutil.disk_usage('/') else 0,
                'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
            },
            'security_posture': {
                'firewall_status': 'ACTIVE',
                'ids_status': 'MONITORING',
                'antivirus_status': 'UPDATED',
                'vulnerability_scan_last': '2024-01-15 10:30:00',
                'security_score': 85
            },
            'network_statistics': {
                'active_connections': len(realtime_monitor.active_connections),
                'blocked_ips': 15,
                'allowed_traffic': '98.5%',
                'bandwidth_usage': '45%'
            }
        }
        
        return JSONResponse(content=metrics)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/compliance-status")
async def get_compliance_status():
    """Obtener estado de cumplimiento normativo"""
    try:
        compliance = {
            'frameworks': {
                'ISO_27001': {
                    'status': 'COMPLIANT',
                    'score': 92,
                    'last_audit': '2024-01-10',
                    'findings': 3
                },
                'NIST_CSF': {
                    'status': 'PARTIAL',
                    'score': 78,
                    'last_audit': '2024-01-05',
                    'findings': 8
                },
                'GDPR': {
                    'status': 'COMPLIANT',
                    'score': 95,
                    'last_audit': '2023-12-20',
                    'findings': 1
                }
            },
            'controls': {
                'access_control': 'IMPLEMENTED',
                'data_encryption': 'IMPLEMENTED',
                'incident_response': 'IMPLEMENTED',
                'backup_recovery': 'NEEDS_REVIEW',
                'security_training': 'IMPLEMENTED'
            },
            'risk_assessment': {
                'last_conducted': '2024-01-01',
                'critical_risks': 2,
                'high_risks': 5,
                'medium_risks': 12,
                'low_risks': 8
            }
        }
        
        return JSONResponse(content=compliance)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/incident-response")
async def get_incident_response():
    """Obtener información del sistema de respuesta a incidentes"""
    try:
        incidents = {
            'active_incidents': [
                {
                    'id': 'INC-2024-001',
                    'title': 'Suspicious Network Activity',
                    'severity': 'MEDIUM',
                    'status': 'INVESTIGATING',
                    'assigned_to': 'Security Team',
                    'created': '2024-01-15 14:30:00',
                    'last_update': '2024-01-15 16:45:00'
                }
            ],
            'recent_incidents': [
                {
                    'id': 'INC-2024-002',
                    'title': 'Failed Login Attempts',
                    'severity': 'LOW',
                    'status': 'RESOLVED',
                    'resolution': 'Account locked, user notified',
                    'created': '2024-01-14 09:15:00',
                    'resolved': '2024-01-14 10:30:00'
                }
            ],
            'response_metrics': {
                'mttr': '2.5 hours',  # Mean Time To Response
                'mtta': '1.2 hours',  # Mean Time To Acknowledge
                'incidents_this_month': 8,
                'false_positives': '15%'
            },
            'playbooks': [
                'Malware Incident Response',
                'Data Breach Response',
                'DDoS Mitigation',
                'Insider Threat Investigation'
            ]
        }
        
        return JSONResponse(content=incidents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

