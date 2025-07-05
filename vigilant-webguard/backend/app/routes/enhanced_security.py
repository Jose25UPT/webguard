from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Dict, Any, Optional
import asyncio
from loguru import logger

from ..services.telemetry_service import telemetry_service
from ..services.real_infrastructure_scanner import real_infrastructure_scanner
from ..services.exploit_suite_service import exploit_suite_service
from ..services.config_service import config_service

router = APIRouter()

# Modelos de datos
class TargetScanRequest(BaseModel):
    target_url: HttpUrl
    scan_type: Optional[str] = "comprehensive"
    enable_telemetry: Optional[bool] = True

class ExploitSuiteRequest(BaseModel):
    target_url: HttpUrl
    request_count: Optional[int] = 1000
    enable_vulnerability_scan: Optional[bool] = True
    enable_mass_requests: Optional[bool] = True

class TelemetryEventRequest(BaseModel):
    event_type: str
    target_url: Optional[HttpUrl] = None
    scan_data: Optional[Dict[str, Any]] = {}
    custom_data: Optional[Dict[str, Any]] = {}

@router.on_event("startup")
async def initialize_services():
    """Inicializar todos los servicios mejorados"""
    try:
        await telemetry_service.initialize()
        await real_infrastructure_scanner.initialize()
        await exploit_suite_service.initialize()
        logger.info("🚀 Servicios de seguridad mejorados inicializados correctamente")
    except Exception as e:
        logger.error(f"Error inicializando servicios: {e}")

@router.on_event("shutdown")
async def cleanup_services():
    """Limpiar recursos al cerrar"""
    try:
        await telemetry_service.close()
        await real_infrastructure_scanner.close()
        await exploit_suite_service.close()
        logger.info("🔒 Servicios de seguridad cerrados correctamente")
    except Exception as e:
        logger.error(f"Error cerrando servicios: {e}")

@router.post("/enhanced-infrastructure-scan")
async def enhanced_infrastructure_scan(
    request: TargetScanRequest,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Escaneo completo y real de infraestructura con telemetría
    """
    target_url = str(request.target_url)
    logger.info(f"🔍 Iniciando escaneo de infraestructura mejorado para: {target_url}")
    
    try:
        # Ejecutar escaneo de infraestructura real
        scan_result = await real_infrastructure_scanner.scan_full_infrastructure(target_url)
        
        # Enviar telemetría si está habilitada
        if request.enable_telemetry:
            telemetry_data = {
                'scan_type': 'infrastructure',
                'target_url': target_url,
                'scan_timestamp': scan_result.get('scan_timestamp'),
                'duration': 0,  # Se calculará en el servicio
                'vulnerabilities_found': len([
                    k for k, v in scan_result.get('infrastructure', {}).items() 
                    if isinstance(v, dict) and v.get('status') == 'success'
                ]),
                'additional_data': {
                    'scan_type_detail': request.scan_type,
                    'infrastructure_checks': scan_result.get('summary', {}).get('total_checks', 0),
                    'successful_checks': scan_result.get('summary', {}).get('successful_checks', 0),
                    'risk_level': scan_result.get('summary', {}).get('risk_level', 'unknown')
                }
            }
            
            # Enviar telemetría en segundo plano
            background_tasks.add_task(telemetry_service.track_scan_event, telemetry_data)
        
        # Agregar metadatos del escaneo
        scan_result['metadata'] = {
            'scan_enhanced': True,
            'telemetry_enabled': request.enable_telemetry,
            'scan_type': request.scan_type,
            'real_data': True,
            'services_used': [
                'DNS Resolution',
                'WHOIS Lookup', 
                'SSL Certificate Analysis',
                'HTTP Headers Analysis',
                'Technology Stack Detection',
                'CDN Detection',
                'Security Headers Analysis',
                'IP Geolocation',
                'Port Scanning'
            ]
        }
        
        logger.info(f"✅ Escaneo de infraestructura completado para {target_url}")
        return scan_result
        
    except Exception as e:
        logger.error(f"Error en escaneo de infraestructura: {e}")
        raise HTTPException(status_code=500, detail=f"Error scanning infrastructure: {str(e)}")

@router.post("/exploit-suite")
async def run_exploit_suite(
    request: ExploitSuiteRequest,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Ejecutar suite completa de exploits y herramientas de penetración
    """
    target_url = str(request.target_url)
    logger.info(f"🎯 Iniciando suite de exploits para: {target_url}")
    
    try:
        # Validar número de peticiones
        if request.request_count > 50000:
            raise HTTPException(
                status_code=400, 
                detail="Request count too high. Maximum allowed: 50,000"
            )
        
        # Ejecutar suite de exploits
        if request.enable_vulnerability_scan and request.enable_mass_requests:
            # Suite completa
            exploit_result = await exploit_suite_service.run_exploit_suite(target_url)
        elif request.enable_vulnerability_scan:
            # Solo escaneo de vulnerabilidades
            exploit_result = await exploit_suite_service.run_vulnerability_scan(target_url)
        elif request.enable_mass_requests:
            # Solo peticiones masivas
            exploit_result = await exploit_suite_service.generate_mass_requests(
                target_url, request.request_count
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="At least one exploit type must be enabled"
            )
        
        # Enviar telemetría
        telemetry_data = {
            'scan_type': 'exploit_suite',
            'target_url': target_url,
            'duration': 0,
            'vulnerabilities_found': len([
                k for k, v in exploit_result.get('vulnerabilities', {}).items()
                if isinstance(v, dict) and v.get('vulnerable', False)
            ]) if 'vulnerabilities' in exploit_result else 0,
            'additional_data': {
                'exploit_type': 'comprehensive' if request.enable_vulnerability_scan and request.enable_mass_requests else 'partial',
                'request_count': request.request_count,
                'mass_requests_enabled': request.enable_mass_requests,
                'vulnerability_scan_enabled': request.enable_vulnerability_scan,
                'risk_score': exploit_result.get('risk_score', exploit_result.get('overall_risk_score', 0))
            }
        }
        
        # Enviar telemetría en segundo plano
        background_tasks.add_task(telemetry_service.track_scan_event, telemetry_data)
        
        # Agregar metadatos del exploit
        exploit_result['metadata'] = {
            'exploit_suite_enhanced': True,
            'request_count': request.request_count,
            'vulnerability_scan_enabled': request.enable_vulnerability_scan,
            'mass_requests_enabled': request.enable_mass_requests,
            'exploit_types_tested': [
                'SQL Injection',
                'Cross-Site Scripting (XSS)',
                'Local File Inclusion (LFI)',
                'Command Injection',
                'XML External Entity (XXE)',
                'Authentication Bypass',
                'Directory Traversal',
                'File Upload Vulnerabilities',
                'Cross-Site Request Forgery (CSRF)',
                'Open Redirects'
            ] if request.enable_vulnerability_scan else [],
            'mass_request_patterns': [
                'GET Requests',
                'POST Requests', 
                'HEAD Requests',
                'OPTIONS Requests',
                'PUT Requests',
                'DELETE Requests'
            ] if request.enable_mass_requests else []
        }
        
        logger.info(f"✅ Suite de exploits completada para {target_url}")
        return exploit_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en suite de exploits: {e}")
        raise HTTPException(status_code=500, detail=f"Error running exploit suite: {str(e)}")

@router.post("/mass-requests")
async def generate_mass_requests(
    request: ExploitSuiteRequest,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Generar peticiones masivas específicamente para pruebas de carga
    """
    target_url = str(request.target_url)
    request_count = min(request.request_count, 50000)  # Límite de seguridad
    
    logger.info(f"🚀 Generando {request_count} peticiones masivas para: {target_url}")
    
    try:
        # Generar peticiones masivas
        mass_request_result = await exploit_suite_service.generate_mass_requests(
            target_url, request_count
        )
        
        # Enviar telemetría
        telemetry_data = {
            'scan_type': 'mass_requests',
            'target_url': target_url,
            'duration': mass_request_result.get('total_duration_seconds', 0),
            'additional_data': {
                'total_requests': request_count,
                'successful_requests': mass_request_result.get('successful_requests', 0),
                'failed_requests': mass_request_result.get('failed_requests', 0),
                'requests_per_second': mass_request_result.get('requests_per_second', 0),
                'average_response_time': mass_request_result.get('average_response_time', 0)
            }
        }
        
        # Enviar telemetría en segundo plano
        background_tasks.add_task(telemetry_service.track_scan_event, telemetry_data)
        
        # Agregar metadatos
        mass_request_result['metadata'] = {
            'test_type': 'load_testing',
            'max_concurrent_requests': 100,
            'batch_size': 500,
            'user_agents_rotated': True,
            'request_methods_used': ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE']
        }
        
        logger.info(f"✅ Peticiones masivas completadas: {mass_request_result.get('successful_requests', 0)}/{request_count}")
        return mass_request_result
        
    except Exception as e:
        logger.error(f"Error generando peticiones masivas: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating mass requests: {str(e)}")

@router.post("/vulnerability-scan")
async def vulnerability_scan_only(
    request: TargetScanRequest,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Escaneo específico de vulnerabilidades sin peticiones masivas
    """
    target_url = str(request.target_url)
    logger.info(f"🔍 Iniciando escaneo de vulnerabilidades para: {target_url}")
    
    try:
        # Ejecutar solo escaneo de vulnerabilidades
        vuln_result = await exploit_suite_service.run_vulnerability_scan(target_url)
        
        # Enviar telemetría si está habilitada
        if request.enable_telemetry:
            telemetry_data = {
                'scan_type': 'vulnerability_only',
                'target_url': target_url,
                'vulnerabilities_found': len([
                    k for k, v in vuln_result.get('vulnerabilities', {}).items()
                    if isinstance(v, dict) and v.get('vulnerable', False)
                ]),
                'additional_data': {
                    'risk_score': vuln_result.get('risk_score', 0),
                    'total_vulnerability_types': len(vuln_result.get('vulnerabilities', {})),
                    'scan_type_detail': request.scan_type
                }
            }
            
            # Enviar telemetría en segundo plano
            background_tasks.add_task(telemetry_service.track_scan_event, telemetry_data)
        
        # Agregar metadatos
        vuln_result['metadata'] = {
            'scan_type': 'vulnerability_assessment',
            'telemetry_enabled': request.enable_telemetry,
            'comprehensive_scan': True,
            'vulnerability_categories': [
                'Injection Flaws',
                'Cross-Site Scripting',
                'Authentication Issues',
                'File Inclusion Vulnerabilities',
                'Command Injection',
                'XML Security Issues',
                'File Upload Issues',
                'CSRF Vulnerabilities',
                'Redirect Vulnerabilities'
            ]
        }
        
        logger.info(f"✅ Escaneo de vulnerabilidades completado para {target_url}")
        return vuln_result
        
    except Exception as e:
        logger.error(f"Error en escaneo de vulnerabilidades: {e}")
        raise HTTPException(status_code=500, detail=f"Error scanning vulnerabilities: {str(e)}")

@router.get("/telemetry/dashboard")
async def get_telemetry_dashboard() -> Dict[str, Any]:
    """
    Obtener dashboard de observabilidad y telemetría
    """
    try:
        dashboard_data = await telemetry_service.get_observability_dashboard()
        
        # Agregar información adicional
        dashboard_data['available_services'] = {
            'real_infrastructure_scanner': True,
            'exploit_suite_service': True,
            'telemetry_service': True,
            'mass_request_generator': True
        }
        
        dashboard_data['capabilities'] = [
            'Real DNS Resolution',
            'WHOIS Lookup',
            'SSL Certificate Analysis',
            'HTTP Headers Analysis',
            'Technology Stack Detection',
            'Vulnerability Scanning',
            'Exploit Testing',
            'Mass Request Generation',
            'Telemetry Collection',
            'Real-time Monitoring'
        ]
        
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Error obteniendo dashboard de telemetría: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting telemetry dashboard: {str(e)}")

@router.post("/telemetry/event")
async def track_custom_event(request: TelemetryEventRequest) -> Dict[str, Any]:
    """
    Rastrear evento personalizado de telemetría
    """
    try:
        event_data = {
            'scan_type': request.event_type,
            'target_url': str(request.target_url) if request.target_url else '',
            'additional_data': request.custom_data,
            **request.scan_data
        }
        
        # Enviar evento a servicios de telemetría
        result = await telemetry_service.track_scan_event(event_data)
        
        return {
            'event_tracked': True,
            'event_type': request.event_type,
            'telemetry_results': result,
            'timestamp': event_data.get('scan_timestamp', 'unknown')
        }
        
    except Exception as e:
        logger.error(f"Error rastreando evento personalizado: {e}")
        raise HTTPException(status_code=500, detail=f"Error tracking custom event: {str(e)}")

@router.get("/tools/suite-info")
async def get_exploit_suite_info() -> Dict[str, Any]:
    """
    Obtener información sobre las herramientas disponibles en la suite
    """
    return {
        'exploit_suite_version': '2.0.0',
        'available_tools': {
            'vulnerability_scanners': [
                'SQL Injection Scanner',
                'XSS Detection Tool',
                'LFI/RFI Scanner', 
                'Command Injection Detector',
                'XXE Vulnerability Scanner',
                'Authentication Bypass Tester',
                'Directory Traversal Scanner',
                'File Upload Vulnerability Scanner',
                'CSRF Protection Analyzer',
                'Open Redirect Detector'
            ],
            'infrastructure_tools': [
                'Real DNS Resolver',
                'WHOIS Information Gatherer',
                'SSL/TLS Certificate Analyzer',
                'HTTP Headers Analyzer',
                'Technology Stack Detector',
                'CDN Detection Tool',
                'Security Headers Analyzer',
                'IP Geolocation Service',
                'Port Scanner',
                'Network Information Gatherer'
            ],
            'load_testing_tools': [
                'Mass Request Generator',
                'Concurrent Connection Tester',
                'DoS Simulation Tool',
                'Response Time Analyzer',
                'Request Pattern Generator'
            ],
            'telemetry_services': [
                'Google Analytics Integration',
                'AWS CloudWatch Integration',
                'Azure Monitor Integration',
                'Datadog Integration',
                'New Relic Integration',
                'System Metrics Collector',
                'Real-time Monitoring'
            ]
        },
        'supported_targets': [
            'HTTP/HTTPS Websites',
            'Web Applications',
            'REST APIs',
            'GraphQL Endpoints',
            'WebSocket Connections'
        ],
        'safety_features': [
            'Request Rate Limiting',
            'Concurrent Connection Limits',
            'Timeout Protection',
            'Error Handling',
            'Resource Usage Monitoring'
        ],
        'real_world_integration': {
            'uses_real_apis': True,
            'performs_actual_scans': True,
            'connects_to_external_services': True,
            'generates_real_traffic': True,
            'collects_real_metrics': True
        }
    }

@router.get("/config/status")
async def get_configuration_status() -> Dict[str, Any]:
    """
    Obtener estado de configuración de API keys y servicios
    """
    try:
        config_status = config_service.get_configuration_status()
        
        # Agregar información adicional sobre la configuración
        config_status['setup_instructions'] = {
            'step_1': 'Copia backend/.env.template a backend/.env',
            'step_2': 'Registrate en los servicios que necesites',
            'step_3': 'Agrega las API keys al archivo .env',
            'step_4': 'Activa los servicios con ENABLE_[SERVICIO]=true',
            'step_5': 'Reinicia el servidor para aplicar cambios'
        }
        
        config_status['service_priority'] = {
            'recommended_first': ['azure_monitor', 'google_analytics'],
            'useful_security': ['virustotal', 'abuseipdb'],
            'advanced_monitoring': ['aws_cloudwatch', 'datadog'],
            'network_analysis': ['shodan']
        }
        
        return config_status
        
    except Exception as e:
        logger.error(f"Error obteniendo estado de configuración: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting configuration status: {str(e)}")

@router.get("/config/setup-guide")
async def get_setup_guide() -> Dict[str, Any]:
    """
    Obtener guía completa de configuración
    """
    try:
        setup_guide = config_service.generate_setup_guide()
        missing_services = config_service.get_missing_services()
        free_services = config_service.get_free_tier_services()
        
        return {
            'setup_guide': setup_guide,
            'missing_services': {name: {
                'name': config.name,
                'service_type': config.service_type,
                'free_tier': config.free_tier,
                'limit_info': config.limit_info,
                'register_url': config.register_url
            } for name, config in missing_services.items()},
            'free_tier_services': {name: {
                'name': config.name,
                'limit_info': config.limit_info,
                'register_url': config.register_url
            } for name, config in free_services.items()},
            'quick_start_azure': {
                'description': 'Azure Monitor es la opción más recomendada para empezar',
                'steps': [
                    '1. Ve a https://azure.microsoft.com/free/',
                    '2. Crea una cuenta gratuita (no requiere tarjeta de crédito)',
                    '3. Ve al Azure Portal',
                    '4. Crea una App Registration en Azure AD',
                    '5. Copia las credenciales al archivo .env',
                    '6. Activa ENABLE_AZURE_MONITOR=true'
                ],
                'benefits': [
                    'Completamente gratis',
                    'Telemetría avanzada',
                    'Dashboards integrados',
                    'Alertas en tiempo real'
                ]
            }
        }
        
    except Exception as e:
        logger.error(f"Error generando guía de configuración: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating setup guide: {str(e)}")

@router.get("/config/service/{service_name}")
async def get_service_info(service_name: str) -> Dict[str, Any]:
    """
    Obtener información detallada de un servicio específico
    """
    try:
        service_config = config_service.get_service_config(service_name)
        
        if not service_config:
            raise HTTPException(
                status_code=404, 
                detail=f"Service '{service_name}' not found"
            )
        
        is_available = config_service.is_service_available(service_name)
        
        detailed_info = {
            'service_name': service_config.name,
            'service_key': service_name,
            'service_type': service_config.service_type,
            'is_configured': service_config.key is not None,
            'is_enabled': service_config.enabled,
            'is_available': is_available,
            'free_tier': service_config.free_tier,
            'limit_info': service_config.limit_info,
            'register_url': service_config.register_url,
            'development_mode': config_service.development_mode
        }
        
        # Agregar información específica del servicio
        service_specific_info = {
            'virustotal': {
                'description': 'Análisis de URLs y archivos maliciosos',
                'use_cases': ['URL scanning', 'File analysis', 'Domain reputation'],
                'integration_complexity': 'Fácil'
            },
            'shodan': {
                'description': 'Motor de búsqueda para dispositivos conectados a Internet',
                'use_cases': ['IP scanning', 'Service detection', 'Banner grabbing'],
                'integration_complexity': 'Medio'
            },
            'azure_monitor': {
                'description': 'Plataforma de monitoreo y telemetría de Azure',
                'use_cases': ['Application monitoring', 'Custom metrics', 'Log analytics'],
                'integration_complexity': 'Medio'
            },
            'google_analytics': {
                'description': 'Análisis web y seguimiento de eventos',
                'use_cases': ['Event tracking', 'User behavior', 'Custom dimensions'],
                'integration_complexity': 'Fácil'
            },
            'aws_cloudwatch': {
                'description': 'Servicio de monitoreo de AWS',
                'use_cases': ['Custom metrics', 'Log monitoring', 'Alarms'],
                'integration_complexity': 'Medio'
            },
            'datadog': {
                'description': 'Plataforma de monitoreo y análisis',
                'use_cases': ['APM', 'Infrastructure monitoring', 'Log management'],
                'integration_complexity': 'Avanzado'
            }
        }
        
        if service_name in service_specific_info:
            detailed_info.update(service_specific_info[service_name])
        
        return detailed_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo información del servicio {service_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting service info: {str(e)}")
