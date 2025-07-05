import asyncio
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
import requests
import aiohttp
from loguru import logger
import os
from dotenv import load_dotenv
import psutil
import platform

load_dotenv()

class TelemetryService:
    """Servicio de telemetría y observabilidad integrado con servicios reales"""
    
    def __init__(self):
        self.session = None
        self.metrics = {
            'system_metrics': {},
            'app_metrics': {},
            'security_metrics': {},
            'network_metrics': {}
        }
        
        # Configuración de servicios
        self.services = {
            'google_analytics': {
                'enabled': bool(os.getenv('GA_MEASUREMENT_ID')),
                'measurement_id': os.getenv('GA_MEASUREMENT_ID'),
                'api_secret': os.getenv('GA_API_SECRET')
            },
            'aws_cloudwatch': {
                'enabled': bool(os.getenv('AWS_ACCESS_KEY_ID')),
                'region': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
                'access_key': os.getenv('AWS_ACCESS_KEY_ID'),
                'secret_key': os.getenv('AWS_SECRET_ACCESS_KEY')
            },
            'azure_monitor': {
                'enabled': bool(os.getenv('AZURE_INSTRUMENTATION_KEY')),
                'instrumentation_key': os.getenv('AZURE_INSTRUMENTATION_KEY'),
                'endpoint': os.getenv('AZURE_MONITOR_ENDPOINT')
            },
            'datadog': {
                'enabled': bool(os.getenv('DATADOG_API_KEY')),
                'api_key': os.getenv('DATADOG_API_KEY'),
                'app_key': os.getenv('DATADOG_APP_KEY'),
                'site': os.getenv('DATADOG_SITE', 'datadoghq.com')
            },
            'new_relic': {
                'enabled': bool(os.getenv('NEW_RELIC_LICENSE_KEY')),
                'license_key': os.getenv('NEW_RELIC_LICENSE_KEY'),
                'account_id': os.getenv('NEW_RELIC_ACCOUNT_ID')
            }
        }

    async def initialize(self):
        """Inicializar servicios de telemetría"""
        self.session = aiohttp.ClientSession()
        logger.info("🔍 Inicializando servicios de telemetría...")
        
        # Verificar servicios disponibles
        available_services = []
        for service_name, config in self.services.items():
            if config['enabled']:
                available_services.append(service_name)
                logger.info(f"✅ {service_name} configurado correctamente")
        
        if not available_services:
            logger.warning("⚠️ No hay servicios de telemetría configurados")
            logger.info("💡 Agrega las siguientes variables de entorno:")
            logger.info("   - GA_MEASUREMENT_ID y GA_API_SECRET (Google Analytics)")
            logger.info("   - AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY (CloudWatch)")
            logger.info("   - AZURE_INSTRUMENTATION_KEY (Azure Monitor)")
            logger.info("   - DATADOG_API_KEY (Datadog)")
            logger.info("   - NEW_RELIC_LICENSE_KEY (New Relic)")
        
        return available_services

    async def collect_system_metrics(self) -> Dict[str, Any]:
        """Recolectar métricas del sistema"""
        try:
            # Métricas de CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # Métricas de memoria
            memory = psutil.virtual_memory()
            
            # Métricas de disco
            disk = psutil.disk_usage('/')
            
            # Métricas de red
            network = psutil.net_io_counters()
            
            # Información del sistema
            system_info = {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'architecture': platform.architecture()[0],
                'python_version': platform.python_version()
            }
            
            metrics = {
                'timestamp': datetime.utcnow().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else None
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'free': memory.free
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': (disk.used / disk.total) * 100
                },
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                },
                'system': system_info
            }
            
            self.metrics['system_metrics'] = metrics
            return metrics
            
        except Exception as e:
            logger.error(f"Error recolectando métricas del sistema: {e}")
            return {}

    async def send_to_google_analytics(self, event_data: Dict[str, Any]):
        """Enviar datos a Google Analytics 4"""
        if not self.services['google_analytics']['enabled']:
            return False
            
        try:
            measurement_id = self.services['google_analytics']['measurement_id']
            api_secret = self.services['google_analytics']['api_secret']
            
            url = f"https://www.google-analytics.com/mp/collect"
            params = {
                'measurement_id': measurement_id,
                'api_secret': api_secret
            }
            
            payload = {
                'client_id': event_data.get('client_id', '555'),
                'events': [{
                    'name': event_data.get('event_name', 'webguard_scan'),
                    'params': {
                        'scan_type': event_data.get('scan_type', 'basic'),
                        'target_url': event_data.get('target_url', ''),
                        'scan_duration': event_data.get('duration', 0),
                        'vulnerabilities_found': event_data.get('vulnerabilities', 0),
                        'custom_parameter_1': event_data.get('custom_data', {})
                    }
                }]
            }
            
            async with self.session.post(url, params=params, json=payload) as response:
                if response.status == 204:
                    logger.info("✅ Datos enviados a Google Analytics")
                    return True
                else:
                    logger.error(f"❌ Error enviando a GA: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error enviando a Google Analytics: {e}")
            return False

    async def send_to_datadog(self, metrics: Dict[str, Any]):
        """Enviar métricas a Datadog"""
        if not self.services['datadog']['enabled']:
            return False
            
        try:
            api_key = self.services['datadog']['api_key']
            site = self.services['datadog']['site']
            
            url = f"https://api.{site}/api/v1/series"
            headers = {
                'DD-API-KEY': api_key,
                'Content-Type': 'application/json'
            }
            
            # Preparar métricas para Datadog
            series = []
            timestamp = int(time.time())
            
            # Agregar métricas del sistema
            if 'system_metrics' in metrics:
                sys_metrics = metrics['system_metrics']
                series.extend([
                    {
                        'metric': 'webguard.system.cpu_percent',
                        'points': [[timestamp, sys_metrics.get('cpu', {}).get('percent', 0)]],
                        'type': 'gauge',
                        'tags': ['service:webguard', 'component:system']
                    },
                    {
                        'metric': 'webguard.system.memory_percent',
                        'points': [[timestamp, sys_metrics.get('memory', {}).get('percent', 0)]],
                        'type': 'gauge',
                        'tags': ['service:webguard', 'component:system']
                    }
                ])
            
            payload = {'series': series}
            
            async with self.session.post(url, headers=headers, json=payload) as response:
                if response.status == 202:
                    logger.info("✅ Métricas enviadas a Datadog")
                    return True
                else:
                    logger.error(f"❌ Error enviando a Datadog: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error enviando a Datadog: {e}")
            return False

    async def send_to_new_relic(self, metrics: Dict[str, Any]):
        """Enviar métricas a New Relic"""
        if not self.services['new_relic']['enabled']:
            return False
            
        try:
            license_key = self.services['new_relic']['license_key']
            
            url = "https://metric-api.newrelic.com/metric/v1"
            headers = {
                'Api-Key': license_key,
                'Content-Type': 'application/json'
            }
            
            # Preparar métricas para New Relic
            metrics_data = []
            timestamp = int(time.time() * 1000)  # New Relic usa milisegundos
            
            if 'system_metrics' in metrics:
                sys_metrics = metrics['system_metrics']
                metrics_data.extend([
                    {
                        'name': 'webguard.system.cpu.percent',
                        'type': 'gauge',
                        'value': sys_metrics.get('cpu', {}).get('percent', 0),
                        'timestamp': timestamp,
                        'attributes': {
                            'service': 'webguard',
                            'component': 'system'
                        }
                    },
                    {
                        'name': 'webguard.system.memory.percent',
                        'type': 'gauge',
                        'value': sys_metrics.get('memory', {}).get('percent', 0),
                        'timestamp': timestamp,
                        'attributes': {
                            'service': 'webguard',
                            'component': 'system'
                        }
                    }
                ])
            
            payload = [{'metrics': metrics_data}]
            
            async with self.session.post(url, headers=headers, json=payload) as response:
                if response.status == 202:
                    logger.info("✅ Métricas enviadas a New Relic")
                    return True
                else:
                    logger.error(f"❌ Error enviando a New Relic: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error enviando a New Relic: {e}")
            return False

    async def track_scan_event(self, scan_data: Dict[str, Any]):
        """Rastrear evento de escaneo en todos los servicios configurados"""
        logger.info(f"🔍 Rastreando evento de escaneo: {scan_data.get('scan_type', 'unknown')}")
        
        # Recolectar métricas del sistema
        system_metrics = await self.collect_system_metrics()
        
        # Preparar datos del evento
        event_data = {
            'client_id': scan_data.get('session_id', '555'),
            'event_name': 'webguard_scan',
            'scan_type': scan_data.get('scan_type', 'basic'),
            'target_url': scan_data.get('target_url', ''),
            'duration': scan_data.get('duration', 0),
            'vulnerabilities': scan_data.get('vulnerabilities_found', 0),
            'custom_data': scan_data.get('additional_data', {})
        }
        
        # Métricas completas
        full_metrics = {
            'system_metrics': system_metrics,
            'scan_metrics': scan_data
        }
        
        # Enviar a todos los servicios configurados
        results = {}
        
        if self.services['google_analytics']['enabled']:
            results['google_analytics'] = await self.send_to_google_analytics(event_data)
        
        if self.services['datadog']['enabled']:
            results['datadog'] = await self.send_to_datadog(full_metrics)
        
        if self.services['new_relic']['enabled']:
            results['new_relic'] = await self.send_to_new_relic(full_metrics)
        
        # Log de resultados
        successful_services = [service for service, success in results.items() if success]
        if successful_services:
            logger.info(f"✅ Telemetría enviada a: {', '.join(successful_services)}")
        else:
            logger.warning("⚠️ No se pudo enviar telemetría a ningún servicio")
        
        return results

    async def get_observability_dashboard(self) -> Dict[str, Any]:
        """Obtener datos para el dashboard de observabilidad"""
        system_metrics = await self.collect_system_metrics()
        
        return {
            'system_health': {
                'cpu_usage': system_metrics.get('cpu', {}).get('percent', 0),
                'memory_usage': system_metrics.get('memory', {}).get('percent', 0),
                'disk_usage': system_metrics.get('disk', {}).get('percent', 0),
                'status': 'healthy' if system_metrics.get('cpu', {}).get('percent', 0) < 80 else 'warning'
            },
            'services_status': {
                service: config['enabled'] for service, config in self.services.items()
            },
            'metrics_summary': system_metrics,
            'timestamp': datetime.utcnow().isoformat()
        }

    async def close(self):
        """Cerrar conexiones"""
        if self.session:
            await self.session.close()

# Instancia global
telemetry_service = TelemetryService()
