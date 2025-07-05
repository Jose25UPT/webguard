import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from loguru import logger
import json

@dataclass
class APIKeyConfig:
    """Configuración de una API key"""
    name: str
    key: Optional[str]
    enabled: bool
    service_type: str
    free_tier: bool
    limit_info: str
    register_url: str
    
class ConfigService:
    """Servicio de configuración flexible para API keys y servicios"""
    
    def __init__(self):
        self.api_configs = {}
        self.development_mode = self._get_bool_env('DEVELOPMENT_MODE', True)
        self._initialize_api_configs()
        
    def _get_bool_env(self, key: str, default: bool = False) -> bool:
        """Obtener variable de entorno booleana"""
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def _initialize_api_configs(self):
        """Inicializar configuraciones de API"""
        
        # Servicios de seguridad
        self.api_configs['virustotal'] = APIKeyConfig(
            name='VirusTotal',
            key=os.getenv('VIRUSTOTAL_API_KEY'),
            enabled=self._get_bool_env('ENABLE_VIRUSTOTAL'),
            service_type='security',
            free_tier=True,
            limit_info='4 requests/min, 500/día',
            register_url='https://www.virustotal.com/gui/join-us'
        )
        
        self.api_configs['shodan'] = APIKeyConfig(
            name='Shodan',
            key=os.getenv('SHODAN_API_KEY'),
            enabled=self._get_bool_env('ENABLE_SHODAN'),
            service_type='security',
            free_tier=True,
            limit_info='100 queries/mes',
            register_url='https://account.shodan.io/register'
        )
        
        self.api_configs['abuseipdb'] = APIKeyConfig(
            name='AbuseIPDB',
            key=os.getenv('ABUSEIPDB_API_KEY'),
            enabled=self._get_bool_env('ENABLE_ABUSEIPDB'),
            service_type='security',
            free_tier=True,
            limit_info='1000 queries/día',
            register_url='https://www.abuseipdb.com/register'
        )
        
        # Servicios de telemetría gratuitos
        self.api_configs['azure_monitor'] = APIKeyConfig(
            name='Azure Monitor',
            key=self._get_azure_config(),
            enabled=self._get_bool_env('ENABLE_AZURE_MONITOR'),
            service_type='telemetry',
            free_tier=True,
            limit_info='Gratis con cuenta Azure',
            register_url='https://azure.microsoft.com/free/'
        )
        
        self.api_configs['aws_cloudwatch'] = APIKeyConfig(
            name='AWS CloudWatch',
            key=self._get_aws_config(),
            enabled=self._get_bool_env('ENABLE_AWS_CLOUDWATCH'),
            service_type='telemetry',
            free_tier=True,
            limit_info='Tier gratuito AWS',
            register_url='https://aws.amazon.com/free/'
        )
        
        self.api_configs['google_analytics'] = APIKeyConfig(
            name='Google Analytics',
            key=os.getenv('GOOGLE_ANALYTICS_TRACKING_ID'),
            enabled=self._get_bool_env('ENABLE_GOOGLE_ANALYTICS'),
            service_type='telemetry',
            free_tier=True,
            limit_info='Completamente gratis',
            register_url='https://analytics.google.com/'
        )
        
        # Servicios premium (opcionales)
        self.api_configs['datadog'] = APIKeyConfig(
            name='Datadog',
            key=os.getenv('DATADOG_API_KEY'),
            enabled=self._get_bool_env('ENABLE_DATADOG'),
            service_type='telemetry',
            free_tier=False,
            limit_info='14 días gratis',
            register_url='https://www.datadoghq.com/free-trial/'
        )
        
        self.api_configs['new_relic'] = APIKeyConfig(
            name='New Relic',
            key=os.getenv('NEW_RELIC_LICENSE_KEY'),
            enabled=self._get_bool_env('ENABLE_NEW_RELIC'),
            service_type='telemetry',
            free_tier=True,
            limit_info='Gratis hasta 100GB/mes',
            register_url='https://newrelic.com/signup'
        )
    
    def _get_azure_config(self) -> Optional[str]:
        """Obtener configuración de Azure"""
        tenant_id = os.getenv('AZURE_TENANT_ID')
        client_id = os.getenv('AZURE_CLIENT_ID')
        client_secret = os.getenv('AZURE_CLIENT_SECRET')
        subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
        
        if all([tenant_id, client_id, client_secret, subscription_id]):
            return json.dumps({
                'tenant_id': tenant_id,
                'client_id': client_id,
                'client_secret': client_secret,
                'subscription_id': subscription_id
            })
        return None
    
    def _get_aws_config(self) -> Optional[str]:
        """Obtener configuración de AWS"""
        access_key = os.getenv('AWS_ACCESS_KEY_ID')
        secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        region = os.getenv('AWS_REGION', 'us-east-1')
        
        if access_key and secret_key:
            return json.dumps({
                'access_key_id': access_key,
                'secret_access_key': secret_key,
                'region': region
            })
        return None
    
    def get_available_services(self) -> Dict[str, APIKeyConfig]:
        """Obtener servicios disponibles (con API keys configuradas)"""
        available = {}
        for service_name, config in self.api_configs.items():
            if config.enabled and config.key:
                available[service_name] = config
        return available
    
    def get_missing_services(self) -> Dict[str, APIKeyConfig]:
        """Obtener servicios sin configurar"""
        missing = {}
        for service_name, config in self.api_configs.items():
            if not config.key:
                missing[service_name] = config
        return missing
    
    def get_free_tier_services(self) -> Dict[str, APIKeyConfig]:
        """Obtener servicios con tier gratuito"""
        free_services = {}
        for service_name, config in self.api_configs.items():
            if config.free_tier:
                free_services[service_name] = config
        return free_services
    
    def is_service_available(self, service_name: str) -> bool:
        """Verificar si un servicio está disponible"""
        config = self.api_configs.get(service_name)
        if not config:
            return False
        
        # En modo desarrollo, simular que está disponible
        if self.development_mode:
            return True
            
        return config.enabled and config.key is not None
    
    def get_service_config(self, service_name: str) -> Optional[APIKeyConfig]:
        """Obtener configuración de un servicio específico"""
        return self.api_configs.get(service_name)
    
    def get_configuration_status(self) -> Dict[str, Any]:
        """Obtener estado completo de la configuración"""
        available = self.get_available_services()
        missing = self.get_missing_services()
        free_tier = self.get_free_tier_services()
        
        return {
            'development_mode': self.development_mode,
            'total_services': len(self.api_configs),
            'available_services': len(available),
            'missing_services': len(missing),
            'free_tier_services': len(free_tier),
            'services': {
                'available': {name: {
                    'name': config.name,
                    'service_type': config.service_type,
                    'free_tier': config.free_tier,
                    'limit_info': config.limit_info
                } for name, config in available.items()},
                'missing': {name: {
                    'name': config.name,
                    'service_type': config.service_type,
                    'free_tier': config.free_tier,
                    'limit_info': config.limit_info,
                    'register_url': config.register_url
                } for name, config in missing.items()},
                'recommendations': self._get_recommendations()
            }
        }
    
    def _get_recommendations(self) -> List[str]:
        """Obtener recomendaciones de configuración"""
        recommendations = []
        
        missing = self.get_missing_services()
        
        # Recomendar servicios gratuitos importantes
        if 'azure_monitor' in missing:
            recommendations.append(
                "✅ RECOMENDADO: Azure Monitor - Completamente gratis y muy útil para telemetría"
            )
        
        if 'google_analytics' in missing:
            recommendations.append(
                "✅ RECOMENDADO: Google Analytics - Gratis y fácil de configurar"
            )
        
        if 'virustotal' in missing:
            recommendations.append(
                "🔍 ÚTIL: VirusTotal - Ideal para análisis de seguridad (tier gratuito disponible)"
            )
        
        if 'aws_cloudwatch' in missing:
            recommendations.append(
                "☁️ OPCIÓN: AWS CloudWatch - Si ya tienes cuenta AWS, es gratis en tier básico"
            )
        
        if not recommendations:
            recommendations.append("🎉 ¡Excelente! Tienes una buena configuración de servicios.")
        
        return recommendations
    
    def get_api_key(self, service_name: str) -> Optional[str]:
        """Obtener API key de un servicio específico"""
        config = self.api_configs.get(service_name)
        if not config:
            return None
        
        # En modo desarrollo, devolver una clave simulada
        if self.development_mode and not config.key:
            return f"dev_mode_{service_name}_key"
        
        return config.key
    
    def generate_setup_guide(self) -> str:
        """Generar guía de configuración"""
        missing = self.get_missing_services()
        
        if not missing:
            return "🎉 ¡Todas las API keys están configuradas!"
        
        guide = """
📋 GUÍA DE CONFIGURACIÓN DE API KEYS
=====================================

Para aprovechar al máximo WebGuard, configura estos servicios:

🆓 SERVICIOS GRATUITOS RECOMENDADOS:
"""
        
        free_missing = {k: v for k, v in missing.items() if v.free_tier}
        
        for service_name, config in free_missing.items():
            guide += f"""
📌 {config.name}
   • Tipo: {config.service_type}
   • Límites: {config.limit_info}
   • Registro: {config.register_url}
   • Variable: {service_name.upper()}_API_KEY
"""
        
        guide += """
🔧 INSTRUCCIONES:
1. Copia backend/.env.template a backend/.env
2. Registrate en los servicios que te interesen
3. Copia las API keys al archivo .env
4. Cambia ENABLE_[SERVICIO]=true para activar cada servicio

💡 TIPS:
• Puedes usar el sistema sin API keys en modo desarrollo
• Solo configura los servicios que necesites
• Azure Monitor es especialmente recomendado para telemetría
"""
        
        return guide

# Instancia global
config_service = ConfigService()
