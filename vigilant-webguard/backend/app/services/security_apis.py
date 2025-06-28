import requests
import json
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse
import hashlib
import socket
from ipwhois import IPWhois
import dns.resolver
import subprocess
from loguru import logger

class SecurityAPIsService:
    """Servicio para integrar múltiples APIs de seguridad y análisis"""
    
    def __init__(self):
        # APIs gratuitas (no requieren clave en muchos casos)
        self.apis = {
            'urlvoid': 'http://api.urlvoid.com/1.0/',
            'virustotal_public': 'https://www.virustotal.com/vtapi/v2/',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/',
            'shodan_public': 'https://api.shodan.io/',
        }
        
        # Cache para evitar consultas repetidas
        self.cache = {}
    
    async def analyze_url_comprehensive(self, url: str) -> Dict:
        """Análisis completo de URL usando múltiples fuentes"""
        results = {
            'url': url,
            'timestamp': self._get_timestamp(),
            'domain_info': await self._analyze_domain(url),
            'ip_reputation': await self._analyze_ip_reputation(url),
            'ssl_certificate': await self._analyze_ssl(url),
            'dns_records': await self._analyze_dns(url),
            'port_scan': await self._port_scan(url),
            'threat_intelligence': await self._threat_intelligence(url),
            'web_technologies': await self._detect_technologies(url),
            'security_headers': await self._check_security_headers(url),
            'malware_scan': await self._malware_scan(url)
        }
        
        # Calcular puntuación de riesgo
        results['risk_score'] = self._calculate_risk_score(results)
        results['risk_level'] = self._get_risk_level(results['risk_score'])
        
        return results
    
    async def _analyze_domain(self, url: str) -> Dict:
        """Análisis de dominio y WHOIS"""
        try:
            domain = urlparse(url).netloc
            
            # WHOIS lookup
            import whois
            domain_info = whois.whois(domain)
            
            return {
                'domain': domain,
                'registrar': getattr(domain_info, 'registrar', None),
                'creation_date': str(getattr(domain_info, 'creation_date', None)),
                'expiration_date': str(getattr(domain_info, 'expiration_date', None)),
                'status': getattr(domain_info, 'status', None),
                'country': getattr(domain_info, 'country', None)
            }
        except Exception as e:
            logger.error(f"Error en análisis de dominio: {e}")
            return {'error': str(e)}
    
    async def _analyze_ip_reputation(self, url: str) -> Dict:
        """Análisis de reputación IP"""
        try:
            domain = urlparse(url).netloc
            ip = socket.gethostbyname(domain)
            
            # Consulta WHOIS de IP
            obj = IPWhois(ip)
            results = obj.lookup_rdap()
            
            return {
                'ip': ip,
                'country': results.get('asn_country_code'),
                'asn': results.get('asn'),
                'asn_description': results.get('asn_description'),
                'network': results.get('network', {}).get('cidr'),
                'abuse_contacts': self._extract_abuse_contacts(results)
            }
        except Exception as e:
            logger.error(f"Error en análisis IP: {e}")
            return {'error': str(e)}
    
    async def _analyze_ssl(self, url: str) -> Dict:
        """Análisis de certificado SSL"""
        try:
            import ssl
            import socket
            from datetime import datetime
            
            domain = urlparse(url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'version': cert['version'],
                'serial_number': cert['serialNumber'],
                'not_before': cert['notBefore'],
                'not_after': cert['notAfter'],
                'signature_algorithm': cert['serialNumber'],
                'is_expired': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') < datetime.now()
            }
        except Exception as e:
            logger.error(f"Error en análisis SSL: {e}")
            return {'error': str(e), 'ssl_enabled': False}
    
    async def _analyze_dns(self, url: str) -> Dict:
        """Análisis de registros DNS"""
        try:
            domain = urlparse(url).netloc
            dns_records = {}
            
            # Consultar diferentes tipos de registros
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except:
                    dns_records[record_type] = []
            
            return dns_records
        except Exception as e:
            logger.error(f"Error en análisis DNS: {e}")
            return {'error': str(e)}
    
    async def _port_scan(self, url: str) -> Dict:
        """Escaneo de puertos básico"""
        try:
            domain = urlparse(url).netloc
            ip = socket.gethostbyname(domain)
            
            # Puertos comunes a escanear
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            return {
                'ip': ip,
                'open_ports': open_ports,
                'total_scanned': len(common_ports),
                'services': self._identify_services(open_ports)
            }
        except Exception as e:
            logger.error(f"Error en escaneo de puertos: {e}")
            return {'error': str(e)}
    
    async def _threat_intelligence(self, url: str) -> Dict:
        """Consulta de inteligencia de amenazas"""
        try:
            # Simulación de consulta a bases de datos de amenazas
            domain = urlparse(url).netloc
            
            # Listas negras conocidas (simuladas)
            threat_feeds = {
                'malware_domains': self._check_malware_domains(domain),
                'phishing_sites': self._check_phishing_sites(domain),
                'botnet_c2': self._check_botnet_c2(domain),
                'reputation_score': self._calculate_domain_reputation(domain)
            }
            
            return threat_feeds
        except Exception as e:
            logger.error(f"Error en threat intelligence: {e}")
            return {'error': str(e)}
    
    async def _detect_technologies(self, url: str) -> Dict:
        """Detección de tecnologías web"""
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'SecurityScanner/1.0'})
            
            technologies = {
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'framework': self._detect_framework(response),
                'cms': self._detect_cms(response),
                'javascript_libraries': self._detect_js_libraries(response),
                'analytics': self._detect_analytics(response)
            }
            
            return technologies
        except Exception as e:
            logger.error(f"Error en detección de tecnologías: {e}")
            return {'error': str(e)}
    
    async def _check_security_headers(self, url: str) -> Dict:
        """Verificación de headers de seguridad"""
        try:
            response = requests.head(url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'strict_transport_security': headers.get('Strict-Transport-Security'),
                'content_security_policy': headers.get('Content-Security-Policy'),
                'x_frame_options': headers.get('X-Frame-Options'),
                'x_content_type_options': headers.get('X-Content-Type-Options'),
                'x_xss_protection': headers.get('X-XSS-Protection'),
                'referrer_policy': headers.get('Referrer-Policy'),
                'feature_policy': headers.get('Feature-Policy')
            }
            
            # Calcular puntuación de seguridad
            security_score = sum(1 for v in security_headers.values() if v is not None)
            security_headers['security_score'] = f"{security_score}/7"
            
            return security_headers
        except Exception as e:
            logger.error(f"Error en verificación de headers: {e}")
            return {'error': str(e)}
    
    async def _malware_scan(self, url: str) -> Dict:
        """Escaneo de malware simulado"""
        try:
            # Simulación de análisis de malware
            # En un entorno real, aquí se integraría con VirusTotal API
            
            suspicious_patterns = [
                'eval(', 'document.write(', 'iframe', 'script src=',
                'base64', 'exec(', 'system(', 'shell_exec('
            ]
            
            response = requests.get(url, timeout=10)
            content = response.text.lower()
            
            detections = []
            for pattern in suspicious_patterns:
                if pattern in content:
                    detections.append(pattern)
            
            return {
                'scan_date': self._get_timestamp(),
                'detections': detections,
                'detection_count': len(detections),
                'risk_level': 'High' if len(detections) > 3 else 'Medium' if len(detections) > 0 else 'Low'
            }
        except Exception as e:
            logger.error(f"Error en escaneo de malware: {e}")
            return {'error': str(e)}
    
    # Métodos auxiliares
    def _get_timestamp(self):
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _extract_abuse_contacts(self, whois_data):
        # Extraer contactos de abuso del WHOIS
        return []
    
    def _identify_services(self, open_ports):
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL'
        }
        return [service_map.get(port, f'Unknown:{port}') for port in open_ports]
    
    def _check_malware_domains(self, domain):
        # Simulación de verificación en listas de malware
        return False
    
    def _check_phishing_sites(self, domain):
        # Simulación de verificación en listas de phishing
        return False
    
    def _check_botnet_c2(self, domain):
        # Simulación de verificación en listas de C&C
        return False
    
    def _calculate_domain_reputation(self, domain):
        # Cálculo simulado de reputación de dominio
        return 75  # Puntuación sobre 100
    
    def _detect_framework(self, response):
        content = response.text.lower()
        if 'django' in content: return 'Django'
        if 'flask' in content: return 'Flask'
        if 'laravel' in content: return 'Laravel'
        if 'react' in content: return 'React'
        return 'Unknown'
    
    def _detect_cms(self, response):
        content = response.text.lower()
        if 'wp-content' in content: return 'WordPress'
        if 'joomla' in content: return 'Joomla'
        if 'drupal' in content: return 'Drupal'
        return 'Unknown'
    
    def _detect_js_libraries(self, response):
        content = response.text.lower()
        libraries = []
        if 'jquery' in content: libraries.append('jQuery')
        if 'bootstrap' in content: libraries.append('Bootstrap')
        if 'angular' in content: libraries.append('Angular')
        return libraries
    
    def _detect_analytics(self, response):
        content = response.text.lower()
        analytics = []
        if 'google-analytics' in content: analytics.append('Google Analytics')
        if 'gtag' in content: analytics.append('Google Tag Manager')
        return analytics
    
    def _calculate_risk_score(self, results):
        score = 0
        
        # SSL
        if results['ssl_certificate'].get('error') or results['ssl_certificate'].get('is_expired'):
            score += 20
        
        # Puertos abiertos
        open_ports = len(results['port_scan'].get('open_ports', []))
        score += min(open_ports * 2, 30)
        
        # Headers de seguridad
        security_score = results['security_headers'].get('security_score', '0/7')
        missing_headers = 7 - int(security_score.split('/')[0])
        score += missing_headers * 3
        
        # Detecciones de malware
        detections = results['malware_scan'].get('detection_count', 0)
        score += detections * 10
        
        return min(score, 100)
    
    def _get_risk_level(self, score):
        if score >= 70: return 'Critical'
        elif score >= 50: return 'High'
        elif score >= 30: return 'Medium'
        else: return 'Low'

