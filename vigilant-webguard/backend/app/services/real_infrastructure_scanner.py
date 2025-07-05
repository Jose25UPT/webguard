import asyncio
import aiohttp
import socket
import ssl
import dns.resolver
import whois
import subprocess
import json
import re
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from loguru import logger
import ipaddress
from ipwhois import IPWhois

class RealInfrastructureScanner:
    """Escáner de infraestructura real que hace escaneos reales de sitios web"""
    
    def __init__(self):
        self.session = None
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
    
    async def initialize(self):
        """Inicializar el escáner"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.user_agents[0]}
        )
    
    async def scan_full_infrastructure(self, target_url: str) -> Dict[str, Any]:
        """Escaneo completo de infraestructura"""
        logger.info(f"🔍 Iniciando escaneo completo de infraestructura para: {target_url}")
        
        # Parsear URL
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path
        
        # Limpiar dominio
        domain = domain.split(':')[0]  # Remover puerto si existe
        
        result = {
            'target_url': target_url,
            'domain': domain,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'infrastructure': {}
        }
        
        try:
            # Ejecutar todos los escaneos en paralelo
            tasks = [
                self.scan_dns_info(domain),
                self.scan_whois_info(domain),
                self.scan_ssl_info(domain),
                self.scan_http_headers(target_url),
                self.scan_server_info(target_url),
                self.scan_network_info(domain),
                self.scan_cdn_info(target_url),
                self.scan_security_headers(target_url),
                self.scan_technology_stack(target_url),
                self.scan_ip_geolocation(domain)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Procesar resultados
            scan_methods = [
                'dns', 'whois', 'ssl', 'http_headers', 'server_info',
                'network', 'cdn', 'security_headers', 'technology_stack', 'ip_geolocation'
            ]
            
            for i, scan_result in enumerate(results):
                method_name = scan_methods[i]
                if isinstance(scan_result, Exception):
                    logger.error(f"Error en {method_name}: {scan_result}")
                    result['infrastructure'][method_name] = {
                        'error': str(scan_result),
                        'status': 'failed'
                    }
                else:
                    result['infrastructure'][method_name] = scan_result
            
            # Generar resumen
            result['summary'] = self.generate_infrastructure_summary(result['infrastructure'])
            
            logger.info(f"✅ Escaneo de infraestructura completado para {domain}")
            return result
            
        except Exception as e:
            logger.error(f"Error en escaneo de infraestructura: {e}")
            result['infrastructure']['error'] = str(e)
            return result
    
    async def scan_dns_info(self, domain: str) -> Dict[str, Any]:
        """Escanear información DNS"""
        logger.info(f"🔍 Escaneando DNS para: {domain}")
        
        dns_info = {
            'domain': domain,
            'records': {},
            'nameservers': [],
            'status': 'success'
        }
        
        try:
            # Resolver diferentes tipos de registros DNS
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records = []
                    for answer in answers:
                        records.append(str(answer))
                    dns_info['records'][record_type] = records
                except dns.resolver.NoAnswer:
                    dns_info['records'][record_type] = []
                except Exception as e:
                    dns_info['records'][record_type] = {'error': str(e)}
            
            # Obtener nameservers
            try:
                ns_answers = dns.resolver.resolve(domain, 'NS')
                dns_info['nameservers'] = [str(ns) for ns in ns_answers]
            except:
                dns_info['nameservers'] = []
            
            return dns_info
            
        except Exception as e:
            logger.error(f"Error escaneando DNS: {e}")
            dns_info['status'] = 'failed'
            dns_info['error'] = str(e)
            return dns_info
    
    async def scan_whois_info(self, domain: str) -> Dict[str, Any]:
        """Escanear información WHOIS"""
        logger.info(f"🔍 Escaneando WHOIS para: {domain}")
        
        whois_info = {
            'domain': domain,
            'status': 'success',
            'data': {}
        }
        
        try:
            # Ejecutar WHOIS en un hilo separado
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, whois.whois, domain)
            
            if whois_data:
                # Convertir a diccionario serializable
                whois_dict = {}
                for key, value in whois_data.items():
                    if isinstance(value, (str, int, float, bool, type(None))):
                        whois_dict[key] = value
                    elif isinstance(value, list):
                        whois_dict[key] = [str(item) for item in value]
                    else:
                        whois_dict[key] = str(value)
                
                whois_info['data'] = whois_dict
                
                # Extraer información clave
                whois_info['registrar'] = whois_dict.get('registrar', 'Unknown')
                whois_info['creation_date'] = str(whois_dict.get('creation_date', 'Unknown'))
                whois_info['expiration_date'] = str(whois_dict.get('expiration_date', 'Unknown'))
                whois_info['name_servers'] = whois_dict.get('name_servers', [])
            
            return whois_info
            
        except Exception as e:
            logger.error(f"Error escaneando WHOIS: {e}")
            whois_info['status'] = 'failed'
            whois_info['error'] = str(e)
            return whois_info
    
    async def scan_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Escanear información SSL/TLS"""
        logger.info(f"🔍 Escaneando SSL para: {domain}")
        
        ssl_info = {
            'domain': domain,
            'status': 'success',
            'certificate': {},
            'cipher_suites': [],
            'vulnerabilities': []
        }
        
        try:
            # Obtener certificado SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Conectar y obtener certificado
            loop = asyncio.get_event_loop()
            
            def get_ssl_cert():
                try:
                    with socket.create_connection((domain, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            return cert, cipher
                except Exception as e:
                    return None, None
            
            cert, cipher = await loop.run_in_executor(None, get_ssl_cert)
            
            if cert:
                ssl_info['certificate'] = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'signature_algorithm': cert.get('signatureAlgorithm'),
                    'san': cert.get('subjectAltName', [])
                }
                
                if cipher:
                    ssl_info['cipher_suites'] = list(cipher)
                
                # Verificar vulnerabilidades básicas
                ssl_info['vulnerabilities'] = self.check_ssl_vulnerabilities(cert, cipher)
            
            return ssl_info
            
        except Exception as e:
            logger.error(f"Error escaneando SSL: {e}")
            ssl_info['status'] = 'failed'
            ssl_info['error'] = str(e)
            return ssl_info
    
    async def scan_http_headers(self, target_url: str) -> Dict[str, Any]:
        """Escanear headers HTTP"""
        logger.info(f"🔍 Escaneando headers HTTP para: {target_url}")
        
        headers_info = {
            'url': target_url,
            'status': 'success',
            'response_headers': {},
            'status_code': 0,
            'redirect_chain': []
        }
        
        try:
            # Hacer petición HTTP
            async with self.session.get(target_url, allow_redirects=True) as response:
                headers_info['status_code'] = response.status
                headers_info['response_headers'] = dict(response.headers)
                
                # Obtener cadena de redirecciones
                if hasattr(response, 'history'):
                    for hist in response.history:
                        headers_info['redirect_chain'].append({
                            'url': str(hist.url),
                            'status': hist.status,
                            'headers': dict(hist.headers)
                        })
                
                # Analizar headers de seguridad
                headers_info['security_analysis'] = self.analyze_security_headers(dict(response.headers))
            
            return headers_info
            
        except Exception as e:
            logger.error(f"Error escaneando headers HTTP: {e}")
            headers_info['status'] = 'failed'
            headers_info['error'] = str(e)
            return headers_info
    
    async def scan_server_info(self, target_url: str) -> Dict[str, Any]:
        """Escanear información del servidor"""
        logger.info(f"🔍 Escaneando información del servidor para: {target_url}")
        
        server_info = {
            'url': target_url,
            'status': 'success',
            'server_software': 'Unknown',
            'powered_by': 'Unknown',
            'response_time': 0,
            'server_location': 'Unknown'
        }
        
        try:
            start_time = time.time()
            
            async with self.session.get(target_url) as response:
                server_info['response_time'] = time.time() - start_time
                
                # Extraer información del servidor
                headers = dict(response.headers)
                server_info['server_software'] = headers.get('Server', 'Unknown')
                server_info['powered_by'] = headers.get('X-Powered-By', 'Unknown')
                
                # Obtener contenido para análisis adicional
                content = await response.text()
                server_info['content_type'] = headers.get('Content-Type', 'Unknown')
                server_info['content_length'] = len(content)
                
                # Detectar tecnologías basadas en el contenido
                server_info['detected_technologies'] = self.detect_technologies_from_content(content)
            
            return server_info
            
        except Exception as e:
            logger.error(f"Error escaneando servidor: {e}")
            server_info['status'] = 'failed'
            server_info['error'] = str(e)
            return server_info
    
    async def scan_network_info(self, domain: str) -> Dict[str, Any]:
        """Escanear información de red"""
        logger.info(f"🔍 Escaneando información de red para: {domain}")
        
        network_info = {
            'domain': domain,
            'status': 'success',
            'ip_addresses': [],
            'open_ports': [],
            'traceroute': []
        }
        
        try:
            # Resolver IPs
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                network_info['ip_addresses'] = ips
            except:
                network_info['ip_addresses'] = []
            
            # Escanear puertos comunes
            if network_info['ip_addresses']:
                main_ip = network_info['ip_addresses'][0]
                network_info['open_ports'] = await self.scan_common_ports(main_ip)
            
            return network_info
            
        except Exception as e:
            logger.error(f"Error escaneando red: {e}")
            network_info['status'] = 'failed'
            network_info['error'] = str(e)
            return network_info
    
    async def scan_cdn_info(self, target_url: str) -> Dict[str, Any]:
        """Detectar CDN y servicios de nube"""
        logger.info(f"🔍 Detectando CDN para: {target_url}")
        
        cdn_info = {
            'url': target_url,
            'status': 'success',
            'cdn_detected': False,
            'cdn_provider': 'Unknown',
            'cloud_services': []
        }
        
        try:
            async with self.session.get(target_url) as response:
                headers = dict(response.headers)
                
                # Detectar CDN basado en headers
                cdn_indicators = {
                    'Cloudflare': ['CF-RAY', 'CF-Cache-Status', 'CF-Request-ID'],
                    'AWS CloudFront': ['X-Amz-Cf-Id', 'X-Amz-Cf-Pop'],
                    'Fastly': ['Fastly-Debug-Digest', 'X-Served-By'],
                    'KeyCDN': ['X-Edge-Location', 'X-Cache'],
                    'MaxCDN': ['X-MaxCDN-Cache'],
                    'Azure CDN': ['X-Azure-Ref', 'X-Ms-Edge-Location']
                }
                
                for cdn_name, indicators in cdn_indicators.items():
                    for indicator in indicators:
                        if indicator in headers:
                            cdn_info['cdn_detected'] = True
                            cdn_info['cdn_provider'] = cdn_name
                            break
                
                # Detectar servicios de nube adicionales
                cloud_indicators = {
                    'AWS': ['X-Amz-', 'X-Amazon-'],
                    'Google Cloud': ['X-Google-', 'X-Goog-'],
                    'Azure': ['X-Azure-', 'X-Ms-'],
                    'Heroku': ['X-Heroku-']
                }
                
                for cloud_name, indicators in cloud_indicators.items():
                    for indicator in indicators:
                        for header in headers:
                            if header.startswith(indicator):
                                if cloud_name not in cdn_info['cloud_services']:
                                    cdn_info['cloud_services'].append(cloud_name)
            
            return cdn_info
            
        except Exception as e:
            logger.error(f"Error detectando CDN: {e}")
            cdn_info['status'] = 'failed'
            cdn_info['error'] = str(e)
            return cdn_info
    
    async def scan_security_headers(self, target_url: str) -> Dict[str, Any]:
        """Analizar headers de seguridad"""
        logger.info(f"🔍 Analizando headers de seguridad para: {target_url}")
        
        security_info = {
            'url': target_url,
            'status': 'success',
            'security_score': 0,
            'security_headers': {},
            'recommendations': []
        }
        
        try:
            async with self.session.get(target_url) as response:
                headers = dict(response.headers)
                
                # Headers de seguridad importantes
                security_headers = {
                    'Strict-Transport-Security': 'HSTS',
                    'Content-Security-Policy': 'CSP',
                    'X-Content-Type-Options': 'X-Content-Type-Options',
                    'X-Frame-Options': 'X-Frame-Options',
                    'X-XSS-Protection': 'X-XSS-Protection',
                    'Referrer-Policy': 'Referrer-Policy',
                    'Permissions-Policy': 'Permissions-Policy'
                }
                
                score = 0
                for header, description in security_headers.items():
                    if header in headers:
                        security_info['security_headers'][header] = {
                            'present': True,
                            'value': headers[header],
                            'description': description
                        }
                        score += 1
                    else:
                        security_info['security_headers'][header] = {
                            'present': False,
                            'description': description
                        }
                        security_info['recommendations'].append(f"Consider adding {header} header")
                
                security_info['security_score'] = (score / len(security_headers)) * 100
            
            return security_info
            
        except Exception as e:
            logger.error(f"Error analizando headers de seguridad: {e}")
            security_info['status'] = 'failed'
            security_info['error'] = str(e)
            return security_info
    
    async def scan_technology_stack(self, target_url: str) -> Dict[str, Any]:
        """Detectar stack tecnológico"""
        logger.info(f"🔍 Detectando stack tecnológico para: {target_url}")
        
        tech_info = {
            'url': target_url,
            'status': 'success',
            'technologies': [],
            'frameworks': [],
            'cms': [],
            'programming_languages': []
        }
        
        try:
            async with self.session.get(target_url) as response:
                headers = dict(response.headers)
                content = await response.text()
                
                # Detectar tecnologías basadas en headers
                tech_headers = {
                    'X-Powered-By': 'Server Technology',
                    'Server': 'Web Server',
                    'X-Generator': 'CMS/Framework',
                    'X-Drupal-Dynamic-Cache': 'Drupal',
                    'X-Pingback': 'WordPress'
                }
                
                for header, tech_type in tech_headers.items():
                    if header in headers:
                        tech_info['technologies'].append({
                            'name': headers[header],
                            'type': tech_type,
                            'source': 'HTTP Header'
                        })
                
                # Detectar tecnologías basadas en contenido
                content_patterns = {
                    'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
                    'Drupal': [r'drupal', r'sites/default', r'/core/'],
                    'Joomla': [r'joomla', r'/templates/', r'/modules/'],
                    'React': [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                    'Vue.js': [r'vue', r'Vue.js'],
                    'Angular': [r'angular', r'ng-'],
                    'jQuery': [r'jquery', r'jQuery'],
                    'Bootstrap': [r'bootstrap', r'Bootstrap'],
                    'Laravel': [r'laravel', r'_token'],
                    'Django': [r'django', r'csrftoken'],
                    'Flask': [r'flask', r'Werkzeug'],
                    'Express': [r'express', r'X-Powered-By.*Express']
                }
                
                for tech_name, patterns in content_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            tech_info['technologies'].append({
                                'name': tech_name,
                                'type': 'Framework/CMS',
                                'source': 'Content Analysis'
                            })
                            break
            
            return tech_info
            
        except Exception as e:
            logger.error(f"Error detectando stack tecnológico: {e}")
            tech_info['status'] = 'failed'
            tech_info['error'] = str(e)
            return tech_info
    
    async def scan_ip_geolocation(self, domain: str) -> Dict[str, Any]:
        """Obtener geolocalización de IP"""
        logger.info(f"🔍 Obteniendo geolocalización para: {domain}")
        
        geo_info = {
            'domain': domain,
            'status': 'success',
            'ip_address': '',
            'location': {},
            'isp': '',
            'organization': ''
        }
        
        try:
            # Resolver IP
            ip_address = socket.gethostbyname(domain)
            geo_info['ip_address'] = ip_address
            
            # Obtener información de WHOIS IP
            obj = IPWhois(ip_address)
            whois_data = obj.lookup_rdap()
            
            if whois_data:
                geo_info['isp'] = whois_data.get('network', {}).get('name', 'Unknown')
                geo_info['organization'] = whois_data.get('network', {}).get('remarks', [{}])[0].get('description', 'Unknown')
                
                # Información de red
                geo_info['network_info'] = {
                    'cidr': whois_data.get('network', {}).get('cidr', ''),
                    'country': whois_data.get('network', {}).get('country', ''),
                    'start_address': whois_data.get('network', {}).get('start_address', ''),
                    'end_address': whois_data.get('network', {}).get('end_address', '')
                }
            
            return geo_info
            
        except Exception as e:
            logger.error(f"Error obteniendo geolocalización: {e}")
            geo_info['status'] = 'failed'
            geo_info['error'] = str(e)
            return geo_info
    
    async def scan_common_ports(self, ip_address: str) -> List[int]:
        """Escanear puertos comunes"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        open_ports = []
        
        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip_address, port),
                    timeout=5
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        tasks = [check_port(port) for port in common_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                open_ports.append(result)
        
        return open_ports
    
    def check_ssl_vulnerabilities(self, cert: Dict, cipher: tuple) -> List[str]:
        """Verificar vulnerabilidades SSL básicas"""
        vulnerabilities = []
        
        # Verificar algoritmos débiles
        if cipher and len(cipher) >= 2:
            if any(weak in cipher[1] for weak in ['DES', 'MD5', 'SHA1']):
                vulnerabilities.append("Weak cipher algorithm detected")
        
        # Verificar longitud de clave
        if cert.get('version', 0) < 3:
            vulnerabilities.append("Certificate version is outdated")
        
        return vulnerabilities
    
    def analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analizar headers de seguridad"""
        analysis = {
            'score': 0,
            'max_score': 7,
            'missing_headers': [],
            'present_headers': []
        }
        
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        
        for header in security_headers:
            if header in headers:
                analysis['score'] += 1
                analysis['present_headers'].append(header)
            else:
                analysis['missing_headers'].append(header)
        
        return analysis
    
    def detect_technologies_from_content(self, content: str) -> List[str]:
        """Detectar tecnologías basadas en el contenido"""
        technologies = []
        
        patterns = {
            'WordPress': r'wp-content|wp-includes',
            'Drupal': r'drupal|sites/default',
            'Joomla': r'joomla|/templates/',
            'React': r'react|__REACT_DEVTOOLS_GLOBAL_HOOK__',
            'Vue.js': r'vue|Vue\.js',
            'Angular': r'angular|ng-',
            'jQuery': r'jquery|jQuery',
            'Bootstrap': r'bootstrap|Bootstrap'
        }
        
        for tech, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies.append(tech)
        
        return technologies
    
    def generate_infrastructure_summary(self, infrastructure: Dict[str, Any]) -> Dict[str, Any]:
        """Generar resumen de infraestructura"""
        summary = {
            'total_checks': 0,
            'successful_checks': 0,
            'failed_checks': 0,
            'key_findings': [],
            'risk_level': 'low',
            'recommendations': []
        }
        
        for scan_type, scan_data in infrastructure.items():
            summary['total_checks'] += 1
            
            if isinstance(scan_data, dict):
                if scan_data.get('status') == 'success':
                    summary['successful_checks'] += 1
                else:
                    summary['failed_checks'] += 1
        
        # Calcular nivel de riesgo
        if summary['failed_checks'] > summary['successful_checks']:
            summary['risk_level'] = 'high'
        elif summary['failed_checks'] > 0:
            summary['risk_level'] = 'medium'
        
        # Generar recomendaciones básicas
        if 'security_headers' in infrastructure:
            sec_headers = infrastructure['security_headers']
            if sec_headers.get('security_score', 0) < 50:
                summary['recommendations'].append("Implement missing security headers")
        
        return summary
    
    async def close(self):
        """Cerrar conexiones"""
        if self.session:
            await self.session.close()

# Instancia global
real_infrastructure_scanner = RealInfrastructureScanner()
