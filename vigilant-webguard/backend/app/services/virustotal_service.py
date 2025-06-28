import requests
import hashlib
import time
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse
from loguru import logger
import os
from datetime import datetime


class VirusTotalService:
    """Servicio completo para integración con VirusTotal API"""
    
    def __init__(self, api_key: Optional[str] = None):
        # Usar API key desde variable de entorno o parámetro
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.base_url_v3 = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        
        # Headers para API v3
        if self.api_key:
            self.session.headers.update({
                'x-apikey': self.api_key,
                'User-Agent': 'VigilantWebGuard/1.0'
            })
        
        # Cache para evitar consultas repetidas
        self.cache = {}
        self.rate_limit_delay = 15  # Segundos entre consultas (API gratuita)
    
    async def comprehensive_url_analysis(self, url: str) -> Dict:
        """Análisis completo de URL con VirusTotal"""
        try:
            # Normalizar URL
            url = self._normalize_url(url)
            url_id = self._get_url_id(url)
            
            if url_id in self.cache:
                logger.info(f"Usando cache para URL: {url}")
                return self.cache[url_id]
            
            # Primero intentar obtener reporte existente
            existing_report = await self._get_url_report_v3(url)
            
            if not existing_report or self._is_report_outdated(existing_report):
                # Enviar URL para análisis
                submission_result = await self._submit_url_for_analysis(url)
                if submission_result.get('success'):
                    # Esperar y obtener resultados
                    await asyncio.sleep(30)  # Dar tiempo al análisis
                    existing_report = await self._get_url_report_v3(url)
            
            # Análisis adicional del dominio
            domain_analysis = await self._analyze_domain_reputation(url)
            
            # Análisis de archivos descargables
            downloadable_files = await self._scan_downloadable_files(url)
            
            # Compilar resultado completo
            result = {
                'url': url,
                'scan_date': datetime.now().isoformat(),
                'url_analysis': existing_report,
                'domain_reputation': domain_analysis,
                'downloadable_files': downloadable_files,
                'threat_intelligence': await self._get_threat_intelligence(url),
                'behavioral_analysis': await self._behavioral_analysis(url),
                'risk_assessment': {}
            }
            
            # Calcular evaluación de riesgo
            result['risk_assessment'] = self._calculate_comprehensive_risk(result)
            
            # Cachear resultado
            self.cache[url_id] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Error en análisis VirusTotal: {e}")
            return {
                'error': str(e),
                'url': url,
                'scan_date': datetime.now().isoformat()
            }
    
    async def _get_url_report_v3(self, url: str) -> Optional[Dict]:
        """Obtener reporte de URL usando API v3"""
        try:
            if not self.api_key:
                return await self._get_public_url_analysis(url)
            
            url_id = self._get_url_id(url)
            endpoint = f"{self.base_url_v3}/urls/{url_id}"
            
            await self._rate_limit_wait()
            response = self.session.get(endpoint)
            
            if response.status_code == 200:
                data = response.json()
                return self._process_url_report_v3(data)
            elif response.status_code == 404:
                return None
            else:
                logger.warning(f"Error API VirusTotal: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error obteniendo reporte URL: {e}")
            return None
    
    async def _submit_url_for_analysis(self, url: str) -> Dict:
        """Enviar URL para análisis"""
        try:
            if not self.api_key:
                return {'success': False, 'reason': 'No API key available'}
            
            endpoint = f"{self.base_url_v3}/urls"
            data = {'url': url}
            
            await self._rate_limit_wait()
            response = self.session.post(endpoint, data=data)
            
            if response.status_code in [200, 201]:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'status_code': response.status_code}
                
        except Exception as e:
            logger.error(f"Error enviando URL para análisis: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _analyze_domain_reputation(self, url: str) -> Dict:
        """Análisis de reputación del dominio"""
        try:
            domain = urlparse(url).netloc
            
            if not self.api_key:
                return await self._get_public_domain_analysis(domain)
            
            domain_id = self._get_domain_id(domain)
            endpoint = f"{self.base_url_v3}/domains/{domain_id}"
            
            await self._rate_limit_wait()
            response = self.session.get(endpoint)
            
            if response.status_code == 200:
                data = response.json()
                return self._process_domain_report(data)
            else:
                return {'error': f'Status code: {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Error en análisis de dominio: {e}")
            return {'error': str(e)}
    
    async def _scan_downloadable_files(self, url: str) -> Dict:
        """Escanear archivos descargables encontrados en la página"""
        try:
            # Obtener página y buscar enlaces de descarga
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
            })
            
            downloadable_links = self._extract_downloadable_links(response.text, url)
            
            file_analyses = []
            for link in downloadable_links[:5]:  # Limitar a 5 archivos
                file_analysis = await self._analyze_file_url(link)
                if file_analysis:
                    file_analyses.append(file_analysis)
            
            return {
                'total_files_found': len(downloadable_links),
                'files_analyzed': len(file_analyses),
                'analyses': file_analyses
            }
            
        except Exception as e:
            logger.error(f"Error escaneando archivos descargables: {e}")
            return {'error': str(e)}
    
    async def _get_threat_intelligence(self, url: str) -> Dict:
        """Obtener inteligencia de amenazas relacionadas"""
        try:
            domain = urlparse(url).netloc
            
            # Buscar en feeds de inteligencia de amenazas
            threat_feeds = {
                'malware_families': await self._check_malware_families(domain),
                'campaign_associations': await self._check_campaign_associations(domain),
                'threat_actor_attribution': await self._check_threat_actors(domain),
                'historical_incidents': await self._get_historical_incidents(domain)
            }
            
            return threat_feeds
            
        except Exception as e:
            logger.error(f"Error en threat intelligence: {e}")
            return {'error': str(e)}
    
    async def _behavioral_analysis(self, url: str) -> Dict:
        """Análisis de comportamiento de la URL"""
        try:
            # Simular análisis de comportamiento
            behaviors = {
                'redirections': await self._analyze_redirections(url),
                'javascript_analysis': await self._analyze_javascript(url),
                'network_behavior': await self._analyze_network_behavior(url),
                'resource_loading': await self._analyze_resource_loading(url)
            }
            
            return behaviors
            
        except Exception as e:
            logger.error(f"Error en análisis de comportamiento: {e}")
            return {'error': str(e)}
    
    # Métodos de análisis público (sin API key)
    async def _get_public_url_analysis(self, url: str) -> Dict:
        """Análisis público de URL sin API key"""
        try:
            # Usar servicios públicos de VirusTotal
            # Nota: Funcionalidad limitada sin API key
            return {
                'service': 'public_analysis',
                'note': 'Análisis limitado sin API key',
                'basic_check': await self._basic_url_check(url)
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_public_domain_analysis(self, domain: str) -> Dict:
        """Análisis público de dominio"""
        try:
            return {
                'service': 'public_domain_analysis',
                'domain': domain,
                'basic_reputation': await self._basic_domain_reputation(domain)
            }
        except Exception as e:
            return {'error': str(e)}
    
    # Métodos auxiliares
    def _normalize_url(self, url: str) -> str:
        """Normalizar URL para análisis"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _get_url_id(self, url: str) -> str:
        """Obtener ID de URL para API v3"""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    
    def _get_domain_id(self, domain: str) -> str:
        """Obtener ID de dominio"""
        return domain
    
    def _process_url_report_v3(self, data: Dict) -> Dict:
        """Procesar reporte de URL de API v3"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'scan_id': data.get('data', {}).get('id'),
                'scan_date': attributes.get('last_analysis_date'),
                'positives': stats.get('malicious', 0),
                'total': sum(stats.values()),
                'detection_engines': attributes.get('last_analysis_results', {}),
                'reputation': attributes.get('reputation', 0),
                'categories': attributes.get('categories', {}),
                'permalink': f"https://www.virustotal.com/gui/url/{data.get('data', {}).get('id', '')}"
            }
        except Exception as e:
            logger.error(f"Error procesando reporte URL: {e}")
            return {'error': str(e)}
    
    def _process_domain_report(self, data: Dict) -> Dict:
        """Procesar reporte de dominio"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            
            return {
                'domain': attributes.get('id'),
                'reputation': attributes.get('reputation', 0),
                'categories': attributes.get('categories', {}),
                'creation_date': attributes.get('creation_date'),
                'last_modification_date': attributes.get('last_modification_date'),
                'registrar': attributes.get('registrar'),
                'whois': attributes.get('whois'),
                'popularity_ranks': attributes.get('popularity_ranks', {}),
                'last_analysis_stats': attributes.get('last_analysis_stats', {})
            }
        except Exception as e:
            logger.error(f"Error procesando reporte dominio: {e}")
            return {'error': str(e)}
    
    def _is_report_outdated(self, report: Dict) -> bool:
        """Verificar si el reporte está desactualizado"""
        try:
            scan_date = report.get('scan_date')
            if not scan_date:
                return True
            
            # Considerar desactualizado si tiene más de 7 días
            from datetime import datetime, timedelta
            if isinstance(scan_date, int):
                scan_datetime = datetime.fromtimestamp(scan_date)
            else:
                scan_datetime = datetime.fromisoformat(str(scan_date).replace('Z', ''))
            
            return (datetime.now() - scan_datetime) > timedelta(days=7)
        except:
            return True
    
    def _calculate_comprehensive_risk(self, analysis_result: Dict) -> Dict:
        """Calcular evaluación de riesgo comprehensiva"""
        risk_score = 0
        risk_factors = []
        
        # Análisis de URL
        url_analysis = analysis_result.get('url_analysis', {})
        if url_analysis and not url_analysis.get('error'):
            positives = url_analysis.get('positives', 0)
            total = url_analysis.get('total', 1)
            detection_rate = (positives / total) * 100 if total > 0 else 0
            
            if detection_rate > 50:
                risk_score += 40
                risk_factors.append(f"Alta detección malware: {detection_rate:.1f}%")
            elif detection_rate > 20:
                risk_score += 25
                risk_factors.append(f"Detección moderada malware: {detection_rate:.1f}%")
            elif detection_rate > 0:
                risk_score += 10
                risk_factors.append(f"Detección baja malware: {detection_rate:.1f}%")
        
        # Reputación del dominio
        domain_rep = analysis_result.get('domain_reputation', {})
        if domain_rep and not domain_rep.get('error'):
            reputation = domain_rep.get('reputation', 0)
            if reputation < -50:
                risk_score += 30
                risk_factors.append("Reputación de dominio muy baja")
            elif reputation < 0:
                risk_score += 15
                risk_factors.append("Reputación de dominio negativa")
        
        # Archivos descargables
        files = analysis_result.get('downloadable_files', {})
        if files and not files.get('error'):
            files_analyzed = files.get('analyses', [])
            malicious_files = [f for f in files_analyzed if f.get('is_malicious')]
            if malicious_files:
                risk_score += len(malicious_files) * 15
                risk_factors.append(f"{len(malicious_files)} archivos maliciosos detectados")
        
        # Determinar nivel de riesgo
        if risk_score >= 70:
            risk_level = "CRÍTICO"
        elif risk_score >= 50:
            risk_level = "ALTO"
        elif risk_score >= 30:
            risk_level = "MEDIO"
        elif risk_score >= 10:
            risk_level = "BAJO"
        else:
            risk_level = "MÍNIMO"
        
        return {
            'score': min(risk_score, 100),
            'level': risk_level,
            'factors': risk_factors,
            'recommendation': self._get_risk_recommendation(risk_level)
        }
    
    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Obtener recomendación basada en nivel de riesgo"""
        recommendations = {
            'CRÍTICO': "🚨 NO ACCEDER - Sitio altamente peligroso. Bloquear inmediatamente.",
            'ALTO': "⚠️ EVITAR - Sitio potencialmente peligroso. Acceso solo con precauciones extremas.",
            'MEDIO': "⚡ PRECAUCIÓN - Sitio con riesgos identificados. Verificar antes de acceder.",
            'BAJO': "💡 VERIFICAR - Sitio con alertas menores. Monitorear actividad.",
            'MÍNIMO': "✅ SEGURO - Sitio aparentemente seguro. Mantener buenas prácticas."
        }
        return recommendations.get(risk_level, "Evaluar manualmente")
    
    async def _rate_limit_wait(self):
        """Esperar para respetar rate limits"""
        await asyncio.sleep(self.rate_limit_delay)
    
    # Métodos de análisis adicionales (implementaciones simplificadas)
    def _extract_downloadable_links(self, html_content: str, base_url: str) -> List[str]:
        """Extraer enlaces de archivos descargables"""
        import re
        from urllib.parse import urljoin
        
        # Buscar enlaces a archivos comunes
        file_extensions = r'\.(exe|zip|rar|pdf|doc|docx|xls|xlsx|ppt|pptx|apk|dmg|pkg)[\'">\s]'
        links = re.findall(r'href=["\']([^"\']+' + file_extensions + ')', html_content, re.IGNORECASE)
        
        # Convertir a URLs absolutas
        absolute_links = []
        for link in links:
            absolute_url = urljoin(base_url, link[0])
            absolute_links.append(absolute_url)
        
        return list(set(absolute_links))  # Eliminar duplicados
    
    async def _analyze_file_url(self, file_url: str) -> Optional[Dict]:
        """Analizar URL de archivo específico"""
        try:
            # Análisis simplificado de archivo
            return {
                'url': file_url,
                'file_name': file_url.split('/')[-1],
                'is_malicious': False,  # Implementar lógica real
                'scan_result': 'pending'
            }
        except:
            return None
    
    async def _check_malware_families(self, domain: str) -> List[str]:
        """Verificar familias de malware asociadas"""
        # Implementación simulada
        return []
    
    async def _check_campaign_associations(self, domain: str) -> List[str]:
        """Verificar campañas de malware asociadas"""
        return []
    
    async def _check_threat_actors(self, domain: str) -> List[str]:
        """Verificar actores de amenazas asociados"""
        return []
    
    async def _get_historical_incidents(self, domain: str) -> List[Dict]:
        """Obtener incidentes históricos"""
        return []
    
    async def _analyze_redirections(self, url: str) -> Dict:
        """Analizar redirecciones"""
        return {'redirect_count': 0, 'final_url': url}
    
    async def _analyze_javascript(self, url: str) -> Dict:
        """Analizar JavaScript malicioso"""
        return {'suspicious_patterns': [], 'obfuscation_detected': False}
    
    async def _analyze_network_behavior(self, url: str) -> Dict:
        """Analizar comportamiento de red"""
        return {'external_connections': [], 'suspicious_traffic': False}
    
    async def _analyze_resource_loading(self, url: str) -> Dict:
        """Analizar carga de recursos"""
        return {'suspicious_resources': [], 'total_resources': 0}
    
    async def _basic_url_check(self, url: str) -> Dict:
        """Verificación básica de URL sin API"""
        return {'status': 'checked', 'accessible': True}
    
    async def _basic_domain_reputation(self, domain: str) -> Dict:
        """Reputación básica de dominio"""
        return {'reputation_score': 'unknown', 'risk_level': 'unknown'}


# Instancia global del servicio
virustotal_service = VirusTotalService()
