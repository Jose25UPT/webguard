import time
import asyncio
import psutil
from datetime import datetime
from typing import Dict, Any, List
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import os
import logging

logger = logging.getLogger(__name__)

class MetricsService:
    def __init__(self):
        self.influx_client = None
        self.write_api = None
        self.query_api = None
        self.bucket = "security_metrics"
        self.org = "webguard"
        self.token = "webguard-super-secret-auth-token"
        self.url = "http://localhost:8086"
        
        # Métricas en memoria para cuando InfluxDB no esté disponible
        self.in_memory_metrics = {
            'vulnerabilities': [],
            'scans': [],
            'attacks': [],
            'requests': [],
            'system': []
        }
        
        self._initialize_influx()
    
    def _initialize_influx(self):
        """Inicializar conexión a InfluxDB"""
        try:
            self.influx_client = InfluxDBClient(
                url=self.url,
                token=self.token,
                org=self.org
            )
            self.write_api = self.influx_client.write_api(write_options=SYNCHRONOUS)
            self.query_api = self.influx_client.query_api()
            logger.info("InfluxDB conectado exitosamente")
            
            # Verificar la conexión
            self.query_api.query('buckets()')
            
        except Exception as e:
            logger.warning(f"No se pudo conectar a InfluxDB: {e}. Usando métricas en memoria.")
            self.influx_client = None
    
    def write_vulnerability_metric(self, severity: str, category: str, count: int = 1, target_url: str = None):
        """Escribir métrica de vulnerabilidad"""
        point = Point("vulnerabilities") \
            .tag("severity", severity) \
            .tag("category", category) \
            .field("count", count) \
            .time(datetime.utcnow(), WritePrecision.NS)
        
        if target_url:
            point = point.tag("target", target_url)
        
        self._write_point(point)
        
        # También guardar en memoria
        self.in_memory_metrics['vulnerabilities'].append({
            'timestamp': datetime.utcnow().isoformat(),
            'severity': severity,
            'category': category,
            'count': count,
            'target': target_url
        })
    
    def write_scan_metric(self, status: str, tool: str, duration: float = None, target_url: str = None):
        """Escribir métrica de escaneo"""
        point = Point("scans") \
            .tag("status", status) \
            .tag("tool", tool) \
            .field("count", 1) \
            .time(datetime.utcnow(), WritePrecision.NS)
        
        if duration:
            point = point.field("duration", duration)
        if target_url:
            point = point.tag("target", target_url)
        
        self._write_point(point)
        
        # También guardar en memoria
        self.in_memory_metrics['scans'].append({
            'timestamp': datetime.utcnow().isoformat(),
            'status': status,
            'tool': tool,
            'duration': duration,
            'target': target_url
        })
    
    def write_attack_metric(self, attack_type: str, status: str, target_url: str = None, 
                          intensity: str = None, requests_sent: int = None):
        """Escribir métrica de ataque"""
        point = Point("attacks") \
            .tag("type", attack_type) \
            .tag("status", status) \
            .field("count", 1) \
            .time(datetime.utcnow(), WritePrecision.NS)
        
        if target_url:
            point = point.tag("target", target_url)
        if intensity:
            point = point.tag("intensity", intensity)
        if requests_sent:
            point = point.field("requests_sent", requests_sent)
        
        self._write_point(point)
        
        # También guardar en memoria
        self.in_memory_metrics['attacks'].append({
            'timestamp': datetime.utcnow().isoformat(),
            'type': attack_type,
            'status': status,
            'target': target_url,
            'intensity': intensity,
            'requests_sent': requests_sent
        })
    
    def write_request_metric(self, endpoint: str, method: str, status_code: int, 
                           response_time: float = None, user_agent: str = None):
        """Escribir métrica de request HTTP"""
        point = Point("requests") \
            .tag("endpoint", endpoint) \
            .tag("method", method) \
            .tag("status_code", str(status_code)) \
            .field("count", 1) \
            .time(datetime.utcnow(), WritePrecision.NS)
        
        if response_time:
            point = point.field("response_time", response_time)
        if user_agent:
            point = point.tag("user_agent", user_agent)
        
        self._write_point(point)
        
        # También guardar en memoria
        self.in_memory_metrics['requests'].append({
            'timestamp': datetime.utcnow().isoformat(),
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'response_time': response_time,
            'user_agent': user_agent
        })
    
    def write_system_metrics(self):
        """Escribir métricas del sistema"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memoria
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used = memory.used
            memory_total = memory.total
            
            # Disco
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Red
            net_io = psutil.net_io_counters()
            
            # Procesos
            process_count = len(psutil.pids())
            
            # Escribir métricas
            timestamp = datetime.utcnow()
            
            points = [
                Point("system_cpu").field("percent", cpu_percent).time(timestamp, WritePrecision.NS),
                Point("system_memory") \
                    .field("percent", memory_percent) \
                    .field("used", memory_used) \
                    .field("total", memory_total) \
                    .time(timestamp, WritePrecision.NS),
                Point("system_disk").field("percent", disk_percent).time(timestamp, WritePrecision.NS),
                Point("system_network") \
                    .field("bytes_sent", net_io.bytes_sent) \
                    .field("bytes_recv", net_io.bytes_recv) \
                    .field("packets_sent", net_io.packets_sent) \
                    .field("packets_recv", net_io.packets_recv) \
                    .time(timestamp, WritePrecision.NS),
                Point("system_processes").field("count", process_count).time(timestamp, WritePrecision.NS)
            ]
            
            for point in points:
                self._write_point(point)
            
            # También guardar en memoria
            system_data = {
                'timestamp': timestamp.isoformat(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'memory_used': memory_used,
                'memory_total': memory_total,
                'disk_percent': disk_percent,
                'network_bytes_sent': net_io.bytes_sent,
                'network_bytes_recv': net_io.bytes_recv,
                'process_count': process_count
            }
            
            self.in_memory_metrics['system'].append(system_data)
            
            # Mantener solo los últimos 1000 registros en memoria
            if len(self.in_memory_metrics['system']) > 1000:
                self.in_memory_metrics['system'] = self.in_memory_metrics['system'][-1000:]
            
            return system_data
            
        except Exception as e:
            logger.error(f"Error escribiendo métricas del sistema: {e}")
            return None
    
    def _write_point(self, point: Point):
        """Escribir punto a InfluxDB"""
        if self.write_api:
            try:
                self.write_api.write(bucket=self.bucket, org=self.org, record=point)
            except Exception as e:
                logger.error(f"Error escribiendo a InfluxDB: {e}")
    
    def get_vulnerability_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Obtener resumen de vulnerabilidades"""
        if self.query_api:
            try:
                query = f'''
                from(bucket: "{self.bucket}")
                  |> range(start: -{hours}h)
                  |> filter(fn: (r) => r._measurement == "vulnerabilities")
                  |> filter(fn: (r) => r._field == "count")
                  |> group(columns: ["severity"])
                  |> sum()
                '''
                
                result = self.query_api.query(org=self.org, query=query)
                
                summary = {}
                for table in result:
                    for record in table.records:
                        severity = record.values.get('severity', 'unknown')
                        count = record.get_value()
                        summary[severity] = count
                
                return summary
                
            except Exception as e:
                logger.error(f"Error consultando vulnerabilidades: {e}")
        
        # Fallback a datos en memoria
        summary = {}
        cutoff_time = datetime.utcnow().timestamp() - (hours * 3600)
        
        for vuln in self.in_memory_metrics['vulnerabilities']:
            vuln_time = datetime.fromisoformat(vuln['timestamp'].replace('Z', '+00:00')).timestamp()
            if vuln_time >= cutoff_time:
                severity = vuln['severity']
                summary[severity] = summary.get(severity, 0) + vuln['count']
        
        return summary
    
    def get_scan_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Obtener resumen de escaneos"""
        if self.query_api:
            try:
                query = f'''
                from(bucket: "{self.bucket}")
                  |> range(start: -{hours}h)
                  |> filter(fn: (r) => r._measurement == "scans")
                  |> filter(fn: (r) => r._field == "count")
                  |> group(columns: ["status"])
                  |> sum()
                '''
                
                result = self.query_api.query(org=self.org, query=query)
                
                summary = {}
                for table in result:
                    for record in table.records:
                        status = record.values.get('status', 'unknown')
                        count = record.get_value()
                        summary[status] = count
                
                return summary
                
            except Exception as e:
                logger.error(f"Error consultando escaneos: {e}")
        
        # Fallback a datos en memoria
        summary = {}
        cutoff_time = datetime.utcnow().timestamp() - (hours * 3600)
        
        for scan in self.in_memory_metrics['scans']:
            scan_time = datetime.fromisoformat(scan['timestamp'].replace('Z', '+00:00')).timestamp()
            if scan_time >= cutoff_time:
                status = scan['status']
                summary[status] = summary.get(status, 0) + 1
        
        return summary
    
    def get_attack_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Obtener resumen de ataques"""
        if self.query_api:
            try:
                query = f'''
                from(bucket: "{self.bucket}")
                  |> range(start: -{hours}h)
                  |> filter(fn: (r) => r._measurement == "attacks")
                  |> filter(fn: (r) => r._field == "count")
                  |> group(columns: ["type", "status"])
                  |> sum()
                '''
                
                result = self.query_api.query(org=self.org, query=query)
                
                summary = {'by_type': {}, 'by_status': {}}
                for table in result:
                    for record in table.records:
                        attack_type = record.values.get('type', 'unknown')
                        status = record.values.get('status', 'unknown')
                        count = record.get_value()
                        
                        summary['by_type'][attack_type] = summary['by_type'].get(attack_type, 0) + count
                        summary['by_status'][status] = summary['by_status'].get(status, 0) + count
                
                return summary
                
            except Exception as e:
                logger.error(f"Error consultando ataques: {e}")
        
        # Fallback a datos en memoria
        summary = {'by_type': {}, 'by_status': {}}
        cutoff_time = datetime.utcnow().timestamp() - (hours * 3600)
        
        for attack in self.in_memory_metrics['attacks']:
            attack_time = datetime.fromisoformat(attack['timestamp'].replace('Z', '+00:00')).timestamp()
            if attack_time >= cutoff_time:
                attack_type = attack['type']
                status = attack['status']
                
                summary['by_type'][attack_type] = summary['by_type'].get(attack_type, 0) + 1
                summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
        
        return summary
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Obtener métricas actuales del sistema"""
        return self.write_system_metrics()
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Obtener todas las métricas en tiempo real"""
        return {
            'vulnerabilities': self.get_vulnerability_summary(),
            'scans': self.get_scan_summary(),
            'attacks': self.get_attack_summary(),
            'system': self.get_system_metrics(),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def start_background_metrics_collection(self):
        """Iniciar recolección de métricas en segundo plano"""
        async def collect_metrics():
            while True:
                try:
                    self.write_system_metrics()
                    await asyncio.sleep(60)  # Cada 60 segundos (1 minuto)
                except Exception as e:
                    logger.error(f"Error en recolección de métricas: {e}")
                    await asyncio.sleep(60)  # Esperar más tiempo si hay error
        
        # Iniciar task en background
        asyncio.create_task(collect_metrics())
    
    def close(self):
        """Cerrar conexión"""
        if self.influx_client:
            self.influx_client.close()

# Instancia global del servicio de métricas
metrics_service = MetricsService()
