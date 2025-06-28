// Service Worker para notificaciones de escaneo
const CACHE_NAME = 'vigilant-webguard-v1';
const API_BASE = '/api';

// Lista de escaneos activos
let activeScans = new Set();

self.addEventListener('install', event => {
    console.log('Service Worker instalado');
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    console.log('Service Worker activado');
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

// Escuchar mensajes desde la página principal
self.addEventListener('message', event => {
    const { type, data } = event.data;
    
    switch (type) {
        case 'START_SCAN_MONITORING':
            startScanMonitoring(data.scanId, data.targetUrl);
            break;
        case 'STOP_SCAN_MONITORING':
            stopScanMonitoring(data.scanId);
            break;
    }
});

// Función para monitorear un escaneo
function startScanMonitoring(scanId, targetUrl) {
    if (activeScans.has(scanId)) {
        return; // Ya está siendo monitoreado
    }
    
    activeScans.add(scanId);
    console.log(`Iniciando monitoreo del escaneo: ${scanId}`);
    
    // Verificar el estado cada 5 segundos
    const interval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE}/scan/${scanId}`);
            const data = await response.json();
            
            if (data.status === 'completed') {
                // Escaneo completado - enviar notificación
                await showNotification(
                    'Escaneo Completado ✅',
                    {
                        body: `El análisis de ${targetUrl} ha finalizado exitosamente`,
                        icon: '/favicon.ico',
                        badge: '/favicon.ico',
                        tag: `scan-${scanId}`,
                        data: { scanId, targetUrl, type: 'scan_completed' },
                        actions: [
                            {
                                action: 'view_report',
                                title: 'Ver Reporte'
                            },
                            {
                                action: 'download_pdf',
                                title: 'Descargar PDF'
                            }
                        ]
                    }
                );
                
                // Detener monitoreo
                clearInterval(interval);
                activeScans.delete(scanId);
                
                // Enviar mensaje a todas las pestañas abiertas
                notifyAllClients('SCAN_COMPLETED', { scanId, targetUrl });
                
            } else if (data.status === 'error') {
                // Error en el escaneo
                await showNotification(
                    'Error en Escaneo ❌',
                    {
                        body: `Error al analizar ${targetUrl}`,
                        icon: '/favicon.ico',
                        tag: `scan-error-${scanId}`,
                        data: { scanId, targetUrl, type: 'scan_error' }
                    }
                );
                
                clearInterval(interval);
                activeScans.delete(scanId);
                
                notifyAllClients('SCAN_ERROR', { scanId, targetUrl });
            }
            
        } catch (error) {
            console.error('Error verificando estado del escaneo:', error);
        }
    }, 5000);
    
    // Timeout de seguridad (10 minutos)
    setTimeout(() => {
        if (activeScans.has(scanId)) {
            clearInterval(interval);
            activeScans.delete(scanId);
            
            showNotification(
                'Escaneo Timeout ⏰',
                {
                    body: `El escaneo de ${targetUrl} está tomando más tiempo del esperado`,
                    icon: '/favicon.ico',
                    tag: `scan-timeout-${scanId}`
                }
            );
        }
    }, 600000); // 10 minutos
}

// Función para detener el monitoreo
function stopScanMonitoring(scanId) {
    activeScans.delete(scanId);
    console.log(`Detenido monitoreo del escaneo: ${scanId}`);
}

// Función para mostrar notificaciones
async function showNotification(title, options) {
    try {
        if ('Notification' in self && Notification.permission === 'granted') {
            await self.registration.showNotification(title, options);
        }
    } catch (error) {
        console.error('Error mostrando notificación:', error);
    }
}

// Función para notificar a todas las pestañas
async function notifyAllClients(type, data) {
    const clients = await self.clients.matchAll();
    clients.forEach(client => {
        client.postMessage({ type, data });
    });
}

// Manejar clicks en notificaciones
self.addEventListener('notificationclick', event => {
    const { action, data } = event.notification;
    
    event.notification.close();
    
    event.waitUntil(
        (async () => {
            const clients = await self.clients.matchAll();
            
            if (action === 'view_report') {
                // Abrir o enfocar la pestaña del dashboard
                const dashboardUrl = '/';
                let targetClient = clients.find(client => 
                    client.url.includes(dashboardUrl)
                );
                
                if (targetClient) {
                    targetClient.focus();
                    targetClient.postMessage({
                        type: 'VIEW_REPORT',
                        data: { scanId: data.scanId }
                    });
                } else {
                    self.clients.openWindow(dashboardUrl);
                }
                
            } else if (action === 'download_pdf') {
                // Descargar PDF directamente
                const clients = await self.clients.matchAll();
                if (clients.length > 0) {
                    clients[0].postMessage({
                        type: 'DOWNLOAD_PDF',
                        data: { scanId: data.scanId }
                    });
                }
                
            } else {
                // Click general en la notificación
                if (clients.length > 0) {
                    clients[0].focus();
                } else {
                    self.clients.openWindow('/');
                }
            }
        })()
    );
});

// Monitoreo periódico de la salud del sistema
setInterval(async () => {
    try {
        const response = await fetch(`${API_BASE}/dashboard/realtime-stats`);
        const stats = await response.json();
        
        // Verificar alertas críticas
        if (stats.critical_alerts && stats.critical_alerts > 0) {
            await showNotification(
                '🚨 Alerta Crítica de Seguridad',
                {
                    body: `Se detectaron ${stats.critical_alerts} alertas críticas`,
                    icon: '/favicon.ico',
                    tag: 'critical-alert',
                    requireInteraction: true,
                    data: { type: 'critical_alert' }
                }
            );
        }
        
    } catch (error) {
        console.error('Error en monitoreo de salud:', error);
    }
}, 30000); // Cada 30 segundos
