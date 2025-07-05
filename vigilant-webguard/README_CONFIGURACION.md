# 🔧 Guía Completa de Configuración - WebGuard

## 📋 Resumen del Sistema

WebGuard ahora incluye un **sistema completo de herramientas de seguridad** con configuración flexible de API keys. No necesitas todas las API keys para usar el sistema - funciona perfectamente en modo desarrollo.

### ✨ Nuevas Herramientas Agregadas

1. **🛡️ Enhanced Security Suite** (`enhanced-security.html`)
   - Escaneo de vulnerabilidades avanzado
   - Análisis de infraestructura real
   - Telemetría en tiempo real

2. **💥 DDoS & Attack Tools** (`ddos-tools.html`)
   - HTTP Flood DDoS
   - TCP SYN Flood
   - UDP Flood
   - Slowloris Attack
   - ICMP Flood
   - Amplification Attacks

3. **⚙️ Configuración de API Keys** (`config.html`)
   - Gestión visual de servicios
   - Estado de configuración
   - Guías de registro

---

## 🚀 Configuración Rápida (Sin API Keys)

El sistema funciona **inmediatamente** sin configuración adicional:

```bash
# 1. Navegar al directorio
cd backend

# 2. Instalar dependencias (si no están instaladas)
pip install fastapi uvicorn python-multipart aiohttp loguru

# 3. Ejecutar el servidor
python -m uvicorn app.main:app --reload

# 4. Abrir el navegador
# http://localhost:8000
```

✅ **¡Listo!** Todas las herramientas funcionan en modo desarrollo.

---

## 🔑 Configuración de API Keys (Opcional)

### Paso 1: Copiar Template
```bash
cp backend/.env.template backend/.env
```

### Paso 2: Configurar Servicios Recomendados

#### 🆓 **Azure Monitor (Más Recomendado)**
```bash
# 1. Ir a https://azure.microsoft.com/free/
# 2. Crear cuenta gratuita
# 3. Crear App Registration en Azure AD
# 4. Agregar al .env:

AZURE_TENANT_ID=tu_tenant_id
AZURE_CLIENT_ID=tu_client_id  
AZURE_CLIENT_SECRET=tu_client_secret
AZURE_SUBSCRIPTION_ID=tu_subscription_id
ENABLE_AZURE_MONITOR=true
```

#### 🆓 **Google Analytics**
```bash
# 1. Ir a https://analytics.google.com/
# 2. Crear propiedad
# 3. Agregar al .env:

GOOGLE_ANALYTICS_TRACKING_ID=GA_TRACKING_ID
GOOGLE_ANALYTICS_MEASUREMENT_ID=G-MEASUREMENT_ID
ENABLE_GOOGLE_ANALYTICS=true
```

#### 🆓 **VirusTotal**
```bash
# 1. Ir a https://www.virustotal.com/gui/join-us
# 2. Registrarse gratis
# 3. Agregar al .env:

VIRUSTOTAL_API_KEY=tu_api_key_de_virustotal
ENABLE_VIRUSTOTAL=true
```

### Paso 3: Reiniciar Servidor
```bash
# Detener servidor (Ctrl+C)
# Reiniciar
python -m uvicorn app.main:app --reload
```

---

## 🔗 Enlaces de Registro Gratuito

### Servicios Principales
- **Azure Monitor**: https://azure.microsoft.com/free/
- **Google Analytics**: https://analytics.google.com/
- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **AWS CloudWatch**: https://aws.amazon.com/free/

### Servicios Adicionales
- **Shodan**: https://account.shodan.io/register
- **AbuseIPDB**: https://www.abuseipdb.com/register
- **New Relic**: https://newrelic.com/signup

---

## 📊 Herramientas Disponibles

### 1. Security Suite
**Acceso**: Click en "🛡️ Security Suite" o navegar a `enhanced-security.html`

**Funciones**:
- ✅ Escaneo de infraestructura real
- ✅ Suite completa de exploits
- ✅ Generación de peticiones masivas
- ✅ Dashboard de telemetría

### 2. DDoS & Attack Tools
**Acceso**: Click en "💥 DDoS & Ataques" o navegar a `ddos-tools.html`

⚠️ **IMPORTANTE**: Estas herramientas son para testing ético únicamente.

**Funciones**:
- 🚀 HTTP Flood DDoS (hasta 1M requests)
- 🌐 TCP SYN Flood (Layer 4)
- 📡 UDP Flood
- 🐌 Slowloris Attack
- 🏓 ICMP Flood
- 💥 Amplification Attacks

### 3. Configuración
**Acceso**: Click en "⚙️ Configuración" o navegar a `config.html`

**Funciones**:
- 📋 Estado de servicios
- 🔧 Guías de configuración
- 🔗 Enlaces de registro
- 📊 Recomendaciones

---

## 🛡️ Modo Desarrollo vs Producción

### Modo Desarrollo (Por Defecto)
```bash
DEVELOPMENT_MODE=true
```
- ✅ Todas las herramientas funcionan
- ✅ APIs simuladas cuando no hay keys
- ⚠️ Datos de ejemplo
- 📊 Telemetría simulada

### Modo Producción
```bash
DEVELOPMENT_MODE=false
```
- 🔑 Requiere API keys reales
- 🌐 Conexiones a servicios reales
- 📊 Telemetría real
- 💾 Datos persistentes

---

## 🔧 Variables de Entorno Importantes

```bash
# Modo de operación
DEVELOPMENT_MODE=true

# Límites de seguridad
MAX_REQUESTS_PER_SCAN=50000
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=300

# Rate limiting
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Logging
LOG_LEVEL=INFO
ENABLE_DEBUG_MODE=false
```

---

## 📝 Estructura de Archivos

```
📁 vigilant-webguard/
├── 📁 backend/
│   ├── 📄 .env.template        # Template de configuración
│   ├── 📄 .env                 # Tu configuración (crear)
│   └── 📁 app/
│       └── 📁 services/
│           ├── config_service.py      # ✨ Nuevo
│           └── ...
├── 📁 frontend/
│   ├── 📄 enhanced-security.html     # ✨ Nuevo
│   ├── 📄 ddos-tools.html           # ✨ Nuevo
│   ├── 📄 config.html               # ✨ Nuevo
│   └── 📄 index.html                # Actualizado
└── 📄 README_CONFIGURACION.md        # ✨ Esta guía
```

---

## 🚨 Advertencias de Seguridad

### DDoS Tools
- ⚠️ **Solo para uso ético y educativo**
- 🔒 Solo usar en sistemas propios
- 📋 Obtener autorización explícita
- 🚫 **El uso malicioso es ILEGAL**

### API Keys
- 🔐 Mantener seguras las API keys
- 🚫 No subir .env a repositorios
- 🔄 Rotar keys periódicamente
- 📊 Monitorear uso de quotas

---

## 🆘 Solución de Problemas

### El servidor no inicia
```bash
# Verificar dependencias
pip install -r requirements.txt

# Verificar puerto
netstat -an | grep 8000
```

### Las herramientas no aparecen
```bash
# Verificar que estás en modo desarrollo
grep DEVELOPMENT_MODE backend/.env

# Debe mostrar: DEVELOPMENT_MODE=true
```

### Error de API keys
```bash
# Verificar configuración
python -c "from backend.app.services.config_service import config_service; print(config_service.get_configuration_status())"
```

### Problemas de permisos (DDoS Tools)
- Los ataques de red (SYN, UDP, ICMP) requieren permisos de administrador
- En Windows: ejecutar como administrador
- En Linux: usar sudo o capabilities

---

## 📚 Recursos Adicionales

### Documentación de APIs
- [Azure Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/)
- [Google Analytics](https://developers.google.com/analytics)
- [VirusTotal API](https://developers.virustotal.com/reference)

### Herramientas de Seguridad
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## ❓ FAQ

**P: ¿Puedo usar el sistema sin API keys?**
R: ¡Sí! El sistema funciona completamente en modo desarrollo con datos simulados.

**P: ¿Las herramientas de DDoS son reales?**
R: Las simulaciones son reales, pero están limitadas para uso ético. Los ataques de red requieren permisos especiales.

**P: ¿Cómo obtengo la API key de Azure?**
R: Ve a la configuración (`config.html`) y sigue la guía paso a paso para Azure Monitor.

**P: ¿Es seguro usar estas herramientas?**
R: Sí, cuando se usan éticamente en sistemas propios o con autorización. Nunca uses las herramientas de ataque en sistemas que no te pertenecen.

---

## 🎯 ¡Listo para Usar!

Tu WebGuard ahora tiene:
- ✅ Sistema de configuración flexible
- ✅ Herramientas avanzadas de seguridad  
- ✅ Suite completa de DDoS tools
- ✅ Telemetría en tiempo real
- ✅ Modo desarrollo sin configuración

**¡Disfruta explorando las nuevas funcionalidades!** 🚀
