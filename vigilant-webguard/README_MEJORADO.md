# Vigilant WebGuard - Plataforma de Análisis de Seguridad Web Mejorada

## 🔒 Descripción

Vigilant WebGuard es una plataforma avanzada de análisis de seguridad web que integra múltiples herramientas de código abierto para realizar escaneos comprehensivos y análisis profundos de vulnerabilidades.

## ✨ Nuevas Características

### 🚀 Análisis Profundo Multi-Herramienta
- **Wapiti3**: Escaneo de vulnerabilidades web (XSS, SQL Injection, etc.)
- **Nikto**: Análisis de configuración de servidores web
- **Análisis Personalizado**: Reconocimiento, búsqueda de credenciales, fuerza bruta

### 🔍 Capacidades Avanzadas
- **Búsqueda de Credenciales**: Detección automática de credenciales expuestas
- **Reconocimiento DNS**: Análisis de subdominios y registros DNS
- **Análisis SSL/TLS**: Evaluación de configuraciones de certificados
- **Descubrimiento de Assets**: Directorios, archivos y tecnologías
- **Escaneo de Puertos**: Identificación de servicios expuestos

### 📊 Reportes Profesionales
- **Generación PDF Mejorada**: Reportes comprehensivos sin dependencias problemáticas
- **Dashboards Interactivos**: Visualización en tiempo real
- **Análisis Visual**: Gráficos de severidad y distribución
- **Recomendaciones Priorizadas**: Acciones basadas en hallazgos

### 🎯 Interfaz Mejorada
- **Selección de Herramientas**: Checkbox para elegir qué herramientas ejecutar
- **Progreso en Tiempo Real**: Seguimiento de fases de análisis
- **Historial de Escaneos**: Gestión de análisis anteriores
- **Notificaciones**: Feedback visual del estado

## 🚀 Instalación

### Prerrequisitos
```bash
# Python 3.8 o superior
python --version

# Opcional: Herramientas de seguridad (para funcionalidad completa)
# Ubuntu/Debian:
sudo apt update
sudo apt install wapiti nikto nmap

# Para Windows: Instalar manualmente desde sitios oficiales
```

### Instalación del Backend
```bash
cd backend/
pip install -r requirements.txt
```

### Configuración de Variables de Entorno
```bash
# Crear archivo .env en backend/
echo "VIRUSTOTAL_API_KEY=tu_api_key_opcional" > .env
```

## 🏃‍♂️ Ejecución

### Iniciar el Backend
```bash
cd backend/
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Acceder a la Aplicación
1. **Dashboard Principal**: http://localhost:8000/frontend/index.html
2. **Análisis Profundo**: http://localhost:8000/frontend/deep-analysis.html
3. **SOC Dashboard**: http://localhost:8000/frontend/dashboard.html

## 📖 Uso

### Análisis Profundo
1. Navegar a la página de **Análisis Profundo**
2. Ingresar la URL objetivo
3. Seleccionar herramientas deseadas:
   - ✅ **Wapiti3**: Para vulnerabilidades web
   - ✅ **Nikto**: Para configuración del servidor
   - ✅ **Análisis Personalizado**: Para reconocimiento profundo
4. Hacer clic en **"Iniciar Análisis Profundo"**
5. Monitorear el progreso en tiempo real
6. Revisar resultados y descargar reportes PDF

### API Endpoints

#### Análisis Profundo
```bash
# Iniciar análisis profundo
POST /api/deep-scan/start-deep-scan
{
  "target_url": "https://ejemplo.com",
  "selected_tools": ["wapiti3", "nikto", "custom"],
  "deep_scan": true
}

# Obtener resultados
GET /api/deep-scan/scan-results/{scan_id}

# Descargar PDF
GET /api/deep-scan/download-pdf/{scan_id}

# Ver herramientas disponibles
GET /api/deep-scan/available-tools
```

## 🛠️ Solución de Problemas Comunes

### Error en VPS/Servidor
```bash
# Verificar dependencias
pip install --upgrade -r requirements.txt

# Verificar permisos de archivos
chmod +x backend/app/services/*.py

# Verificar puertos disponibles
netstat -tulpn | grep :8000
```

### PDF No Se Genera
El nuevo generador PDF usa ReportLab (más estable):
```bash
pip install reportlab==4.4.2
```

### Herramientas No Disponibles
El sistema funciona con simulaciones si las herramientas no están instaladas:
```bash
# Para instalar herramientas opcionales:
# Wapiti3
pip install wapiti3

# Nikto (Ubuntu/Debian)
sudo apt install nikto
```

## 🔧 Arquitectura Mejorada

### Backend
```
backend/
├── app/
│   ├── routes/
│   │   ├── deep_scan.py          # ✨ Nuevas rutas de análisis profundo
│   │   └── ...
│   ├── services/
│   │   ├── deep_analysis_service.py    # ✨ Servicio principal de análisis
│   │   ├── opensource_tools_service.py # ✨ Integración herramientas
│   │   └── ...
│   └── utils/
│       ├── enhanced_pdf_generator.py   # ✨ Generador PDF mejorado
│       └── ...
```

### Frontend
```
frontend/
├── deep-analysis.html    # ✨ Nueva interfaz de análisis profundo
├── index.html           # Dashboard principal mejorado
└── dashboard.html       # SOC Dashboard
```

## 🎯 Características Técnicas

### Análisis Profundo
- **5 Fases de Análisis**: Reconocimiento → Herramientas → Personalizado → Credenciales → Consolidación
- **Ejecución Paralela**: Múltiples herramientas ejecutándose simultáneamente
- **Fallback Inteligente**: Simulaciones cuando herramientas no están disponibles
- **Timeout Configurable**: Prevención de escaneos eternos

### Búsqueda de Credenciales
- **Archivos de Configuración**: `.env`, `config.php`, `database.yml`, etc.
- **Patrones Regex**: API keys, passwords, tokens, private keys
- **URLs de Base de Datos**: MongoDB, MySQL, PostgreSQL, Redis
- **Archivos de Log**: Búsqueda en logs accesibles

### Reconocimiento Avanzado
- **DNS**: Registros A, AAAA, MX, TXT, NS, CNAME
- **SSL/TLS**: Análisis de certificados y configuración
- **Tecnologías**: Detección de frameworks, CMS, librerías
- **Subdominios**: Enumeración de subdominios comunes
- **Puertos**: Escaneo de puertos principales

### Generación de Reportes
- **PDF Profesional**: Usando ReportLab (sin wkhtmltopdf)
- **Secciones Completas**: Resumen ejecutivo, metodología, hallazgos, recomendaciones
- **Apéndice Técnico**: Estadísticas detalladas e información de reconocimiento
- **Diseño Responsive**: Tablas, gráficos y formateo profesional

## 📊 Métricas y Estadísticas

### Dashboards
- **Vulnerabilidades por Severidad**: Gráfico de donut interactivo
- **Assets Descubiertos**: Gráfico de barras por tipo
- **Progreso en Tiempo Real**: Barras de progreso por fase
- **Historial**: Lista de escaneos anteriores con métricas

### Exportación
- **PDF Comprehensive**: Reporte completo profesional
- **JSON Raw**: Datos completos para integración
- **Estadísticas Agregadas**: Métricas consolidadas

## 🔮 Próximas Mejoras

- [ ] **Integración Base de Datos**: PostgreSQL para persistencia
- [ ] **Autenticación**: Sistema de usuarios y roles
- [ ] **API Rate Limiting**: Prevención de abuso
- [ ] **Notificaciones Email**: Reportes automáticos por email
- [ ] **Webhooks**: Integración con SIEM/SOC
- [ ] **Planificación**: Escaneos programados
- [ ] **Multi-tenant**: Soporte para múltiples organizaciones

## 🤝 Contribución

1. Fork el repositorio
2. Crear rama para feature: `git checkout -b feature/nueva-caracteristica`
3. Commit cambios: `git commit -am 'Agregar nueva característica'`
4. Push a la rama: `git push origin feature/nueva-caracteristica`
5. Crear Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver `LICENSE` para más detalles.

## 👥 Autores

- **Equipo de Desarrollo** - Proyecto Académico SI889
- **Institución** - Universidad de Ingeniería

## 🙏 Agradecimientos

- Comunidad de herramientas de seguridad de código abierto
- Wapiti3, Nikto, y otros proyectos que inspiraron esta plataforma
- Comunidad FastAPI y Python por las librerías utilizadas

---

**⚠️ Disclaimer**: Esta herramienta está destinada para pruebas de seguridad autorizadas únicamente. Los usuarios son responsables de cumplir con todas las leyes y regulaciones aplicables.
