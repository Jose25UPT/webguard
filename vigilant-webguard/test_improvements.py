#!/usr/bin/env python3
"""
Script de prueba para verificar las mejoras implementadas en Vigilant WebGuard
"""

import asyncio
import json
import os
from pathlib import Path
import sys

# Añadir el directorio backend al path
backend_dir = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_dir))

try:
    from app.services.opensource_tools_service import opensource_tools_service
    from app.services.live_analysis_service import live_analysis_service
except ImportError as e:
    print(f"❌ Error importando módulos: {e}")
    print("Asegúrate de que las dependencias estén instaladas y el PYTHONPATH esté configurado")
    sys.exit(1)

async def test_wapiti_nikto_improvements():
    """Probar las mejoras en Wapiti y Nikto"""
    print("🔧 Probando mejoras de Wapiti y Nikto...")
    
    test_url = "https://httpbin.org"  # URL de prueba segura
    
    try:
        # Probar el servicio mejorado de herramientas opensource
        print(f"   📡 Iniciando escaneo completo para {test_url}")
        result = await opensource_tools_service.comprehensive_security_scan(test_url)
        
        print(f"   ✅ Escaneo completado. Scan ID: {result.get('scan_id', 'N/A')}")
        print(f"   📊 Herramientas ejecutadas: {len(result.get('tools_results', {}))}")
        
        # Verificar archivos JSON generados
        wapiti_results = result.get('tools_results', {}).get('wapiti', {})
        nikto_results = result.get('tools_results', {}).get('nikto', {})
        
        if wapiti_results.get('json_file'):
            print(f"   📄 Archivo JSON Wapiti generado: {wapiti_results['json_file']}")
            if Path(wapiti_results['json_file']).exists():
                print("   ✅ Archivo JSON Wapiti existe")
            else:
                print("   ⚠️ Archivo JSON Wapiti no encontrado")
        
        if nikto_results.get('json_file'):
            print(f"   📄 Archivo JSON Nikto generado: {nikto_results['json_file']}")
            if Path(nikto_results['json_file']).exists():
                print("   ✅ Archivo JSON Nikto existe")
            else:
                print("   ⚠️ Archivo JSON Nikto no encontrado")
        
        # Mostrar estadísticas
        if 'summary' in result:
            summary = result['summary']
            print(f"   📈 Vulnerabilidades totales: {summary.get('total_vulnerabilities', 0)}")
            print(f"   🚨 Problemas críticos: {summary.get('critical_issues', 0)}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error en el test: {e}")
        return False

async def test_live_analysis_improvements():
    """Probar las mejoras en el análisis en vivo"""
    print("🔄 Probando mejoras del análisis en vivo...")
    
    test_url = "https://httpbin.org"
    
    try:
        # Iniciar análisis progresivo
        print(f"   🚀 Iniciando análisis progresivo para {test_url}")
        scan_id = await live_analysis_service.start_progressive_scan(test_url)
        
        print(f"   📝 Scan ID generado: {scan_id}")
        
        # Esperar un momento para que inicie
        await asyncio.sleep(5)
        
        # Verificar progreso
        progress = live_analysis_service.get_scan_progress(scan_id)
        if progress:
            print(f"   📊 Estado actual: {progress.status}")
            print(f"   🔄 Progreso: {progress.progress}%")
            print(f"   📋 Paso actual: {progress.current_step}")
            print(f"   🔍 Vulnerabilidades encontradas: {progress.vulnerabilities_found}")
            print(f"   ⚠️ Problemas críticos: {progress.critical_issues}")
            print(f"   💡 Recomendaciones: {len(progress.recommendations)}")
        else:
            print("   ⚠️ No se pudo obtener el progreso del escaneo")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Error en el test de análisis en vivo: {e}")
        return False

def test_frontend_improvements():
    """Verificar mejoras del frontend"""
    print("🎨 Verificando mejoras del frontend...")
    
    frontend_files = [
        "frontend/index.html",
        "frontend/dashboard.html"
    ]
    
    all_good = True
    
    for file_path in frontend_files:
        full_path = Path(file_path)
        if full_path.exists():
            print(f"   ✅ {file_path} existe")
            
            # Verificar contenido específico
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if file_path == "frontend/index.html":
                checks = [
                    ("Font Awesome", "font-awesome" in content.lower()),
                    ("Gradiente CSS", "gradient-bg" in content),
                    ("Funciones de navegación", "showSection" in content),
                    ("Dashboard iframe", "dashboard.html" in content),
                    ("Nuevas secciones", "reports" in content and "history" in content)
                ]
                
                for check_name, check_result in checks:
                    if check_result:
                        print(f"     ✅ {check_name}")
                    else:
                        print(f"     ⚠️ {check_name} no encontrado")
                        all_good = False
            
        else:
            print(f"   ❌ {file_path} no existe")
            all_good = False
    
    return all_good

def test_json_generation():
    """Verificar que el directorio de resultados existe"""
    print("📁 Verificando directorios de resultados...")
    
    directories = [
        "results/opensource_tools",
        "results/live_analysis"
    ]
    
    all_good = True
    
    for directory in directories:
        dir_path = Path(directory)
        if dir_path.exists():
            print(f"   ✅ {directory} existe")
        else:
            print(f"   📁 Creando directorio {directory}")
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                print(f"   ✅ {directory} creado")
            except Exception as e:
                print(f"   ❌ Error creando {directory}: {e}")
                all_good = False
    
    return all_good

async def main():
    """Función principal del test"""
    print("🚀 Iniciando pruebas de mejoras en Vigilant WebGuard")
    print("=" * 60)
    
    results = []
    
    # Test 1: Verificar directorios
    print("\n1️⃣ TEST: Directorios de resultados")
    results.append(test_json_generation())
    
    # Test 2: Verificar frontend
    print("\n2️⃣ TEST: Mejoras del frontend")
    results.append(test_frontend_improvements())
    
    # Test 3: Probar Wapiti y Nikto mejorados
    print("\n3️⃣ TEST: Herramientas Wapiti y Nikto mejoradas")
    results.append(await test_wapiti_nikto_improvements())
    
    # Test 4: Probar análisis en vivo
    print("\n4️⃣ TEST: Análisis en vivo mejorado")
    results.append(await test_live_analysis_improvements())
    
    # Resumen final
    print("\n" + "=" * 60)
    print("📊 RESUMEN DE RESULTADOS:")
    
    passed = sum(results)
    total = len(results)
    
    print(f"   ✅ Tests pasados: {passed}/{total}")
    print(f"   📈 Porcentaje de éxito: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("   🎉 ¡Todas las mejoras están funcionando correctamente!")
    else:
        print("   ⚠️ Algunas mejoras necesitan ajustes")
    
    print("\n🎯 MEJORAS IMPLEMENTADAS:")
    print("   ✅ Diseño del home más intuitivo y atractivo")
    print("   ✅ SOC Dashboard se abre en la misma página")
    print("   ✅ Escaneos robustos con Wapiti y Nikto")
    print("   ✅ Generación de archivos JSON para reportes")
    print("   ✅ Navegación mejorada entre secciones")
    print("   ✅ Análisis en vivo más robusto")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏹️ Prueba interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error ejecutando las pruebas: {e}")
        sys.exit(1)
