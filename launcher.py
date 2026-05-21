"""
Punto de entrada para el ejecutable generado por PyInstaller.
Arranca Django localmente y abre el navegador de forma automática.
"""
import os
import sys
import threading
import webbrowser
import time


def _configure_environment():
    """Ajusta rutas y variables de entorno para modo normal y congelado."""
    if getattr(sys, 'frozen', False):
        bundle_dir = sys._MEIPASS                          # archivos de solo lectura
        runtime_dir = os.path.dirname(sys.executable)     # directorio escribible (junto al .exe)
        # El bundle_dir debe estar en sys.path para poder importar los módulos
        if bundle_dir not in sys.path:
            sys.path.insert(0, bundle_dir)
        os.chdir(bundle_dir)
    else:
        bundle_dir = os.path.dirname(os.path.abspath(__file__))
        runtime_dir = bundle_dir

    os.environ['COFFEE_BUNDLE_DIR'] = bundle_dir
    os.environ['COFFEE_RUNTIME_DIR'] = runtime_dir
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ecommerce_project.settings')


def _copy_media_if_needed():
    """Al primer arranque copia las fotos del bundle al directorio escribible."""
    if not getattr(sys, 'frozen', False):
        return
    import shutil
    bundle_media  = os.path.join(os.environ['COFFEE_BUNDLE_DIR'],  'media')
    runtime_media = os.path.join(os.environ['COFFEE_RUNTIME_DIR'], 'media')
    if os.path.exists(bundle_media) and not os.path.exists(runtime_media):
        shutil.copytree(bundle_media, runtime_media)


def _open_browser():
    time.sleep(3)
    webbrowser.open('http://127.0.0.1:8000')


def main():
    _configure_environment()

    import django
    django.setup()

    from django.core.management import call_command

    print()
    print("=" * 52)
    print("       COFFEE SHOP  —  Sistema de Cafeteria")
    print("=" * 52)
    print()

    _copy_media_if_needed()

    print("  [1/3] Preparando base de datos...")
    call_command('migrate', '--noinput', verbosity=0)

    print("  [2/3] Cargando productos...")
    try:
        from store.models import Product
        if not Product.objects.exists():
            call_command('loaddata', 'store/fixtures/initial_data.json', verbosity=0)
            print("        Productos cargados correctamente.")
        else:
            print("        Datos ya existentes.")
    except Exception as exc:
        print(f"        Aviso: {exc}")

    threading.Thread(target=_open_browser, daemon=True).start()

    print("  [3/3] Iniciando servidor...")
    print()
    print("  La tienda se abrira en tu navegador en 3 segundos.")
    print("  URL: http://127.0.0.1:8000")
    print()
    print("  Cierra esta ventana para detener el servidor.")
    print("=" * 52)
    print()

    try:
        call_command('runserver', '127.0.0.1:8000', '--noreload')
    except KeyboardInterrupt:
        print("\nServidor detenido.")


if __name__ == '__main__':
    main()
