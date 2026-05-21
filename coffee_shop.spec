# -*- mode: python ; coding: utf-8 -*-
"""
Spec file para generar el ejecutable Coffee Shop con PyInstaller.
Ejecutar con:  pyinstaller coffee_shop.spec
"""
import os
import glob
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# ── Archivos de datos a incluir en el bundle ──────────────────────────────────

# Plantillas HTML del proyecto
template_datas = [
    ('store/templates', 'store/templates'),
]

# Archivos de migraciones (Django necesita leer el directorio en tiempo de ejecucion)
migration_files = glob.glob('store/migrations/*.py')
migration_datas = [(f, 'store/migrations') for f in migration_files]

# Fixtures con datos iniciales
fixture_datas = [
    ('store/fixtures', 'store/fixtures'),
]

# Archivos estaticos de Django y contrib
django_datas = collect_data_files('django.contrib.admin')
django_datas += collect_data_files('django.contrib.auth')

# Archivos estaticos del proyecto (se generan con collectstatic en build_exe.bat)
static_datas = []
if os.path.exists('staticfiles'):
    static_datas = [('staticfiles', 'staticfiles')]

# Imagenes de productos
media_datas = []
if os.path.exists('media'):
    media_datas = [('media', 'media')]

all_datas = (
    template_datas +
    migration_datas +
    fixture_datas +
    django_datas +
    static_datas +
    media_datas
)

# ── Imports que PyInstaller no detecta automaticamente ────────────────────────
hidden = (
    # Módulos del proyecto (listados explícitamente para garantizar inclusión)
    [
        'store',
        'store.apps',
        'store.models',
        'store.views',
        'store.urls',
        'store.forms',
        'store.admin',
        'store.middleware',
        'store.encryption',
        'store.migrations',
        'store.migrations.0001_initial',
        'store.migrations.0002_customer',
        'store.migrations.0003_order_orderitem',
        'store.migrations.0004_alter_order_options_remove_order_complete_and_more',
        'store.migrations.0005_alter_order_options_remove_order_notes_and_more',
        'store.migrations.0006_alter_category_description_alter_customer_address_and_more',
        'store.migrations.0007_remove_customer_address_remove_customer_phone_and_more',
        'store.migrations.0008_alter_product_image_alter_product_weight',
        'ecommerce_project',
        'ecommerce_project.settings',
        'ecommerce_project.urls',
        'ecommerce_project.wsgi',
    ] +
    collect_submodules('django.template') +
    collect_submodules('django.contrib.admin') +
    collect_submodules('django.contrib.auth') +
    collect_submodules('django.contrib.contenttypes') +
    collect_submodules('django.contrib.sessions') +
    collect_submodules('django.contrib.messages') +
    collect_submodules('django.contrib.staticfiles') +
    collect_submodules('django.db.backends.sqlite3') +
    [
        'django.template.loaders.filesystem',
        'django.template.loaders.app_directories',
        'django.template.defaulttags',
        'django.template.defaultfilters',
        'django.template.context_processors',
        'django.core.management.commands.migrate',
        'django.core.management.commands.loaddata',
        'django.core.management.commands.runserver',
        'django.core.management.commands.collectstatic',
        'cryptography.hazmat.backends.openssl',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.ciphers.algorithms',
        'cryptography.hazmat.primitives.ciphers.modes',
        'PIL._imaging',
        'PIL.Image',
        'bleach',
        'bleach.sanitizer',
        'whitenoise',
        'whitenoise.middleware',
        'whitenoise.storage',
    ]
)

# ── Analisis principal ────────────────────────────────────────────────────────
import os as _os
_PROJECT_ROOT = _os.path.dirname(_os.path.abspath(SPEC))  # noqa: F821

a = Analysis(
    ['launcher.py'],
    pathex=[_PROJECT_ROOT],
    binaries=[],
    datas=all_datas,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['psycopg2', 'psycopg2_binary', 'dj_database_url'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='CoffeeShop',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,   # Muestra consola para ver logs del servidor
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CoffeeShop',
)
