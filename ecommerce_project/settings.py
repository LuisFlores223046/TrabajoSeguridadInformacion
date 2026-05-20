import os
import sys as _sys
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

# ── Modo ejecutable PyInstaller ───────────────────────────────────────────────
_IS_FROZEN = getattr(_sys, 'frozen', False)
if _IS_FROZEN:
    _BUNDLE_DIR  = Path(os.environ.get('COFFEE_BUNDLE_DIR',  str(_sys._MEIPASS)))
    _RUNTIME_DIR = Path(os.environ.get('COFFEE_RUNTIME_DIR', str(Path(_sys.executable).parent)))
else:
    _BUNDLE_DIR  = BASE_DIR
    _RUNTIME_DIR = BASE_DIR
# ─────────────────────────────────────────────────────────────────────────────

# --- Entorno ---
IS_PRODUCTION = 'RENDER' in os.environ
DEBUG = not IS_PRODUCTION

# --- Secret Key ---
if _IS_FROZEN:
    SECRET_KEY = 'coffee-shop-local-demo-only-not-for-production-use'
else:
    SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
    if not SECRET_KEY:
        if IS_PRODUCTION:
            raise ImproperlyConfigured('DJANGO_SECRET_KEY no está configurada en las variables de entorno.')
        SECRET_KEY = 'dev-only-insecure-key-change-before-deploying'

# --- Hosts ---
ALLOWED_HOSTS = ['localhost', '127.0.0.1']
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# --- Apps ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'store.apps.StoreConfig',
]

# --- Middleware (orden correcto: SecurityMiddleware y WhiteNoise primero) ---
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'store.middleware.SecurityHeadersMiddleware',
    'store.middleware.BruteForceProtectionMiddleware',
    'store.middleware.SuspiciousActivityMiddleware',
    'store.middleware.RequestLoggingMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ecommerce_project.urls'

_TEMPLATE_DIRS = [_BUNDLE_DIR / 'store' / 'templates'] if _IS_FROZEN else []
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': _TEMPLATE_DIRS,
        'APP_DIRS': not _IS_FROZEN,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.media',
            ],
            # APP_DIRS y loaders son mutuamente excluyentes en Django
            **({'loaders': [
                'django.template.loaders.filesystem.Loader',
                'django.template.loaders.app_directories.Loader',
            ]} if _IS_FROZEN else {}),
        },
    },
]

WSGI_APPLICATION = 'ecommerce_project.wsgi.application'

# --- Base de datos ---
# Ejecutable local → SQLite junto al .exe
# Producción      → PostgreSQL via DATABASE_URL
# Desarrollo      → SQLite en BASE_DIR
DATABASE_URL = os.environ.get('DATABASE_URL')
if _IS_FROZEN:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': _RUNTIME_DIR / 'coffeeshop.db',
        }
    }
elif DATABASE_URL:
    import dj_database_url
    DATABASES = {
        'default': dj_database_url.config(default=DATABASE_URL, conn_max_age=600, ssl_require=True)
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# --- Cache ---
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'coffee-store-cache',
        'TIMEOUT': 300,
        'OPTIONS': {'MAX_ENTRIES': 1000},
    }
}

# --- Validadores de contraseña ---
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 8},
    },
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# --- Internacionalización ---
LANGUAGE_CODE = 'es-mx'
TIME_ZONE = 'America/Mexico_City'
USE_I18N = True
USE_TZ = True

# --- Archivos estáticos ---
STATIC_URL = '/static/'
if _IS_FROZEN:
    # Archivos estáticos incluidos en el bundle (solo lectura)
    STATIC_ROOT = _BUNDLE_DIR / 'staticfiles'
    STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'
    STATICFILES_DIRS = []
else:
    STATIC_ROOT = BASE_DIR / 'staticfiles'
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
    _static_dir = BASE_DIR / 'static'
    STATICFILES_DIRS = [_static_dir] if _static_dir.exists() else []

# --- Archivos media ---
# Producción  → sirve desde staticfiles/media via WhiteNoise
# Ejecutable  → sirve desde directorio escribible junto al .exe
# Desarrollo  → sirve desde media/ local
if IS_PRODUCTION:
    MEDIA_URL = '/static/media/'
    MEDIA_ROOT = BASE_DIR / 'staticfiles' / 'media'
elif _IS_FROZEN:
    MEDIA_URL = '/media/'
    MEDIA_ROOT = _RUNTIME_DIR / 'media'
else:
    MEDIA_URL = '/media/'
    MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Autenticación ---
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'store'
LOGOUT_REDIRECT_URL = 'login'

# --- Seguridad en producción ---
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

if IS_PRODUCTION:
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
    SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'

# --- Cookies ---
SESSION_COOKIE_SECURE = IS_PRODUCTION
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 1800  # 30 minutos
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

CSRF_COOKIE_SECURE = IS_PRODUCTION
CSRF_COOKIE_HTTPONLY = True

# --- Uploads ---
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024   # 5 MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
FILE_UPLOAD_PERMISSIONS = 0o644

# --- Protección fuerza bruta ---
BRUTE_FORCE_MAX_ATTEMPTS = 10
BRUTE_FORCE_LOCKOUT_TIME = 300  # segundos

# --- Email ---
if IS_PRODUCTION:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('EMAIL_HOST', '')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
    EMAIL_USE_TLS = True
    EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', '')
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# --- Logging ---
# En producción Render captura stdout, así que solo usamos StreamHandler.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{levelname}] {asctime} {module} — {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'store': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
