# ecommerce_project/settings.py - CONFIGURACIÓN COMPLETA CON SEGURIDAD MEJORADA
import os
from pathlib import Path
import tempfile

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'your-default-secret-key-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = 'RENDER' not in os.environ

ALLOWED_HOSTS = []

RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')

if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# ====== APLICACIONES INSTALADAS ======
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'store.apps.StoreConfig',
    'django_ratelimit',
    'django_otp',
    'django_otp.plugins.otp_totp',
]

# ====== MIDDLEWARE DE SEGURIDAD MEJORADO ======
MIDDLEWARE = [
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'store.middleware.SecurityHeadersMiddleware',
    'store.middleware.XSSProtectionMiddleware',
    'store.middleware.SQLInjectionProtectionMiddleware',
    'store.middleware.FileUploadSecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ecommerce_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.media',
            ],
        },
    },
]

WSGI_APPLICATION = 'ecommerce_project.wsgi.application'

# ====== CONFIGURACIÓN DE BASE DE DATOS ======
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ====== VALIDACIÓN DE PASSWORDS MÁS ESTRICTA ======
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12}
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.AttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
        'OPTIONS': {
            'user_attributes': ('username', 'first_name', 'last_name', 'email'),
            'max_similarity': 0.7,
        }
    },
]

# ====== CONFIGURACIÓN DE INTERNACIONALIZACIÓN ======
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ====== CONFIGURACIÓN DE ARCHIVOS ESTÁTICOS Y MEDIA ======
STATIC_URL = 'static/'
if not DEBUG:
    STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
    
    # En producción, configuramos MEDIA_ROOT dentro de STATIC_ROOT
    MEDIA_ROOT = os.path.join(STATIC_ROOT, 'media')
    MEDIA_URL = '/static/media/'
else:
    # En desarrollo mantenemos la configuración normal
    MEDIA_URL = '/media/'
    MEDIA_ROOT = BASE_DIR / 'media'

# ====== CONFIGURACIÓN DE ARCHIVOS SUBIDOS MÁS SEGURA ======
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
FILE_UPLOAD_PERMISSIONS = 0o644

# Configurar directorio de archivos temporales
FILE_UPLOAD_TEMP_DIR = tempfile.gettempdir()

# Configurar validación de archivos
SECURE_FILE_VALIDATION = {
    'MAX_FILE_SIZE': 5 * 1024 * 1024,  # 5MB
    'ALLOWED_EXTENSIONS': ['.jpg', '.jpeg', '.png', '.gif', '.webp'],
    'ALLOWED_MIME_TYPES': [
        'image/jpeg',
        'image/png', 
        'image/gif',
        'image/webp'
    ],
    'SCAN_FOR_MALWARE': True,
    'VALIDATE_IMAGE_HEADERS': True,
}

# Configurar validación de tipos de archivo
FILE_UPLOAD_HANDLERS = [
    'django.core.files.uploadhandler.MemoryFileUploadHandler',
    'django.core.files.uploadhandler.TemporaryFileUploadHandler',
]

# ====== CONFIGURACIÓN PRINCIPAL DE CLAVES ======
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ====== CONFIGURACIÓN DE AUTENTICACIÓN ======
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'store'
LOGOUT_REDIRECT_URL = 'login'
LOGOUT_URL = 'logout'

# Configuraciones adicionales de autenticación
LOGIN_ATTEMPTS_LIMIT = 5
LOGIN_ATTEMPTS_TIMEOUT = 300  # 5 minutos

# ====== CONFIGURACIONES DE SEGURIDAD HTTPS (PRODUCCIÓN) ======
if not DEBUG:
    # Configuraciones HTTPS obligatorias en producción
    SECURE_HSTS_SECONDS = 31536000  # 1 año
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_REDIRECT_EXEMPT = []
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ====== CONFIGURACIÓN DE COOKIES SEGURAS ======
SESSION_COOKIE_AGE = 3600  # 1 hora
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_NAME = 'csessionid'  # Nombre personalizado
SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'

# Configuración CSRF mejorada
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_AGE = 3600
CSRF_COOKIE_NAME = 'ccsrftoken'  # Nombre personalizado
CSRF_USE_SESSIONS = False
CSRF_FAILURE_VIEW = 'django.views.csrf.csrf_failure'

# ====== CONFIGURACIÓN DE HEADERS DE SEGURIDAD ======
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'

# ====== CONFIGURACIÓN DE DJANGO-RATELIMIT ======
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_ENABLE = True

# ====== CONFIGURACIÓN DE CACHE PARA RATELIMIT ======
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# ====== CONFIGURACIÓN DE LOGGING DE SEGURIDAD MEJORADO ======
# Crear directorio de logs si no existe
os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'security': {
            'format': 'SECURITY [{asctime}] {levelname} {module}: {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'security.log'),
            'formatter': 'verbose',
        },
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'security_alerts.log'),
            'formatter': 'security',
        },
        'console': {
            'level': 'DEBUG' if DEBUG else 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'store': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'security': {
            'handlers': ['security_file', 'console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['security_file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# ====== CONFIGURACIÓN DE VALIDACIÓN DE ENTRADA ======
INPUT_VALIDATION = {
    'MAX_STRING_LENGTH': 1000,
    'MAX_FILE_SIZE': 5 * 1024 * 1024,  # 5MB
    'ALLOWED_IMAGE_TYPES': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    'ALLOWED_FILE_EXTENSIONS': ['.jpg', '.jpeg', '.png', '.gif', '.webp'],
    'MAX_SEARCH_LENGTH': 100,
    'MAX_NAME_LENGTH': 200,
    'MAX_DESCRIPTION_LENGTH': 1000,
    'MAX_ADDRESS_LENGTH': 500,
    'MAX_PHONE_LENGTH': 20,
    'BLOCKED_PATTERNS': [
        '<script',
        '</script>',
        'javascript:',
        'vbscript:',
        'on\w+\s*=',
        '<iframe',
        '<object',
        '<embed',
        'data:text/html',
    ],
}

# ====== CONFIGURACIONES DE DJANGO-OTP ======
OTP_TOTP_ISSUER = 'Coffee Shop'
OTP_LOGIN_URL = '/accounts/login/'

# ====== CONFIGURACIONES DE BLEACH PARA SANITIZACIÓN ======
BLEACH_ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li']
BLEACH_ALLOWED_ATTRIBUTES = {}
BLEACH_STRIP_TAGS = True
BLEACH_STRIP_COMMENTS = True

# ====== CONFIGURACIONES DE VALIDACIÓN DE EMAIL ======
EMAIL_VALIDATION = {
    'MAX_LENGTH': 254,
    'REQUIRE_UNIQUE': True,
    'BLOCKED_DOMAINS': [
        'tempmail.com',
        '10minutemail.com',
        'guerrillamail.com',
        'mailinator.com',
        'throwaway.email',
        'temp-mail.org',
    ],
}

# ====== CONFIGURACIONES DE RATE LIMITING POR ACCIÓN ======
RATELIMIT_SETTINGS = {
    'LOGIN': {'rate': '5/m', 'key': 'ip'},
    'REGISTER': {'rate': '3/m', 'key': 'ip'},
    'PASSWORD_RESET': {'rate': '3/h', 'key': 'ip'},
    'CONTACT_FORM': {'rate': '10/h', 'key': 'ip'},
    'SEARCH': {'rate': '100/m', 'key': 'ip'},
    'CART_ADD': {'rate': '30/m', 'key': 'user'},
    'CHECKOUT': {'rate': '3/m', 'key': 'user'},
    'PROFILE_UPDATE': {'rate': '10/m', 'key': 'user'},
    'ADMIN_CREATE': {'rate': '10/m', 'key': 'user'},
    'ADMIN_UPDATE': {'rate': '15/m', 'key': 'user'},
    'ADMIN_DELETE': {'rate': '5/m', 'key': 'user'},
}

# ====== CONFIGURACIONES DE MONITOREO DE SEGURIDAD ======
SECURITY_MONITORING = {
    'LOG_FAILED_LOGINS': True,
    'LOG_XSS_ATTEMPTS': True,
    'LOG_SQL_INJECTION_ATTEMPTS': True,
    'LOG_FILE_UPLOAD_ATTEMPTS': True,
    'EMAIL_SECURITY_ALERTS': False,  # Cambiar a True y configurar email
    'ALERT_EMAIL': 'admin@yourdomain.com',
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOCKOUT_TIME': 300,  # 5 minutos
}

# ====== VALIDACIÓN ADICIONAL DE MODELOS ======
MODEL_VALIDATION = {
    'STRICT_MODE': True,
    'VALIDATE_ON_SAVE': True,
    'ESCAPE_HTML_FIELDS': True,
    'MAX_DECIMAL_PLACES': 2,
    'MAX_DIGITS': 10,
}

# ====== CONFIGURACIÓN DE CONTENT SECURITY POLICY ======
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "https://cdnjs.cloudflare.com")
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FORM_ACTION = ("'self'",)

# ====== CONFIGURACIONES DE CORS (si usas API) ======
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    # Agregar dominios permitidos aquí si usas API
]

# ====== CONFIGURACIONES ADICIONALES DE SEGURIDAD ======
# Prevenir ataques de fuerza bruta (requiere django-axes si se instala)
AXES_ENABLED = True
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = 1  # hora

# ====== CONFIGURACIÓN PARA DESARROLLO LOCAL ======
if DEBUG:
    # Solo en desarrollo - configuraciones para facilitar testing
    ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '[::1]']
    
    # Configuraciones menos estrictas para desarrollo
    RATELIMIT_ENABLE = False  # Desactivar rate limiting en desarrollo
    
    # Email backend para desarrollo
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
else:
    # ====== CONFIGURACIONES ESPECÍFICAS DE PRODUCCIÓN ======
    
    # Configuración de email para producción (configurar según tu proveedor)
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587'))
    EMAIL_USE_TLS = True
    EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@yourdomain.com')
    
    # Configuraciones adicionales de producción
    SECURE_SSL_HOST = None  # Configurar si usas un host SSL específico
    
    # Configuración de base de datos para producción (opcional)
    # DATABASE_URL = os.environ.get('DATABASE_URL')
    # if DATABASE_URL:
    #     import dj_database_url
    #     DATABASES['default'] = dj_database_url.parse(DATABASE_URL)

# ====== CONFIGURACIONES OPCIONALES AVANZADAS ======

# Lista de IPs permitidas para funciones admin críticas (opcional)
ADMIN_ALLOWED_IPS = [
    '127.0.0.1',
    '::1',
    # Agregar IPs específicas aquí si necesitas restricción por IP
]

# Configuración de timeout para requests
REQUEST_TIMEOUT = 30  # 30 segundos

# Configuración de tamaño máximo de request
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000

# ====== CONFIGURACIÓN DE WHITENOISE (ARCHIVOS ESTÁTICOS) ======
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = DEBUG

# ====== CONFIGURACIÓN DE ADMIN ======
ADMIN_SITE_HEADER = "Coffee Shop Administration"
ADMIN_SITE_TITLE = "Coffee Shop Admin"
ADMIN_INDEX_TITLE = "Welcome to Coffee Shop Administration"

# ====== CONFIGURACIONES DE SEGURIDAD ADICIONALES ======

# Configuración de referrer policy
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Configuración de feature policy
PERMISSIONS_POLICY = {
    'geolocation': [],
    'microphone': [],
    'camera': [],
    'payment': [],
    'usb': [],
    'magnetometer': [],
    'accelerometer': [],
    'gyroscope': [],
}

# ====== CONFIGURACIONES DE TESTING ======
if 'test' in os.sys.argv:
    # Configuraciones específicas para testing
    PASSWORD_HASHERS = [
        'django.contrib.auth.hashers.MD5PasswordHasher',  # Más rápido para tests
    ]
    
    # Base de datos en memoria para tests
    DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
    
    # Desactivar logging en tests
    LOGGING_CONFIG = None

# ====== MENSAJE DE CONFIGURACIÓN ======
if DEBUG:
    print("🔧 Django running in DEVELOPMENT mode")
    print("⚠️  Security features may be relaxed for development")
else:
    print("🚀 Django running in PRODUCTION mode")
    print("🔒 All security features are ACTIVE")

# ====== VALIDACIÓN DE CONFIGURACIÓN CRÍTICA ======
# Verificar que las configuraciones críticas estén presentes
REQUIRED_SETTINGS = ['SECRET_KEY', 'ALLOWED_HOSTS']
for setting in REQUIRED_SETTINGS:
    if not globals().get(setting):
        raise Exception(f"Critical setting {setting} is not configured!")

# ====== FIN DE CONFIGURACIÓN ======