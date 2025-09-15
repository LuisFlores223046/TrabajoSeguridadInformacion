"""
Django settings for ecommerce_project project.
"""
import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'your-default-secret-key')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = 'RENDER' not in os.environ

# Configuración de hosts permitidos
ALLOWED_HOSTS = []

RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')

if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# En desarrollo, permitir localhost
if DEBUG:
    ALLOWED_HOSTS.extend(['localhost', '127.0.0.1'])
else:
    # En producción, especificar dominios exactos
    ALLOWED_HOSTS.extend(['yourdomain.com', 'www.yourdomain.com'])

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'store.apps.StoreConfig',
]

MIDDLEWARE = [
    'store.middleware.SecurityHeadersMiddleware',
    'store.middleware.BruteForceProtectionMiddleware', 
    'store.middleware.SuspiciousActivityMiddleware',
    'store.middleware.RequestLoggingMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
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
        'DIRS': [
            BASE_DIR / 'templates',  # ← Añade esto si no existe
            BASE_DIR / 'store' / 'templates',  # ← Y esto también
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.media',
            ],
        },
    },
]

WSGI_APPLICATION = 'ecommerce_project.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Cache configuration (requerido para rate limiting y middleware de seguridad)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'TIMEOUT': 300,
        'OPTIONS': {
            'MAX_ENTRIES': 1000,
        }
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = 'static/'
if not DEBUG:
    STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
    
    # Esta es la clave: en producción, configuramos MEDIA_ROOT dentro de STATIC_ROOT
    MEDIA_ROOT = os.path.join(STATIC_ROOT, 'media')
    MEDIA_URL = '/static/media/'
else:
    # En desarrollo mantenemos la configuración normal
    MEDIA_URL = '/media/'
    MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Authentication settings
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'store'
LOGOUT_REDIRECT_URL = 'login'

# =============================================================================
# CONFIGURACIONES DE SEGURIDAD ADICIONALES
# =============================================================================

# Headers de seguridad
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# HSTS (HTTP Strict Transport Security) - solo en producción
if not DEBUG:
    SECURE_HSTS_SECONDS = 31536000  # 1 año
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    
    # Configuración HTTPS en producción
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Configuración de cookies seguras
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 3600  # 1 hora
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Configuración de cookies CSRF
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_AGE = 3600

# Configuración de archivos subidos
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
FILE_UPLOAD_PERMISSIONS = 0o644

# Configuración para protección contra fuerza bruta
BRUTE_FORCE_MAX_ATTEMPTS = 5
BRUTE_FORCE_LOCKOUT_TIME = 300  # 5 minutos

# Configuración de logging mejorada
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {asctime} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'app.log'),
            'formatter': 'verbose',
        },
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'security.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.security': {
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': True,
        },
        'store': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Configuración adicional para producción
if not DEBUG:
    # Configuración de base de datos para producción (ejemplo con PostgreSQL)
    # Descomenta y configura según tu base de datos de producción
    # DATABASES = {
    #     'default': {
    #         'ENGINE': 'django.db.backends.postgresql',
    #         'NAME': os.environ.get('DB_NAME'),
    #         'USER': os.environ.get('DB_USER'),
    #         'PASSWORD': os.environ.get('DB_PASSWORD'),
    #         'HOST': os.environ.get('DB_HOST'),
    #         'PORT': os.environ.get('DB_PORT'),
    #         'OPTIONS': {
    #             'sslmode': 'require',
    #         },
    #     }
    # }
    
    # Configuraciones adicionales de seguridad en producción
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
    
    # Cache para producción (ejemplo con Redis)
    # CACHES = {
    #     'default': {
    #         'BACKEND': 'django_redis.cache.RedisCache',
    #         'LOCATION': os.environ.get('REDIS_URL'),
    #         'OPTIONS': {
    #             'CLIENT_CLASS': 'django_redis.client.DefaultClient',
    #         }
    #     }
    # }

# Configuración de admin
ADMIN_URL = os.environ.get('ADMIN_URL', 'admin/')

# Email configuration (para notificaciones de seguridad)
if not DEBUG:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('EMAIL_HOST')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
    EMAIL_USE_TLS = True
    EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL')
    
    # Email para administradores (reciben notificaciones de errores)
    ADMINS = [
        ('Admin', os.environ.get('ADMIN_EMAIL', 'admin@yourdomain.com')),
    ]
    
    # Email para managers
    MANAGERS = ADMINS
else:
    # En desarrollo, usar console backend
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Configuración adicional de seguridad
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'

# Configuración para WhiteNoise
STATICFILES_DIRS = [
    BASE_DIR / "static",
] if (BASE_DIR / "static").exists() else []

# Timeout de sesión inactiva (30 minutos)
SESSION_COOKIE_AGE = 1800

# Configuración para archivos de logs con rotación
if not DEBUG:
    LOGGING['handlers']['file']['class'] = 'logging.handlers.RotatingFileHandler'
    LOGGING['handlers']['file']['maxBytes'] = 10 * 1024 * 1024  # 10MB
    LOGGING['handlers']['file']['backupCount'] = 5
    
    LOGGING['handlers']['security_file']['class'] = 'logging.handlers.RotatingFileHandler'
    LOGGING['handlers']['security_file']['maxBytes'] = 10 * 1024 * 1024  # 10MB
    LOGGING['handlers']['security_file']['backupCount'] = 5