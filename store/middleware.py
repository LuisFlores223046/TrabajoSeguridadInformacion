# ACTUALIZA store/middleware.py con estas mejoras:

"""
Middleware personalizado para seguridad adicional
"""
import logging
import time
from django.core.cache import cache
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render
from django.conf import settings
from django.contrib import messages

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware:
    """Middleware para añadir headers de seguridad adicionales"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Headers de seguridad adicionales
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy básico
        if not settings.DEBUG:
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                "img-src 'self' data: https:; "
                "font-src 'self' https://cdnjs.cloudflare.com; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )
            response['Content-Security-Policy'] = csp
        
        return response

class BruteForceProtectionMiddleware:
    """Middleware para protección contra ataques de fuerza bruta mejorado"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.max_attempts = getattr(settings, 'BRUTE_FORCE_MAX_ATTEMPTS', 10)
        self.lockout_time = getattr(settings, 'BRUTE_FORCE_LOCKOUT_TIME', 300)  # 5 minutos

    def __call__(self, request):
        # Solo aplicar a rutas de login y admin
        protected_paths = ['/login/', '/admin/', '/admin-dashboard/', '/checkout/']
        
        if any(request.path.startswith(path) for path in protected_paths):
            ip = self.get_client_ip(request)
            
            # Verificar si la IP está bloqueada
            if self.is_ip_blocked(ip):
                logger.warning(f"IP bloqueada por fuerza bruta: {ip}")
                
                # Si es AJAX, devolver JSON
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'error': 'Too many failed attempts. Please try again later.',
                        'blocked_until': time.time() + self.lockout_time
                    }, status=429)
                
                # Para requests normales, mostrar página de error
                messages.error(request, "Too many failed attempts. Please try again later.")
                return HttpResponseForbidden("Too many failed attempts. Please try again later.")
            
            response = self.get_response(request)
            
            # Verificar si el login falló
            if (request.method == 'POST' and 
                request.path in ['/login/', '/admin/login/', '/checkout/'] and 
                response.status_code in [200, 302] and 
                self.is_failed_attempt(request, response)):
                
                self.record_failed_attempt(ip)
            
            return response
        
        return self.get_response(request)
    
    def get_client_ip(self, request):
        """Obtener la IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def is_ip_blocked(self, ip):
        """Verificar si una IP está bloqueada"""
        try:
            cache_key = f"brute_force_block:{ip}"
            return cache.get(cache_key, False)
        except Exception:
            return False
    
    def is_failed_attempt(self, request, response):
        """Detectar si fue un intento fallido"""
        # Para login
        if request.path in ['/login/', '/admin/login/']:
            return (hasattr(response, 'content') and 
                   (b'error' in response.content.lower() or 
                    b'invalid' in response.content.lower() or
                    b'incorrect' in response.content.lower()))
        
        # Para checkout
        if request.path == '/checkout/':
            return (response.status_code == 200 and 
                   hasattr(response, 'content') and
                   b'error' in response.content.lower())
        
        return False
    
    def record_failed_attempt(self, ip):
        """Registrar un intento fallido"""
        try:
            cache_key = f"brute_force_attempts:{ip}"
            attempts = cache.get(cache_key, 0) + 1
            
            # Guardar intentos por 1 hora
            cache.set(cache_key, attempts, 3600)
            
            if attempts >= self.max_attempts:
                # Bloquear IP
                block_key = f"brute_force_block:{ip}"
                cache.set(block_key, True, self.lockout_time)
                logger.warning(f"IP {ip} bloqueada por {self.max_attempts} intentos fallidos")
        except Exception as e:
            logger.error(f"Error en record_failed_attempt: {e}")

class SuspiciousActivityMiddleware:
    """Middleware para detectar actividad sospechosa mejorado"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.suspicious_patterns = [
            'union select', 'drop table', 'script>', '<iframe',
            'javascript:', 'vbscript:', 'onload=', 'onerror=',
            '../../../', '..\\..\\..\\', 'cmd.exe', '/etc/passwd',
            'eval(', 'base64_decode', 'system(', 'exec(',
            '<script', '</script>', 'alert(', 'confirm(',
            'prompt(', 'document.cookie', 'window.location'
        ]
        
        # Patrones específicos para ataques XSS y SQLi más sofisticados
        self.advanced_patterns = [
            r'<\s*script[^>]*>.*?<\s*/\s*script\s*>',
            r'javascript\s*:',
            r'on\w+\s*=\s*[\'"][^\'\"]*[\'"]',
            r'union\s+select',
            r'drop\s+table',
            r'insert\s+into',
            r'delete\s+from',
            r'update\s+.*set',
            r'<\s*iframe[^>]*>',
        ]

    def __call__(self, request):
        # Verificar patrones sospechosos en parámetros GET y POST
        if self.check_suspicious_patterns(request):
            ip = self.get_client_ip(request)
            logger.critical(f"ATAQUE DETECTADO desde {ip}: {request.path}")
            
            # Bloquear temporalmente la IP
            self.block_suspicious_ip(ip)
            
            # Respuesta para atacantes
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Forbidden'}, status=403)
            
            return HttpResponseForbidden("Suspicious activity detected.")
        
        response = self.get_response(request)
        return response
    
    def check_suspicious_patterns(self, request):
        """Verificar patrones sospechosos en la request"""
        import re
        
        ip = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Verificar en parámetros GET
        for param, value in request.GET.items():
            if self.contains_suspicious_pattern(str(value).lower()):
                logger.warning(f"Patrón sospechoso en GET desde {ip}: {param}")
                return True
            
            # Verificar patrones avanzados con regex
            for pattern in self.advanced_patterns:
                if re.search(pattern, str(value), re.IGNORECASE):
                    logger.warning(f"Patrón avanzado detectado en GET desde {ip}: {param}")
                    return True
        
        # Verificar en parámetros POST
        for param, value in request.POST.items():
            if self.contains_suspicious_pattern(str(value).lower()):
                logger.warning(f"Patrón sospechoso en POST desde {ip}: {param}")
                return True
                
            # Verificar patrones avanzados con regex
            for pattern in self.advanced_patterns:
                if re.search(pattern, str(value), re.IGNORECASE):
                    logger.warning(f"Patrón avanzado detectado en POST desde {ip}: {param}")
                    return True
        
        # Verificar User-Agent sospechoso
        suspicious_agents = ['sqlmap', 'nikto', 'nessus', 'burp', 'zaproxy', 'w3af', 'havij']
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            logger.warning(f"User-Agent sospechoso desde {ip}: {user_agent}")
            return True
        
        # Verificar longitud excesiva de parámetros (posible buffer overflow)
        for param, value in list(request.GET.items()) + list(request.POST.items()):
            if len(str(value)) > 10000:  # 10KB
                logger.warning(f"Parámetro excesivamente largo desde {ip}: {param}")
                return True
        
        return False
    
    def contains_suspicious_pattern(self, text):
        """Verificar si el texto contiene patrones sospechosos"""
        return any(pattern in text for pattern in self.suspicious_patterns)
    
    def block_suspicious_ip(self, ip):
        """Bloquear IP sospechosa temporalmente"""
        try:
            cache_key = f"suspicious_ip_block:{ip}"
            cache.set(cache_key, True, 3600)  # Bloquear por 1 hora
            logger.info(f"IP {ip} bloqueada por actividad sospechosa")
        except Exception as e:
            logger.error(f"Error al bloquear IP sospechosa: {e}")
    
    def get_client_ip(self, request):
        """Obtener la IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class RequestLoggingMiddleware:
    """Middleware para logging detallado de requests mejorado"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start_time = time.time()
        
        # Log de request entrante
        ip = self.get_client_ip(request)
        
        # Verificar si request.user existe y está autenticado
        try:
            user = getattr(request, 'user', None)
            if user and hasattr(user, 'is_authenticated') and user.is_authenticated:
                username = user.username
            else:
                username = 'Anonymous'
        except Exception:
            username = 'Anonymous'
        
        # Log más detallado para requests importantes
        if request.path.startswith(('/admin', '/checkout', '/login')):
            logger.info(f"IMPORTANT Request: {request.method} {request.path} from {ip} by {username}")
        else:
            logger.debug(f"Request: {request.method} {request.path} from {ip} by {username}")
        
        response = self.get_response(request)
        
        # Log de response con métricas
        duration = time.time() - start_time
        
        # Log errores y requests lentos con más detalle
        if response.status_code >= 400:
            logger.warning(f"ERROR Response: {response.status_code} for {request.path} ({duration:.2f}s) - IP: {ip}")
        elif duration > 2.0:  # Requests que toman más de 2 segundos
            logger.warning(f"SLOW Response: {response.status_code} for {request.path} ({duration:.2f}s) - IP: {ip}")
        else:
            logger.debug(f"Response: {response.status_code} for {request.path} ({duration:.2f}s)")
        
        return response
    
    def get_client_ip(self, request):
        """Obtener la IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip