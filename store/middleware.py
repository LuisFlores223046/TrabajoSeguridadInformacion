import logging
import re
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('security')

class SecurityHeadersMiddleware:
    """Middleware mejorado para headers de seguridad"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Headers adicionales de seguridad
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Content Security Policy básico
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        
        return response

class XSSProtectionMiddleware(MiddlewareMixin):
    """Middleware para detectar y bloquear intentos de XSS"""
    
    # Patrones peligrosos comunes
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>',
        r'<link[^>]*rel\s*=\s*["\']stylesheet["\'][^>]*>',
        r'<meta[^>]*>',
        r'vbscript:',
        r'data:text/html',
        r'<svg[^>]*>.*?</svg>',
    ]
    
    def process_request(self, request):
        """Procesa la request para detectar XSS"""
        
        # Verificar parámetros GET
        for key, value in request.GET.items():
            if self._contains_xss(value):
                logger.warning(f"XSS attempt detected in GET parameter '{key}': {value}")
                return HttpResponseForbidden("Malicious content detected")
        
        # Verificar parámetros POST
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                if self._contains_xss(value):
                    logger.warning(f"XSS attempt detected in POST parameter '{key}': {value}")
                    return HttpResponseForbidden("Malicious content detected")
        
        return None
    
    def _contains_xss(self, value):
        """Verifica si el valor contiene patrones XSS"""
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE | re.DOTALL):
                return True
        
        return False

class SQLInjectionProtectionMiddleware(MiddlewareMixin):
    """Middleware para detectar intentos de inyección SQL"""
    
    # Patrones comunes de inyección SQL
    SQL_INJECTION_PATTERNS = [
        r"';\s*(drop|delete|insert|update|create|alter|exec|execute)",
        r"union\s+select",
        r"1\s*=\s*1",
        r"or\s+1\s*=\s*1",
        r"and\s+1\s*=\s*1",
        r"';--",
        r"';\s*--",
        r"'\s*or\s*'",
        r"'\s*and\s*'",
        r"concat\s*\(",
        r"char\s*\(",
        r"ascii\s*\(",
        r"substring\s*\(",
        r"0x[0-9a-f]+",
        r"@@version",
        r"information_schema",
        r"sys\.tables",
        r"xp_cmdshell",
        r"sp_executesql",
    ]
    
    def process_request(self, request):
        """Procesa la request para detectar inyección SQL"""
        
        # Verificar parámetros GET
        for key, value in request.GET.items():
            if self._contains_sql_injection(value):
                logger.warning(f"SQL injection attempt detected in GET parameter '{key}': {value}")
                return HttpResponseForbidden("Malicious content detected")
        
        # Verificar parámetros POST
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                if self._contains_sql_injection(value):
                    logger.warning(f"SQL injection attempt detected in POST parameter '{key}': {value}")
                    return HttpResponseForbidden("Malicious content detected")
        
        return None
    
    def _contains_sql_injection(self, value):
        """Verifica si el valor contiene patrones de inyección SQL"""
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
        
        return False

class FileUploadSecurityMiddleware(MiddlewareMixin):
    """Middleware para validar uploads de archivos"""
    
    ALLOWED_CONTENT_TYPES = [
        'image/jpeg',
        'image/png', 
        'image/gif',
        'image/webp'
    ]
    
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    def process_request(self, request):
        """Valida archivos subidos"""
        
        if request.method == 'POST' and request.FILES:
            for field_name, uploaded_file in request.FILES.items():
                
                # Verificar tamaño
                if uploaded_file.size > self.MAX_FILE_SIZE:
                    logger.warning(f"File too large uploaded: {uploaded_file.size} bytes")
                    return HttpResponseForbidden("File too large")
                
                # Verificar tipo de contenido
                if hasattr(uploaded_file, 'content_type'):
                    if uploaded_file.content_type not in self.ALLOWED_CONTENT_TYPES:
                        logger.warning(f"Invalid file type uploaded: {uploaded_file.content_type}")
                        return HttpResponseForbidden("Invalid file type")
                
                # Verificar extensión
                if hasattr(uploaded_file, 'name') and uploaded_file.name:
                    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
                    file_ext = uploaded_file.name.lower().split('.')[-1]
                    if f'.{file_ext}' not in allowed_extensions:
                        logger.warning(f"Invalid file extension: {file_ext}")
                        return HttpResponseForbidden("Invalid file extension")
        
        return None

class RateLimitMiddleware(MiddlewareMixin):
    """Middleware básico de rate limiting por IP"""
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.request_counts = {}
        self.blocked_ips = set()
    
    def process_request(self, request):
        """Aplica rate limiting básico"""
        
        ip = self._get_client_ip(request)
        
        # Verificar si la IP está bloqueada
        if ip in self.blocked_ips:
            logger.warning(f"Blocked IP attempted access: {ip}")
            return HttpResponseForbidden("Rate limit exceeded")
        
        # Contar requests (implementación básica)
        current_time = time.time()
        
        if ip not in self.request_counts:
            self.request_counts[ip] = []
        
        # Limpiar requests antiguos (más de 1 minuto)
        self.request_counts[ip] = [
            req_time for req_time in self.request_counts[ip] 
            if current_time - req_time < 60
        ]
        
        # Agregar request actual
        self.request_counts[ip].append(current_time)
        
        # Verificar límite (100 requests por minuto)
        if len(self.request_counts[ip]) > 100:
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            self.blocked_ips.add(ip)
            return HttpResponseForbidden("Rate limit exceeded")
        
        return None
    
    def _get_client_ip(self, request):
        """Obtiene la IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip