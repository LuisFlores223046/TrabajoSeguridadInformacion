# store/middleware.py
import logging
import time
import re
from datetime import datetime
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.conf import settings

security_logger = logging.getLogger('security')

class SecurityLoggingMiddleware:
    """
    Middleware para logging y monitoreo de seguridad
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Patrones sospechosos en URLs
        self.suspicious_patterns = [
            r'\.\./',           # Directory traversal
            r'\.\.\\',          # Directory traversal (Windows)
            r'<script',         # XSS
            r'javascript:',     # XSS
            r'eval\(',          # Code injection
            r'union\s+select',  # SQL injection
            r'drop\s+table',    # SQL injection
            r'insert\s+into',   # SQL injection
            r'update\s+.*set',  # SQL injection
            r'delete\s+from',   # SQL injection
            r'exec\s*\(',       # Command injection
            r'system\s*\(',     # Command injection
            r'wp-admin',        # WordPress admin
            r'phpmyadmin',      # phpMyAdmin
            r'admin\.php',      # Generic admin
            r'config\.php',     # Config files
            r'\.env',           # Environment files
            r'\.git',           # Git files
            r'\.svn',           # SVN files
        ]
        
        # User agents sospechosos
        self.suspicious_agents = [
            'sqlmap', 'nikto', 'nmap', 'burp', 'w3af',
            'acunetix', 'nessus', 'openvas', 'metasploit',
            'dirb', 'dirbuster', 'gobuster', 'wfuzz'
        ]
    
    def __call__(self, request):
        start_time = time.time()
        
        # Obtener información del cliente
        client_ip = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Verificar patrones sospechosos
        self.check_suspicious_request(request, client_ip, user_agent)
        
        # Rate limiting
        if self.is_rate_limited(request, client_ip):
            security_logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return HttpResponseForbidden("Too many requests")
        
        # Procesar request
        response = self.get_response(request)
        
        # Log del tiempo de procesamiento
        processing_time = time.time() - start_time
        if processing_time > 5:  # Más de 5 segundos
            security_logger.warning(
                f"Slow response: {request.path} took {processing_time:.2f}s "
                f"for IP: {client_ip}"
            )
        
        # Añadir headers de seguridad
        self.add_security_headers(response)
        
        return response
    
    def get_client_ip(self, request):
        """Obtiene la IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def check_suspicious_request(self, request, client_ip, user_agent):
        """Verifica si el request es sospechoso"""
        
        # Verificar URL sospechosa
        url = request.get_full_path().lower()
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                security_logger.warning(
                    f"Suspicious URL pattern '{pattern}' detected in: {url} "
                    f"from IP: {client_ip}"
                )
                break
        
        # Verificar User-Agent sospechoso
        for agent in self.suspicious_agents:
            if agent in user_agent.lower():
                security_logger.warning(
                    f"Suspicious User-Agent: {user_agent} from IP: {client_ip}"
                )
                break
        
        # Verificar método HTTP inusual
        if request.method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
            security_logger.warning(
                f"Unusual HTTP method: {request.method} from IP: {client_ip}"
            )
        
        # Verificar headers sospechosos
        suspicious_headers = request.META.get('HTTP_X_REQUESTED_WITH', '')
        if 'xmlhttprequest' not in suspicious_headers.lower() and request.is_ajax():
            security_logger.info(f"AJAX request without proper header from IP: {client_ip}")
    
    def is_rate_limited(self, request, client_ip):
        """Implementa rate limiting básico"""
        if not getattr(settings, 'SECURITY_SETTINGS', {}).get('ENABLE_RATE_LIMITING', False):
            return False
        
        # Límites por IP
        cache_key = f"rate_limit_{client_ip}"
        current_requests = cache.get(cache_key, 0)
        
        # Límite: 100 requests por minuto por IP
        if current_requests >= 100:
            return True
        
        # Incrementar contador
        cache.set(cache_key, current_requests + 1, 60)  # 60 segundos
        return False
    
    def add_security_headers(self, response):
        """Añade headers de seguridad a la respuesta"""
        
        # Content Security Policy básico
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
        
        # Otros headers de seguridad
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response


class RequestSizeMiddleware:
    """
    Middleware para controlar el tamaño de requests
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.max_request_size = 10 * 1024 * 1024  # 10MB
    
    def __call__(self, request):
        # Verificar tamaño del request
        if hasattr(request, 'META') and 'CONTENT_LENGTH' in request.META:
            content_length = int(request.META['CONTENT_LENGTH'])
            if content_length > self.max_request_size:
                security_logger.warning(
                    f"Request too large: {content_length} bytes from IP: "
                    f"{self.get_client_ip(request)}"
                )
                return HttpResponseForbidden("Request too large")
        
        return self.get_response(request)
    
    def get_client_ip(self, request):
        """Obtiene la IP del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SQLInjectionProtectionMiddleware:
    """
    Middleware para detectar intentos de inyección SQL
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Patrones de inyección SQL más comunes
        self.sql_patterns = [
            r"union\s+(all\s+)?select",
            r"(select|insert|update|delete|drop|create|alter)\s+.*(from|into|table|database)",
            r"(exec|execute)\s*\(",
            r"(sp_|xp_)\w+",
            r"(script|javascript|vbscript|onload|onerror)",
            r"(eval|expression)\s*\(",
            r"(declare|cast|convert)\s*\(",
            r"(waitfor|delay)\s+",
            r"(information_schema|sysobjects|syscolumns)",
            r"(concat|char|ascii|substring)\s*\(",
            r"(benchmark|sleep)\s*\(",
            r"(load_file|into\s+outfile)",
        ]
    
    def __call__(self, request):
        # Verificar parámetros GET
        for key, value in request.GET.items():
            if self.contains_sql_injection(value):
                self.log_sql_injection_attempt(request, key, value, 'GET')
                return HttpResponseForbidden("Suspicious input detected")
        
        # Verificar parámetros POST
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                if self.contains_sql_injection(value):
                    self.log_sql_injection_attempt(request, key, value, 'POST')
                    return HttpResponseForbidden("Suspicious input detected")
        
        return self.get_response(request)
    
    def contains_sql_injection(self, value):
        """Verifica si el valor contiene patrones de inyección SQL"""
        if not isinstance(value, str):
            return False
        
        value_lower = value.lower()
        for pattern in self.sql_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
        return False
    
    def log_sql_injection_attempt(self, request, field, value, method):
        """Log del intento de inyección SQL"""
        client_ip = self.get_client_ip(request)
        user = request.user.username if request.user.is_authenticated else 'anonymous'
        
        security_logger.critical(
            f"SQL Injection attempt detected! "
            f"User: {user}, IP: {client_ip}, "
            f"Method: {method}, Field: {field}, "
            f"Value: {value[:100]}..."  # Solo los primeros 100 caracteres
        )
    
    def get_client_ip(self, request):
        """Obtiene la IP del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip