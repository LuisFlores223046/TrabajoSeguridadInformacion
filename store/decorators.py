"""
Decoradores personalizados para rate limiting y seguridad
"""
from functools import wraps
from django.core.cache import cache
from django.http import HttpResponse
from django.contrib import messages
from django.shortcuts import redirect
import time
import logging

logger = logging.getLogger(__name__)

def rate_limit(key, rate, method='POST'):
    """
    Decorador para limitar la velocidad de requests
    
    Args:
        key: Función que retorna la clave para el rate limiting
        rate: Formato "requests/period" (ej: "5/m" = 5 por minuto)
        method: Método HTTP a limitar
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Solo aplicar rate limiting al método especificado
            if request.method != method:
                return view_func(request, *args, **kwargs)
            
            # Parsear la tasa (ej: "5/m" -> 5 requests por minuto)
            try:
                requests, period = rate.split('/')
                requests = int(requests)
                
                # Convertir período a segundos
                if period == 'm':
                    seconds = 60
                elif period == 'h':
                    seconds = 3600
                elif period == 'd':
                    seconds = 86400
                elif period == 's':
                    seconds = 1
                else:
                    seconds = int(period)
            except (ValueError, IndexError):
                logger.error(f"Formato de rate inválido: {rate}")
                return view_func(request, *args, **kwargs)
            
            # Generar clave única para el cache
            cache_key = f"rate_limit:{key(request)}"
            
            # Obtener el contador actual
            try:
                current_requests = cache.get(cache_key, 0)
            except Exception:
                # Si el cache falla, continuar sin rate limiting
                return view_func(request, *args, **kwargs)
            
            if current_requests >= requests:
                # Rate limit excedido
                logger.warning(f"Rate limit excedido para {key(request)} - IP: {request.META.get('REMOTE_ADDR')}")
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    # Para requests AJAX
                    return HttpResponse('Rate limit exceeded', status=429)
                else:
                    # Para requests normales
                    messages.error(request, 'Too many requests. Please try again later.')
                    return redirect('store')
            
            # Incrementar contador
            try:
                cache.set(cache_key, current_requests + 1, timeout=seconds)
            except Exception as e:
                logger.error(f"Error al actualizar cache de rate limiting: {e}")
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator

def ip_rate_limit(rate, method='POST'):
    """Rate limiting basado en IP"""
    def get_ip(request):
        # Obtener IP real considerando proxies
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    return rate_limit(get_ip, rate, method)

def user_rate_limit(rate, method='POST'):
    """Rate limiting basado en usuario autenticado"""
    def get_user_key(request):
        if request.user.is_authenticated:
            return f"user_{request.user.id}"
        else:
            # Fallback a IP si no está autenticado
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0].strip()
            else:
                ip = request.META.get('REMOTE_ADDR')
            return f"ip_{ip}"
    
    return rate_limit(get_user_key, rate, method)

def session_rate_limit(rate, method='POST'):
    """Rate limiting basado en sesión"""
    def get_session_key(request):
        return f"session_{request.session.session_key or 'anonymous'}"
    
    return rate_limit(get_session_key, rate, method)