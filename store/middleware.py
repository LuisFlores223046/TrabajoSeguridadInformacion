# ACTUALIZA store/middleware.py - Sección BruteForceProtectionMiddleware:

class BruteForceProtectionMiddleware:
    """Middleware para protección contra ataques de fuerza bruta mejorado"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.max_attempts = getattr(settings, 'BRUTE_FORCE_MAX_ATTEMPTS', 10)
        self.lockout_time = getattr(settings, 'BRUTE_FORCE_LOCKOUT_TIME', 300)  # 5 minutos

    def __call__(self, request):
        # ✅ CORREGIDO: Solo aplicar a rutas de login y admin (NO checkout)
        protected_paths = ['/login/', '/admin/', '/admin-dashboard/']
        
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
            
            # ✅ CORREGIDO: Verificar si el login falló (NO checkout)
            if (request.method == 'POST' and 
                request.path in ['/login/', '/admin/login/'] and 
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
        """Detectar si fue un intento fallido - SOLO PARA LOGIN"""
        # ✅ CORREGIDO: Solo para login y admin
        if request.path in ['/login/', '/admin/login/']:
            return (hasattr(response, 'content') and 
                   (b'error' in response.content.lower() or 
                    b'invalid' in response.content.lower() or
                    b'incorrect' in response.content.lower()))
        
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