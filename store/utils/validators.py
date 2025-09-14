# store/utils/validators.py
import re
import html
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags
from django.contrib.auth.password_validation import validate_password
import logging

logger = logging.getLogger(__name__)

class InputValidator:
    """Clase para validación y sanitización de entradas de usuario"""
    
    # Patrones de inyección SQL comunes
    SQL_INJECTION_PATTERNS = [
        r"(union\s+select)",
        r"(drop\s+table)",
        r"(delete\s+from)",
        r"(insert\s+into)",
        r"(update\s+set)",
        r"(exec\s*\()",
        r"(script\s*>)",
        r"(<\s*script)",
        r"(javascript\s*:)",
        r"(on\w+\s*=)",
        r"(--\s*$)",
        r"(/\*.*\*/)",
        r"(xp_cmdshell)",
        r"(sp_executesql)",
    ]
    
    # Patrones XSS comunes
    XSS_PATTERNS = [
        r"<\s*script[^>]*>.*?<\s*/\s*script\s*>",
        r"javascript\s*:",
        r"on\w+\s*=\s*['\"][^'\"]*['\"]",
        r"<\s*iframe[^>]*>",
        r"<\s*object[^>]*>",
        r"<\s*embed[^>]*>",
        r"<\s*link[^>]*>",
        r"<\s*meta[^>]*>",
    ]
    
    @classmethod
    def validate_text_input(cls, value, field_name="input", max_length=500):
        """
        Valida y sanitiza entrada de texto
        """
        if not value:
            return ""
            
        # Convertir a string si no lo es
        value = str(value).strip()
        
        # Verificar longitud
        if len(value) > max_length:
            raise ValidationError(f"{field_name} must be less than {max_length} characters")
        
        # Detectar patrones de inyección SQL
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"SQL injection attempt detected in {field_name}: {value}")
                raise ValidationError(f"Invalid characters detected in {field_name}")
        
        # Detectar patrones XSS
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"XSS attempt detected in {field_name}: {value}")
                raise ValidationError(f"Invalid characters detected in {field_name}")
        
        # Sanitizar HTML
        value = html.escape(value)
        value = strip_tags(value)
        
        return value
    
    @classmethod
    def validate_email(cls, email):
        """
        Valida formato de email
        """
        if not email:
            return ""
            
        email = cls.validate_text_input(email, "email", 254)
        
        # Patrón básico de email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValidationError("Invalid email format")
        
        return email.lower().strip()
    
    @classmethod
    def validate_phone(cls, phone):
        """
        Valida número de teléfono
        """
        if not phone:
            return ""
            
        phone = cls.validate_text_input(phone, "phone", 20)
        
        # Remover caracteres no numéricos excepto +, -, (, ), espacios
        cleaned_phone = re.sub(r'[^\d\+\-\(\)\s]', '', phone)
        
        # Verificar que tenga al menos 10 dígitos
        digits_only = re.sub(r'[^\d]', '', cleaned_phone)
        if len(digits_only) < 10:
            raise ValidationError("Phone number must have at least 10 digits")
        
        return cleaned_phone
    
    @classmethod
    def validate_address(cls, address):
        """
        Valida dirección
        """
        if not address:
            return ""
            
        address = cls.validate_text_input(address, "address", 500)
        
        # Verificar que no esté vacía después de sanitización
        if len(address.strip()) < 5:
            raise ValidationError("Address must be at least 5 characters long")
        
        return address
    
    @classmethod
    def validate_product_name(cls, name):
        """
        Valida nombre de producto
        """
        if not name:
            raise ValidationError("Product name is required")
            
        name = cls.validate_text_input(name, "product name", 200)
        
        # Verificar que no esté vacío después de sanitización
        if len(name.strip()) < 2:
            raise ValidationError("Product name must be at least 2 characters long")
        
        # Verificar caracteres válidos para nombres de producto
        if not re.match(r'^[a-zA-Z0-9\s\-\.&(),]+$', name):
            raise ValidationError("Product name contains invalid characters")
        
        return name
    
    @classmethod
    def validate_price(cls, price):
        """
        Valida precio
        """
        try:
            price = float(price)
            if price < 0:
                raise ValidationError("Price cannot be negative")
            if price > 9999.99:
                raise ValidationError("Price too high")
            return round(price, 2)
        except (ValueError, TypeError):
            raise ValidationError("Invalid price format")
    
    @classmethod
    def validate_quantity(cls, quantity):
        """
        Valida cantidad
        """
        try:
            quantity = int(quantity)
            if quantity < 0:
                raise ValidationError("Quantity cannot be negative")
            if quantity > 10000:
                raise ValidationError("Quantity too high")
            return quantity
        except (ValueError, TypeError):
            raise ValidationError("Invalid quantity format")
    
    @classmethod
    def validate_search_query(cls, query):
        """
        Valida consulta de búsqueda
        """
        if not query:
            return ""
            
        query = cls.validate_text_input(query, "search query", 100)
        
        # Remover caracteres especiales peligrosos
        query = re.sub(r'[<>"\']', '', query)
        
        return query.strip()

class PasswordValidator:
    """
    Validador personalizado para contraseñas
    """
    
    @classmethod
    def validate_password_strength(cls, password, user=None):
        """
        Valida fortaleza de contraseña
        """
        errors = []
        
        # Usar validadores de Django
        try:
            validate_password(password, user)
        except ValidationError as e:
            errors.extend(e.messages)
        
        # Validaciones adicionales
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Verificar patrones comunes
        common_patterns = ['123', 'abc', 'password', 'admin', 'qwerty']
        if any(pattern in password.lower() for pattern in common_patterns):
            errors.append("Password contains common patterns")
        
        if errors:
            raise ValidationError(errors)
        
        return password