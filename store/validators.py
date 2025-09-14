from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
import re
import html
import magic
import bleach

def validate_image_content(value):
    """Valida el contenido real del archivo, no solo la extensión"""
    if not value:
        return
    
    # Verificar magic number
    file_type = magic.from_buffer(value.read(1024), mime=True)
    value.seek(0)
    
    allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    if file_type not in allowed_types:
        raise ValidationError(f"Invalid file type: {file_type}")

def sanitize_rich_text(value):
    """Sanitiza texto enriquecido permitiendo solo tags seguros"""
    allowed_tags = ['p', 'br', 'strong', 'em']
    allowed_attributes = {}
    
    return bleach.clean(value, tags=allowed_tags, attributes=allowed_attributes)

class SecureInputValidator:
    """Validador personalizado para entradas de usuario seguras"""
    
    @staticmethod
    def validate_product_name(value):
        """Valida nombres de productos contra inyección de scripts"""
        if not value or len(value.strip()) == 0:
            raise ValidationError("Product name cannot be empty.")
        
        # Normalizar entrada - remover caracteres peligrosos
        cleaned_value = html.escape(value.strip())
        
        # Verificar longitud
        if len(cleaned_value) > 200:
            raise ValidationError("Product name cannot exceed 200 characters.")
        
        # Verificar caracteres permitidos (letras, números, espacios, guiones)
        pattern = r'^[a-zA-Z0-9\s\-\.\']+$'
        if not re.match(pattern, cleaned_value):
            raise ValidationError("Product name contains invalid characters. Only letters, numbers, spaces, hyphens, periods and apostrophes are allowed.")
        
        return cleaned_value
    
    @staticmethod
    def validate_description(value):
        """Valida descripciones contra XSS"""
        if value:
            # Normalizar y escapar HTML
            cleaned_value = html.escape(value.strip())
            
            # Verificar longitud
            if len(cleaned_value) > 1000:
                raise ValidationError("Description cannot exceed 1000 characters.")
            
            return cleaned_value
        return value
    
    @staticmethod
    def validate_price(value):
        """Valida precios para evitar valores negativos o inválidos"""
        if value is None:
            raise ValidationError("Price is required.")
        
        if value < 0:
            raise ValidationError("Price cannot be negative.")
        
        if value > 999999.99:
            raise ValidationError("Price cannot exceed $999,999.99.")
        
        return value
    
    @staticmethod
    def validate_stock(value):
        """Valida stock para evitar valores negativos"""
        if value is None:
            raise ValidationError("Stock is required.")
        
        if value < 0:
            raise ValidationError("Stock cannot be negative.")
        
        if value > 999999:
            raise ValidationError("Stock cannot exceed 999,999 units.")
        
        return value
    
    @staticmethod
    def validate_phone(value):
        """Valida números de teléfono"""
        if value:
            # Remover espacios y caracteres especiales excepto + - ( )
            cleaned_value = re.sub(r'[^\d\+\-\(\)\s]', '', value.strip())
            
            # Verificar formato básico de teléfono
            phone_pattern = r'^[\+]?[\d\s\-\(\)]{7,20}$'
            if not re.match(phone_pattern, cleaned_value):
                raise ValidationError("Please enter a valid phone number.")
            
            return cleaned_value
        return value
    
    @staticmethod
    def validate_address(value):
        """Valida direcciones contra inyección"""
        if value:
            # Normalizar y escapar
            cleaned_value = html.escape(value.strip())
            
            # Verificar longitud
            if len(cleaned_value) > 500:
                raise ValidationError("Address cannot exceed 500 characters.")
            
            return cleaned_value
        return value
    
    

# Validadores específicos usando RegexValidator
alphanumeric_validator = RegexValidator(
    regex=r'^[a-zA-Z0-9\s\-\.\']+$',
    message='Only letters, numbers, spaces, hyphens, periods and apostrophes are allowed.',
    code='invalid_characters'
)

phone_validator = RegexValidator(
    regex=r'^[\+]?[\d\s\-\(\)]{7,20}$',
    message='Please enter a valid phone number.',
    code='invalid_phone'
)

# Validador para prevenir inyección SQL en búsquedas
search_validator = RegexValidator(
    regex=r'^[a-zA-Z0-9\s\-\.\']{0,100}$',
    message='Search terms can only contain letters, numbers, spaces, hyphens, periods and apostrophes.',
    code='invalid_search'
)