# store/urls_encryption.py
"""
URLs para las vistas de demostración del cifrado híbrido AES-RSA

Añadir estas rutas a tu store/urls.py existente
"""

from django.urls import path
from . import views_encryption_demo

# URLs para demostración de cifrado
encryption_urlpatterns = [
    # Vista principal de demostración
    path('encryption-demo/', 
         views_encryption_demo.encryption_demo, 
         name='encryption_demo'),
    
    # API para cifrar texto de demostración
    path('encrypt-demo-text/', 
         views_encryption_demo.encrypt_demo_text, 
         name='encrypt_demo_text'),
    
    # API para descifrar texto de demostración
    path('decrypt-demo-text/', 
         views_encryption_demo.decrypt_demo_text, 
         name='decrypt_demo_text'),
    
    # API para cifrar datos reales del usuario
    path('encrypt-user-data/', 
         views_encryption_demo.encrypt_user_data, 
         name='encrypt_user_data'),
    
    # Vista para ver datos cifrados en BD
    path('view-encrypted-data/', 
         views_encryption_demo.view_encrypted_data, 
         name='view_encrypted_data'),
    
    # Vista de comparación de cifrado
    path('encryption-comparison/', 
         views_encryption_demo.encryption_comparison, 
         name='encryption_comparison'),
]

# ============================================================================
# INTEGRACIÓN CON TU ARCHIVO store/urls.py EXISTENTE
# ============================================================================
"""
Para integrar estas rutas en tu proyecto, añade al final de store/urls.py:

# Importar las rutas de cifrado
from .urls_encryption import encryption_urlpatterns

# Añadir al final del archivo
urlpatterns = (
    auth_urlpatterns + 
    customer_urlpatterns + 
    admin_urlpatterns + 
    order_urlpatterns + 
    cart_urlpatterns + 
    account_urlpatterns +
    encryption_urlpatterns  # ← AÑADIR ESTA LÍNEA
)
"""
