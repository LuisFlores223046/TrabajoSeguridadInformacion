# store/views_encryption_demo.py
"""
Vista de demostración del sistema de cifrado híbrido AES-RSA

Esta vista demuestra:
1. Cómo funciona el cifrado RSA (clave pública/privada)
2. Cómo funciona el cifrado AES (simétrico)
3. Cómo se combinan en un sistema híbrido
4. Aplicación práctica en datos de usuarios
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
import json
import logging

logger = logging.getLogger(__name__)


@login_required
def encryption_demo(request):
    """
    Vista principal de demostración del cifrado híbrido
    
    Muestra:
    - Información sobre las claves RSA generadas
    - Formulario para probar cifrado/descifrado
    - Explicación del proceso paso a paso
    - Estadísticas de rendimiento
    """
    from .encryption import encryption_service
    
    # Obtener información de la clave pública
    public_key_info = encryption_service.get_public_key_info()
    
    # Obtener estado de cifrado del usuario actual
    encryption_status = None
    if hasattr(request.user, 'customer'):
        try:
            encryption_status = request.user.customer.get_encryption_status()
        except:
            encryption_status = {'phone_encrypted': False, 'address_encrypted': False}
    
    context = {
        'public_key_info': public_key_info,
        'encryption_status': encryption_status,
        'demo_text': 'Hello, this is a test message for encryption!'
    }
    
    return render(request, 'store/encryption_demo.html', context)


@require_http_methods(["POST"])
@login_required
def encrypt_demo_text(request):
    """
    API endpoint para cifrar texto de demostración
    
    Retorna JSON con:
    - Texto original
    - Datos cifrados (Base64)
    - Tamaños de cada componente
    - Tiempo de ejecución
    """
    import time
    from .encryption import encryption_service
    
    try:
        data = json.loads(request.body)
        plaintext = data.get('text', '')
        
        if not plaintext:
            return JsonResponse({'error': 'No text provided'}, status=400)
        
        # Medir tiempo de cifrado
        start_time = time.time()
        encrypted = encryption_service.encrypt(plaintext)
        end_time = time.time()
        
        response_data = {
            'success': True,
            'original_text': plaintext,
            'original_length': len(plaintext),
            'encrypted_data': encrypted['encrypted_data'],
            'encrypted_data_length': len(encrypted['encrypted_data']),
            'encrypted_key': encrypted['encrypted_key'],
            'encrypted_key_length': len(encrypted['encrypted_key']),
            'iv': encrypted['iv'],
            'iv_length': len(encrypted['iv']),
            'encryption_time_ms': round((end_time - start_time) * 1000, 2),
            'process_explanation': [
                f"1. Se generó una clave AES aleatoria de 32 bytes (256 bits)",
                f"2. Se generó un IV aleatorio de 16 bytes (128 bits)",
                f"3. El texto ({len(plaintext)} caracteres) se cifró con AES-256-CBC",
                f"4. La clave AES se cifró con RSA-2048 usando la clave pública",
                f"5. Todo se codificó en Base64 para almacenamiento seguro"
            ]
        }
        
        logger.info(f"Usuario {request.user.username} cifró texto de {len(plaintext)} caracteres")
        return JsonResponse(response_data)
        
    except Exception as e:
        logger.error(f"Error en encrypt_demo_text: {e}")
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
@login_required
def decrypt_demo_text(request):
    """
    API endpoint para descifrar texto de demostración
    
    Retorna JSON con:
    - Texto descifrado
    - Tiempo de ejecución
    - Proceso de descifrado
    """
    import time
    from .encryption import encryption_service
    
    try:
        data = json.loads(request.body)
        encrypted_data = data.get('encrypted_data', '')
        encrypted_key = data.get('encrypted_key', '')
        iv = data.get('iv', '')
        
        if not all([encrypted_data, encrypted_key, iv]):
            return JsonResponse({'error': 'Missing encryption data'}, status=400)
        
        encrypted_dict = {
            'encrypted_data': encrypted_data,
            'encrypted_key': encrypted_key,
            'iv': iv
        }
        
        # Medir tiempo de descifrado
        start_time = time.time()
        decrypted = encryption_service.decrypt(encrypted_dict)
        end_time = time.time()
        
        response_data = {
            'success': True,
            'decrypted_text': decrypted,
            'decrypted_length': len(decrypted),
            'decryption_time_ms': round((end_time - start_time) * 1000, 2),
            'process_explanation': [
                f"1. Se decodificó de Base64 a bytes binarios",
                f"2. La clave AES se descifró usando la clave privada RSA-2048",
                f"3. El texto se descifró con AES-256-CBC usando la clave recuperada",
                f"4. Se removió el padding PKCS7 y se obtuvo el texto original"
            ]
        }
        
        logger.info(f"Usuario {request.user.username} descifró texto exitosamente")
        return JsonResponse(response_data)
        
    except Exception as e:
        logger.error(f"Error en decrypt_demo_text: {e}")
        return JsonResponse({'error': f'Decryption failed: {str(e)}'}, status=500)


@require_http_methods(["POST"])
@login_required
def encrypt_user_data(request):
    """
    Cifra datos reales del usuario (teléfono y dirección)
    
    Demuestra la aplicación práctica del cifrado híbrido
    """
    from .encryption import encrypt_sensitive_data
    
    try:
        if not hasattr(request.user, 'customer'):
            return JsonResponse({'error': 'Customer profile not found'}, status=404)
        
        customer = request.user.customer
        data = json.loads(request.body)
        
        field = data.get('field')  # 'phone' o 'address'
        value = data.get('value', '')
        
        if not field or field not in ['phone', 'address']:
            return JsonResponse({'error': 'Invalid field'}, status=400)
        
        # Cifrar y guardar
        if field == 'phone':
            customer.phone = value
        elif field == 'address':
            customer.address = value
        
        customer.save()
        
        # Obtener estado actualizado
        encryption_status = customer.get_encryption_status()
        
        logger.info(f"Usuario {request.user.username} cifró su {field}")
        
        return JsonResponse({
            'success': True,
            'message': f'{field.capitalize()} encrypted and saved successfully',
            'encryption_status': encryption_status
        })
        
    except Exception as e:
        logger.error(f"Error en encrypt_user_data: {e}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def view_encrypted_data(request):
    """
    Muestra los datos cifrados tal como se almacenan en la base de datos
    
    Demuestra que los datos están realmente cifrados
    """
    if not hasattr(request.user, 'customer'):
        return JsonResponse({'error': 'Customer profile not found'}, status=404)
    
    customer = request.user.customer
    
    encrypted_fields = {
        'phone': {
            'encrypted_data': customer.encrypted_phone or 'Not encrypted',
            'encrypted_key': customer.phone_key or 'Not encrypted',
            'iv': customer.phone_iv or 'Not encrypted',
            'decrypted_value': customer.phone or 'No data'
        },
        'address': {
            'encrypted_data': customer.encrypted_address or 'Not encrypted',
            'encrypted_key': customer.address_key or 'Not encrypted',
            'iv': customer.address_iv or 'Not encrypted',
            'decrypted_value': customer.address or 'No data'
        }
    }
    
    context = {
        'encrypted_fields': encrypted_fields,
        'encryption_status': customer.get_encryption_status()
    }
    
    return render(request, 'store/view_encrypted_data.html', context)


@login_required
def encryption_comparison(request):
    """
    Vista que compara los datos en texto plano vs cifrados
    
    Muestra una tabla lado a lado para propósitos educativos
    """
    import time
    from .encryption import encryption_service
    
    # Datos de ejemplo
    test_data = [
        "555-1234",
        "john.doe@email.com",
        "123 Main St, Ciudad Juárez, Chihuahua",
        "This is a longer text with multiple words to demonstrate AES encryption efficiency"
    ]
    
    comparisons = []
    for plaintext in test_data:
        start_time = time.time()
        encrypted = encryption_service.encrypt(plaintext)
        encryption_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = encryption_service.decrypt(encrypted)
        decryption_time = time.time() - start_time
        
        comparisons.append({
            'plaintext': plaintext,
            'plaintext_size': len(plaintext),
            'encrypted_data': encrypted['encrypted_data'][:50] + '...',
            'encrypted_size': len(encrypted['encrypted_data']),
            'size_increase': f"{((len(encrypted['encrypted_data']) / len(plaintext)) * 100):.1f}%",
            'encryption_time_ms': f"{encryption_time * 1000:.2f}",
            'decryption_time_ms': f"{decryption_time * 1000:.2f}",
            'verified': plaintext == decrypted
        })
    
    context = {
        'comparisons': comparisons
    }
    
    return render(request, 'store/encryption_comparison.html', context)
