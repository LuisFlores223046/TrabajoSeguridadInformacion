"""
Script de migración para cifrar datos existentes

Uso:
    python manage.py shell < migrate_to_encrypted.py

O desde Django shell:
    from store.migrate_to_encrypted import migrate_all_customers
    migrate_all_customers()
"""

from store.models import Customer
from store.encryption import encrypt_sensitive_data
import logging

logger = logging.getLogger(__name__)


def migrate_customer_to_encrypted(customer):
    """
    Migra un Customer individual a formato cifrado
    
    Args:
        customer: Instancia de Customer
    
    Returns:
        bool: True si fue exitoso, False si hubo error
    """
    try:
        updated = False
        
        # Migrar teléfono si existe y no está cifrado
        if customer.phone and not customer.encrypted_phone:
            encrypted_phone = encrypt_sensitive_data(customer.phone)
            customer.encrypted_phone = encrypted_phone['encrypted_data']
            customer.phone_key = encrypted_phone['encrypted_key']
            customer.phone_iv = encrypted_phone['iv']
            updated = True
            logger.info(f"Teléfono migrado para {customer.user.username}")
        
        # Migrar dirección si existe y no está cifrada
        if customer.address and not customer.encrypted_address:
            encrypted_address = encrypt_sensitive_data(customer.address)
            customer.encrypted_address = encrypted_address['encrypted_data']
            customer.address_key = encrypted_address['encrypted_key']
            customer.address_iv = encrypted_address['iv']
            updated = True
            logger.info(f"Dirección migrada para {customer.user.username}")
        
        if updated:
            customer.save()
            logger.info(f"✓ Customer {customer.user.username} migrado exitosamente")
            return True
        else:
            logger.info(f"→ Customer {customer.user.username} ya estaba cifrado")
            return True
            
    except Exception as e:
        logger.error(f"✗ Error migrando {customer.user.username}: {e}")
        return False


def migrate_all_customers():
    """
    Migra todos los Customers a formato cifrado
    
    Returns:
        dict con estadísticas de la migración
    """
    customers = Customer.objects.all()
    total = customers.count()
    success = 0
    errors = 0
    already_encrypted = 0
    
    logger.info(f"Iniciando migración de {total} customers...")
    
    for customer in customers:
        # Verificar si ya está cifrado
        if customer.encrypted_phone or customer.encrypted_address:
            already_encrypted += 1
            logger.debug(f"  {customer.user.username} ya cifrado")
            continue
        
        if migrate_customer_to_encrypted(customer):
            success += 1
        else:
            errors += 1
    
    stats = {
        'total': total,
        'success': success,
        'errors': errors,
        'already_encrypted': already_encrypted
    }
    
    logger.info("=" * 60)
    logger.info("RESUMEN DE MIGRACIÓN")
    logger.info("=" * 60)
    logger.info(f"Total de customers: {total}")
    logger.info(f"Migrados exitosamente: {success}")
    logger.info(f"Ya estaban cifrados: {already_encrypted}")
    logger.info(f"Errores: {errors}")
    logger.info("=" * 60)
    
    return stats


def verify_encryption():
    """
    Verifica que todos los datos estén correctamente cifrados
    
    Returns:
        dict con resultados de verificación
    """
    customers = Customer.objects.all()
    verified = 0
    errors = []
    
    logger.info("Verificando cifrado de datos...")
    
    for customer in customers:
        try:
            # Intentar acceder a los datos cifrados
            phone = customer.phone
            address = customer.address
            
            # Si llegamos aquí, el descifrado funcionó
            verified += 1
            logger.debug(f"✓ {customer.user.username} verificado")
            
        except Exception as e:
            errors.append({
                'username': customer.user.username,
                'error': str(e)
            })
            logger.error(f"✗ Error verificando {customer.user.username}: {e}")
    
    logger.info("=" * 60)
    logger.info("RESUMEN DE VERIFICACIÓN")
    logger.info("=" * 60)
    logger.info(f"Customers verificados: {verified}/{customers.count()}")
    logger.info(f"Errores encontrados: {len(errors)}")
    if errors:
        logger.error("Detalles de errores:")
        for error in errors:
            logger.error(f"  - {error['username']}: {error['error']}")
    logger.info("=" * 60)
    
    return {
        'total': customers.count(),
        'verified': verified,
        'errors': errors
    }


def rollback_encryption(customer_id=None):
    """
    Revierte el cifrado (para pruebas o rollback)
    
    Args:
        customer_id: ID del customer (None para todos)
    
    ADVERTENCIA: Esto elimina los datos cifrados. Solo usar en desarrollo.
    """
    if customer_id:
        customers = [Customer.objects.get(id=customer_id)]
    else:
        customers = Customer.objects.all()
    
    logger.warning("⚠️  INICIANDO ROLLBACK DE CIFRADO")
    logger.warning(f"Afectará a {len(customers)} customer(s)")
    
    for customer in customers:
        customer.encrypted_phone = None
        customer.phone_key = None
        customer.phone_iv = None
        customer.encrypted_address = None
        customer.address_key = None
        customer.address_iv = None
        customer.save()
        logger.info(f"Cifrado revertido para {customer.user.username}")
    
    logger.warning("⚠️  ROLLBACK COMPLETADO")


# Si se ejecuta directamente
if __name__ == "__main__":
    print("Ejecutando migración...")
    stats = migrate_all_customers()
    print("\nEjecutando verificación...")
    verify_encryption()
