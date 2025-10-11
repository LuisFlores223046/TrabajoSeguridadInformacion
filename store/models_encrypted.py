# store/models_encrypted.py
"""
Extensión de modelos con soporte para cifrado híbrido AES-RSA

IMPORTANTE: Este archivo muestra cómo modificar los modelos existentes.
Para implementarlo:
1. Crear migración para añadir nuevos campos
2. Migrar datos existentes (ver script migration_helper.py)
3. Actualizar referencias en views.py
"""

from django.db import models
from django.contrib.auth.models import User
import json
import logging

# NOTA: En tu proyecto real, la importación sería:
# from .encryption import encrypt_sensitive_data, decrypt_sensitive_data

logger = logging.getLogger(__name__)


class EncryptedCustomer(models.Model):
    """
    Modelo Customer con campos cifrados usando AES-RSA
    
    Campos cifrados:
    - phone: Número de teléfono
    - address: Dirección postal
    
    Cada campo cifrado requiere 3 campos en BD:
    - encrypted_[campo]: Datos cifrados con AES (Base64)
    - [campo]_key: Clave AES cifrada con RSA (Base64)
    - [campo]_iv: Vector de inicialización AES (Base64)
    """
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    # ===== CAMPOS CIFRADOS: TELÉFONO =====
    encrypted_phone = models.TextField(
        blank=True, 
        null=True,
        help_text="Teléfono cifrado con AES (Base64)"
    )
    phone_key = models.TextField(
        blank=True, 
        null=True,
        help_text="Clave AES cifrada con RSA (Base64)"
    )
    phone_iv = models.TextField(
        blank=True, 
        null=True,
        help_text="Vector de inicialización para AES (Base64)"
    )
    
    # ===== CAMPOS CIFRADOS: DIRECCIÓN =====
    encrypted_address = models.TextField(
        blank=True, 
        null=True,
        help_text="Dirección cifrada con AES (Base64)"
    )
    address_key = models.TextField(
        blank=True, 
        null=True,
        help_text="Clave AES cifrada con RSA (Base64)"
    )
    address_iv = models.TextField(
        blank=True, 
        null=True,
        help_text="Vector de inicialización para AES (Base64)"
    )
    
    class Meta:
        db_table = 'store_customer'  # Usar misma tabla que Customer original
        verbose_name = 'Customer'
        verbose_name_plural = 'Customers'
    
    def __str__(self):
        return self.user.username
    
    # ===== PROPIEDADES PARA TELÉFONO =====
    
    @property
    def phone(self) -> str:
        """
        Descifra y retorna el teléfono
        
        Returns:
            Teléfono en texto plano o string vacío si no existe
        """
        if self.encrypted_phone and self.phone_key and self.phone_iv:
            try:
                from .encryption import decrypt_sensitive_data
                encrypted_dict = {
                    'encrypted_data': self.encrypted_phone,
                    'encrypted_key': self.phone_key,
                    'iv': self.phone_iv
                }
                decrypted = decrypt_sensitive_data(encrypted_dict)
                logger.debug(f"Teléfono descifrado para usuario {self.user.username}")
                return decrypted
            except Exception as e:
                logger.error(f"Error descifrando teléfono: {e}")
                return ""
        return ""
    
    @phone.setter
    def phone(self, value: str):
        """
        Cifra y guarda el teléfono
        
        Args:
            value: Teléfono en texto plano
        """
        if value:
            try:
                from .encryption import encrypt_sensitive_data
                encrypted = encrypt_sensitive_data(value)
                self.encrypted_phone = encrypted['encrypted_data']
                self.phone_key = encrypted['encrypted_key']
                self.phone_iv = encrypted['iv']
                logger.info(f"Teléfono cifrado para usuario {self.user.username}")
            except Exception as e:
                logger.error(f"Error cifrando teléfono: {e}")
                raise
        else:
            # Si el valor está vacío, limpiar los campos
            self.encrypted_phone = None
            self.phone_key = None
            self.phone_iv = None
    
    # ===== PROPIEDADES PARA DIRECCIÓN =====
    
    @property
    def address(self) -> str:
        """
        Descifra y retorna la dirección
        
        Returns:
            Dirección en texto plano o string vacío si no existe
        """
        if self.encrypted_address and self.address_key and self.address_iv:
            try:
                from .encryption import decrypt_sensitive_data
                encrypted_dict = {
                    'encrypted_data': self.encrypted_address,
                    'encrypted_key': self.address_key,
                    'iv': self.address_iv
                }
                decrypted = decrypt_sensitive_data(encrypted_dict)
                logger.debug(f"Dirección descifrada para usuario {self.user.username}")
                return decrypted
            except Exception as e:
                logger.error(f"Error descifrando dirección: {e}")
                return ""
        return ""
    
    @address.setter
    def address(self, value: str):
        """
        Cifra y guarda la dirección
        
        Args:
            value: Dirección en texto plano
        """
        if value:
            try:
                from .encryption import encrypt_sensitive_data
                encrypted = encrypt_sensitive_data(value)
                self.encrypted_address = encrypted['encrypted_data']
                self.address_key = encrypted['encrypted_key']
                self.address_iv = encrypted['iv']
                logger.info(f"Dirección cifrada para usuario {self.user.username}")
            except Exception as e:
                logger.error(f"Error cifrando dirección: {e}")
                raise
        else:
            # Si el valor está vacío, limpiar los campos
            self.encrypted_address = None
            self.address_key = None
            self.address_iv = None
    
    # ===== MÉTODOS AUXILIARES =====
    
    def get_encryption_status(self) -> dict:
        """
        Retorna el estado del cifrado para este customer
        
        Returns:
            dict con información sobre qué campos están cifrados
        """
        return {
            'phone_encrypted': bool(self.encrypted_phone),
            'address_encrypted': bool(self.encrypted_address),
            'phone_size': len(self.encrypted_phone) if self.encrypted_phone else 0,
            'address_size': len(self.encrypted_address) if self.encrypted_address else 0
        }


class EncryptedOrder(models.Model):
    """
    Modelo Order con dirección de envío cifrada
    
    NOTA: Heredar de Order original y añadir campos cifrados
    """
    
    # ... (otros campos del Order original)
    
    # ===== CAMPOS CIFRADOS: DIRECCIÓN DE ENVÍO =====
    encrypted_shipping_address = models.TextField(
        blank=True, 
        null=True,
        help_text="Dirección de envío cifrada con AES"
    )
    shipping_key = models.TextField(
        blank=True, 
        null=True,
        help_text="Clave AES cifrada con RSA"
    )
    shipping_iv = models.TextField(
        blank=True, 
        null=True,
        help_text="IV para descifrar dirección de envío"
    )
    
    @property
    def shipping_address(self) -> str:
        """Descifra dirección de envío"""
        if self.encrypted_shipping_address and self.shipping_key and self.shipping_iv:
            try:
                from .encryption import decrypt_sensitive_data
                encrypted_dict = {
                    'encrypted_data': self.encrypted_shipping_address,
                    'encrypted_key': self.shipping_key,
                    'iv': self.shipping_iv
                }
                return decrypt_sensitive_data(encrypted_dict)
            except Exception as e:
                logger.error(f"Error descifrando dirección de envío: {e}")
                return ""
        return ""
    
    @shipping_address.setter
    def shipping_address(self, value: str):
        """Cifra dirección de envío"""
        if value:
            try:
                from .encryption import encrypt_sensitive_data
                encrypted = encrypt_sensitive_data(value)
                self.encrypted_shipping_address = encrypted['encrypted_data']
                self.shipping_key = encrypted['encrypted_key']
                self.shipping_iv = encrypted['iv']
            except Exception as e:
                logger.error(f"Error cifrando dirección de envío: {e}")
                raise
        else:
            self.encrypted_shipping_address = None
            self.shipping_key = None
            self.shipping_iv = None


# ===== FUNCIONES DE AYUDA PARA MIGRACIÓN =====

def encrypt_existing_customer_data(customer):
    """
    Migra datos existentes de un Customer a formato cifrado
    
    Usar en data migration o script de migración
    
    Args:
        customer: Instancia de Customer (modelo antiguo)
    
    Returns:
        EncryptedCustomer con datos migrados
    """
    from .encryption import encrypt_sensitive_data
    
    encrypted_customer = EncryptedCustomer.objects.get_or_create(
        user=customer.user
    )[0]
    
    # Cifrar teléfono si existe
    if customer.phone:
        encrypted_customer.phone = customer.phone
    
    # Cifrar dirección si existe
    if customer.address:
        encrypted_customer.address = customer.address
    
    encrypted_customer.save()
    logger.info(f"Datos migrados para {customer.user.username}")
    
    return encrypted_customer
