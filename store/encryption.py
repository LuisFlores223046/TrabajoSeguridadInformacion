"""
Módulo de Cifrado Híbrido AES-RSA
===================================

Este módulo implementa cifrado híbrido combinando:
- RSA (2048 bits): Para cifrado de claves simétricas
- AES (256 bits en modo CBC): Para cifrado de datos

Flujo de Cifrado:
1. Se genera una clave AES aleatoria de 256 bits
2. Los datos se cifran con AES usando esa clave
3. La clave AES se cifra con la clave pública RSA
4. Se retornan ambos: datos cifrados con AES y clave AES cifrada con RSA

Flujo de Descifrado:
1. Se descifra la clave AES usando la clave privada RSA
2. Se usan esa clave AES para descifrar los datos
3. Se retornan los datos originales

Uso académico: Demostración de algoritmos de clave pública (RSA) y 
cifrado simétrico (AES) en aplicaciones web.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from django.conf import settings
import base64
import os
import logging

logger = logging.getLogger(__name__)


class RSAKeyManager:
    """
    Gestiona el par de claves RSA para el servidor.
    
    En producción, las claves deberían:
    - Cargarse desde variables de entorno seguras
    - Almacenarse en un servicio de gestión de secretos (AWS KMS, Azure Key Vault)
    - NUNCA guardarse en el código fuente o base de datos
    """
    
    _private_key = None
    _public_key = None
    
    @classmethod
    def get_private_key(cls):
        """
        Obtiene la clave privada RSA del servidor.
        En este ejemplo educativo, se genera en memoria.
        """
        if cls._private_key is None:
            logger.info("Generando nuevo par de claves RSA (2048 bits)...")
            cls._private_key = rsa.generate_private_key(
                public_exponent=65537,  # Exponente público estándar
                key_size=2048,          # 2048 bits = seguridad alta
                backend=default_backend()
            )
            cls._public_key = cls._private_key.public_key()
            logger.info("Par de claves RSA generado exitosamente")
        return cls._private_key
    
    @classmethod
    def get_public_key(cls):
        """Obtiene la clave pública RSA del servidor"""
        if cls._public_key is None:
            cls.get_private_key()  # Esto genera ambas claves
        return cls._public_key
    
    @classmethod
    def export_public_key_pem(cls) -> str:
        """
        Exporta la clave pública en formato PEM (para compartir con clientes)
        """
        public_key = cls.get_public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')


class AESCipher:
    """
    Implementa cifrado AES-256 en modo CBC con padding PKCS7.
    
    AES (Advanced Encryption Standard):
    - Algoritmo de cifrado simétrico (misma clave para cifrar y descifrar)
    - 256 bits = clave muy segura
    - CBC (Cipher Block Chaining) = modo de operación seguro
    - Requiere IV (Vector de Inicialización) aleatorio para cada cifrado
    """
    
    @staticmethod
    def generate_key() -> bytes:
        """
        Genera una clave AES aleatoria de 256 bits (32 bytes)
        """
        return os.urandom(32)
    
    @staticmethod
    def generate_iv() -> bytes:
        """
        Genera un IV (Vector de Inicialización) aleatorio de 128 bits (16 bytes)
        El IV debe ser único para cada operación de cifrado
        """
        return os.urandom(16)
    
    @staticmethod
    def pad(data: bytes) -> bytes:
        """
        Aplica padding PKCS7 a los datos.
        
        AES requiere que los datos sean múltiplos de 16 bytes.
        PKCS7 añade bytes al final para completar el bloque.
        
        Ejemplo: Si faltan 3 bytes, añade: 0x03 0x03 0x03
        """
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def unpad(data: bytes) -> bytes:
        """
        Remueve el padding PKCS7 de los datos descifrados.
        El último byte indica cuántos bytes de padding hay.
        """
        padding_length = data[-1]
        return data[:-padding_length]
    
    @staticmethod
    def encrypt(plaintext: str, key: bytes, iv: bytes) -> bytes:
        """
        Cifra texto plano usando AES-256-CBC
        
        Args:
            plaintext: Texto a cifrar (string)
            key: Clave AES de 32 bytes (256 bits)
            iv: Vector de inicialización de 16 bytes (128 bits)
        
        Returns:
            Datos cifrados (bytes)
        """
        # Crear cifrador AES en modo CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Aplicar padding y cifrar
        padded_data = AESCipher.pad(plaintext.encode('utf-8'))
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        logger.debug(f"AES: Cifrado {len(plaintext)} caracteres -> {len(encrypted_data)} bytes")
        return encrypted_data
    
    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> str:
        """
        Descifra datos usando AES-256-CBC
        
        Args:
            ciphertext: Datos cifrados (bytes)
            key: Clave AES de 32 bytes (256 bits)
            iv: Vector de inicialización de 16 bytes (128 bits)
        
        Returns:
            Texto plano (string)
        """
        # Crear descifrador AES en modo CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Descifrar y remover padding
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_data = AESCipher.unpad(decrypted_padded)
        
        logger.debug(f"AES: Descifrado {len(ciphertext)} bytes -> {len(decrypted_data)} bytes")
        return decrypted_data.decode('utf-8')


class RSACipher:
    """
    Implementa cifrado RSA con padding OAEP.
    
    RSA (Rivest-Shamir-Adleman):
    - Algoritmo de cifrado asimétrico (clave pública/privada)
    - Clave pública: Para cifrar (puede compartirse)
    - Clave privada: Para descifrar (debe mantenerse secreta)
    - OAEP: Padding seguro con funciones hash
    """
    
    @staticmethod
    def encrypt(plaintext: bytes, public_key) -> bytes:
        """
        Cifra datos usando RSA con la clave pública
        
        Args:
            plaintext: Datos a cifrar (bytes, máximo ~190 bytes para RSA-2048)
            public_key: Clave pública RSA
        
        Returns:
            Datos cifrados (bytes, siempre 256 bytes para RSA-2048)
        """
        encrypted = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logger.debug(f"RSA: Cifrado {len(plaintext)} bytes -> {len(encrypted)} bytes")
        return encrypted
    
    @staticmethod
    def decrypt(ciphertext: bytes, private_key) -> bytes:
        """
        Descifra datos usando RSA con la clave privada
        
        Args:
            ciphertext: Datos cifrados (bytes, 256 bytes para RSA-2048)
            private_key: Clave privada RSA
        
        Returns:
            Datos descifrados (bytes)
        """
        decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logger.debug(f"RSA: Descifrado {len(ciphertext)} bytes -> {len(decrypted)} bytes")
        return decrypted


class HybridEncryption:
    """
    Implementa cifrado híbrido combinando RSA y AES.
    
    ¿Por qué híbrido?
    - RSA es LENTO y tiene límite de tamaño (~190 bytes)
    - AES es RÁPIDO y puede cifrar datos grandes
    - Solución: Usar RSA para proteger la clave AES, y AES para los datos
    
    Ventajas:
    - Seguridad de RSA (clave pública/privada)
    - Velocidad de AES (cifrado simétrico)
    - Sin límite de tamaño de datos
    """
    
    def __init__(self):
        """Inicializa el sistema de cifrado híbrido"""
        self.key_manager = RSAKeyManager()
    
    def encrypt(self, plaintext: str) -> dict:
        """
        Cifra datos usando el sistema híbrido RSA-AES
        
        Proceso:
        1. Genera clave AES aleatoria (256 bits)
        2. Genera IV aleatorio (128 bits)
        3. Cifra datos con AES-256-CBC
        4. Cifra la clave AES con RSA-2048
        5. Retorna todo codificado en Base64
        
        Args:
            plaintext: Texto a cifrar (puede ser de cualquier tamaño)
        
        Returns:
            dict con:
                - encrypted_data: Datos cifrados con AES (Base64)
                - encrypted_key: Clave AES cifrada con RSA (Base64)
                - iv: Vector de inicialización (Base64)
        """
        logger.info(f"CIFRADO HÍBRIDO: Iniciando cifrado de {len(plaintext)} caracteres")
        
        # Paso 1: Generar clave AES y IV aleatorios
        aes_key = AESCipher.generate_key()
        iv = AESCipher.generate_iv()
        logger.debug(f"  → Clave AES generada: {len(aes_key)} bytes")
        logger.debug(f"  → IV generado: {len(iv)} bytes")
        
        # Paso 2: Cifrar datos con AES
        encrypted_data = AESCipher.encrypt(plaintext, aes_key, iv)
        logger.debug(f"  → Datos cifrados con AES: {len(encrypted_data)} bytes")
        
        # Paso 3: Cifrar la clave AES con RSA
        public_key = self.key_manager.get_public_key()
        encrypted_key = RSACipher.encrypt(aes_key, public_key)
        logger.debug(f"  → Clave AES cifrada con RSA: {len(encrypted_key)} bytes")
        
        # Paso 4: Codificar todo en Base64 para almacenamiento
        result = {
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
        
        logger.info("CIFRADO HÍBRIDO: Completado exitosamente")
        logger.debug(f"  → Tamaño encrypted_data (Base64): {len(result['encrypted_data'])} chars")
        logger.debug(f"  → Tamaño encrypted_key (Base64): {len(result['encrypted_key'])} chars")
        logger.debug(f"  → Tamaño iv (Base64): {len(result['iv'])} chars")
        
        return result
    
    def decrypt(self, encrypted_dict: dict) -> str:
        """
        Descifra datos del sistema híbrido RSA-AES
        
        Proceso:
        1. Decodifica de Base64
        2. Descifra la clave AES con RSA (clave privada)
        3. Descifra los datos con AES
        4. Retorna el texto plano
        
        Args:
            encrypted_dict: dict con encrypted_data, encrypted_key, iv
        
        Returns:
            Texto plano original (string)
        """
        logger.info("DESCIFRADO HÍBRIDO: Iniciando descifrado")
        
        # Paso 1: Decodificar de Base64
        encrypted_data = base64.b64decode(encrypted_dict['encrypted_data'])
        encrypted_key = base64.b64decode(encrypted_dict['encrypted_key'])
        iv = base64.b64decode(encrypted_dict['iv'])
        logger.debug(f"  → Datos decodificados de Base64")
        
        # Paso 2: Descifrar la clave AES con RSA
        private_key = self.key_manager.get_private_key()
        aes_key = RSACipher.decrypt(encrypted_key, private_key)
        logger.debug(f"  → Clave AES descifrada con RSA: {len(aes_key)} bytes")
        
        # Paso 3: Descifrar los datos con AES
        plaintext = AESCipher.decrypt(encrypted_data, aes_key, iv)
        logger.debug(f"  → Datos descifrados con AES: {len(plaintext)} caracteres")
        
        logger.info("DESCIFRADO HÍBRIDO: Completado exitosamente")
        return plaintext
    
    def get_public_key_info(self) -> dict:
        """
        Retorna información sobre la clave pública (para demostración)
        """
        public_key = self.key_manager.get_public_key()
        pem = self.key_manager.export_public_key_pem()
        
        return {
            'algorithm': 'RSA',
            'key_size': 2048,
            'public_exponent': 65537,
            'pem': pem,
            'pem_preview': pem[:100] + '...' if len(pem) > 100 else pem
        }


# Instancia global para uso en toda la aplicación
encryption_service = HybridEncryption()


def encrypt_sensitive_data(data: str) -> dict:
    """
    Función de conveniencia para cifrar datos sensibles
    
    Args:
        data: Texto a cifrar
    
    Returns:
        dict con datos cifrados
    """
    if not data:
        return None
    return encryption_service.encrypt(data)


def decrypt_sensitive_data(encrypted_dict: dict) -> str:
    """
    Función de conveniencia para descifrar datos sensibles
    
    Args:
        encrypted_dict: dict con datos cifrados
    
    Returns:
        Texto plano
    """
    if not encrypted_dict:
        return ""
    return encryption_service.decrypt(encrypted_dict)
