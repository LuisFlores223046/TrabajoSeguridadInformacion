"""
Módulo de Cifrado Híbrido AES-RSA - CORREGIDO
===================================
"""

import base64
import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
# ✅ IMPORTACIONES FALTANTES AGREGADAS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)

# Rutas para guardar las claves
PRIVATE_KEY_FILE = os.path.join("keys", "private_key.pem")
PUBLIC_KEY_FILE = os.path.join("keys", "public_key.pem")

# Asegurarnos de que la carpeta exista
os.makedirs("keys", exist_ok=True)

class RSAKeyManager:
    """
    Gestiona el par de claves RSA y las persiste en archivos PEM.
    """

    _private_key = None
    _public_key = None

    @classmethod
    def load_or_generate_keys(cls):
        """Carga claves desde archivos, o genera nuevas si no existen"""
        if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
            logger.info("Cargando claves RSA desde archivos PEM...")
            # Cargar clave privada
            with open(PRIVATE_KEY_FILE, "rb") as f:
                cls._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            # Cargar clave pública
            with open(PUBLIC_KEY_FILE, "rb") as f:
                cls._public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            logger.info("Claves RSA cargadas correctamente.")
        else:
            logger.info("Generando nuevo par de claves RSA (2048 bits)...")
            cls._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            cls._public_key = cls._private_key.public_key()

            # Guardar claves en archivos PEM
            with open(PRIVATE_KEY_FILE, "wb") as f:
                f.write(cls._private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(PUBLIC_KEY_FILE, "wb") as f:
                f.write(cls._public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            logger.info("Claves RSA generadas y guardadas en archivos PEM.")

    @classmethod
    def get_private_key(cls):
        """Obtiene la clave privada RSA"""
        if cls._private_key is None:
            cls.load_or_generate_keys()
        return cls._private_key

    @classmethod
    def get_public_key(cls):
        """Obtiene la clave pública RSA"""
        if cls._public_key is None:
            cls.load_or_generate_keys()
        return cls._public_key

    @classmethod
    def export_public_key_pem(cls) -> str:
        """Exporta la clave pública en formato PEM"""
        public_key = cls.get_public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode("utf-8")


class AESCipher:
    """
    Implementa cifrado AES-256 en modo CBC con padding PKCS7.
    """
    
    @staticmethod
    def generate_key() -> bytes:
        """Genera una clave AES aleatoria de 256 bits (32 bytes)"""
        return os.urandom(32)
    
    @staticmethod
    def generate_iv() -> bytes:
        """Genera un IV (Vector de Inicialización) aleatorio de 128 bits (16 bytes)"""
        return os.urandom(16)
    
    @staticmethod
    def pad(data: bytes) -> bytes:
        """Aplica padding PKCS7 a los datos."""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def unpad(data: bytes) -> bytes:
        """Remueve el padding PKCS7 de los datos descifrados."""
        padding_length = data[-1]
        return data[:-padding_length]
    
    @staticmethod
    def encrypt(plaintext: str, key: bytes, iv: bytes) -> bytes:
        """Cifra texto plano usando AES-256-CBC"""
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
        """Descifra datos usando AES-256-CBC"""
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
    """Implementa cifrado RSA con padding OAEP."""
    
    @staticmethod
    def encrypt(plaintext: bytes, public_key) -> bytes:
        """Cifra datos usando RSA con la clave pública"""
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
        """Descifra datos usando RSA con la clave privada"""
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
    """Implementa cifrado híbrido combinando RSA y AES."""
    
    def __init__(self):
        """Inicializa el sistema de cifrado híbrido"""
        self.key_manager = RSAKeyManager()
    
    def encrypt(self, plaintext: str) -> dict:
        """Cifra datos usando el sistema híbrido RSA-AES"""
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
        """Descifra datos del sistema híbrido RSA-AES"""
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
        """Retorna información sobre la clave pública (para demostración)"""
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
    """Función de conveniencia para cifrar datos sensibles"""
    if not data:
        return None
    return encryption_service.encrypt(data)


def decrypt_sensitive_data(encrypted_dict: dict) -> str:
    """Función de conveniencia para descifrar datos sensibles"""
    if not encrypted_dict:
        return ""
    return encryption_service.decrypt(encrypted_dict)