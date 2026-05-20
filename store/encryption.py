"""
Cifrado híbrido RSA-2048 + AES-256-CBC.

En producción (Render) las claves se cargan desde las variables de entorno
RSA_PRIVATE_KEY_B64 y RSA_PUBLIC_KEY_B64 (PEM codificado en base64).
En desarrollo se cargan desde archivos en el directorio keys/ o se generan
automáticamente si no existen.
"""

import base64
import os
import sys as _sys
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)

# En modo ejecutable (PyInstaller) los archivos del bundle son de solo lectura,
# por lo que las claves deben guardarse junto al .exe (directorio escribible).
if getattr(_sys, 'frozen', False):
    _KEYS_DIR = Path(os.environ.get('COFFEE_RUNTIME_DIR', str(Path(_sys.executable).parent))) / 'keys'
else:
    _KEYS_DIR = Path(__file__).resolve().parent.parent / 'keys'
_PRIVATE_KEY_FILE = _KEYS_DIR / 'private_key.pem'
_PUBLIC_KEY_FILE = _KEYS_DIR / 'public_key.pem'


class RSAKeyManager:
    """Gestiona el par de claves RSA: env vars → archivos PEM → generación nueva."""

    _private_key = None
    _public_key = None

    @classmethod
    def load_or_generate_keys(cls):
        # 1. Intentar desde variables de entorno (producción)
        private_b64 = os.environ.get('RSA_PRIVATE_KEY_B64')
        public_b64 = os.environ.get('RSA_PUBLIC_KEY_B64')

        if private_b64 and public_b64:
            logger.info('Cargando claves RSA desde variables de entorno.')
            cls._private_key = serialization.load_pem_private_key(
                base64.b64decode(private_b64),
                password=None,
                backend=default_backend(),
            )
            cls._public_key = serialization.load_pem_public_key(
                base64.b64decode(public_b64),
                backend=default_backend(),
            )
            return

        # 2. Intentar desde archivos locales (desarrollo)
        if _PRIVATE_KEY_FILE.exists() and _PUBLIC_KEY_FILE.exists():
            logger.info('Cargando claves RSA desde archivos PEM.')
            cls._private_key = serialization.load_pem_private_key(
                _PRIVATE_KEY_FILE.read_bytes(),
                password=None,
                backend=default_backend(),
            )
            cls._public_key = serialization.load_pem_public_key(
                _PUBLIC_KEY_FILE.read_bytes(),
                backend=default_backend(),
            )
            return

        # 3. Generar nuevas claves y guardarlas
        logger.info('Generando nuevo par de claves RSA de 2048 bits.')
        cls._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        cls._public_key = cls._private_key.public_key()

        _KEYS_DIR.mkdir(parents=True, exist_ok=True)
        _PRIVATE_KEY_FILE.write_bytes(
            cls._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        _PUBLIC_KEY_FILE.write_bytes(
            cls._public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        logger.info('Claves RSA generadas y guardadas en %s', _KEYS_DIR)

    @classmethod
    def get_private_key(cls):
        if cls._private_key is None:
            cls.load_or_generate_keys()
        return cls._private_key

    @classmethod
    def get_public_key(cls):
        if cls._public_key is None:
            cls.load_or_generate_keys()
        return cls._public_key


class AESCipher:
    """AES-256 en modo CBC con padding PKCS7."""

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)

    @staticmethod
    def generate_iv() -> bytes:
        return os.urandom(16)

    @staticmethod
    def _pad(data: bytes) -> bytes:
        n = 16 - (len(data) % 16)
        return data + bytes([n] * n)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        return data[: -data[-1]]

    @staticmethod
    def encrypt(plaintext: str, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        padded = AESCipher._pad(plaintext.encode('utf-8'))
        return enc.update(padded) + enc.finalize()

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        raw = dec.update(ciphertext) + dec.finalize()
        return AESCipher._unpad(raw).decode('utf-8')


class RSACipher:
    """Cifrado RSA con padding OAEP-SHA256."""

    _OAEP = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

    @classmethod
    def encrypt(cls, plaintext: bytes, public_key) -> bytes:
        return public_key.encrypt(plaintext, cls._OAEP)

    @classmethod
    def decrypt(cls, ciphertext: bytes, private_key) -> bytes:
        return private_key.decrypt(ciphertext, cls._OAEP)


class HybridEncryption:
    """Cifrado híbrido: datos con AES-256-CBC, clave AES con RSA-2048."""

    def encrypt(self, plaintext: str) -> dict:
        aes_key = AESCipher.generate_key()
        iv = AESCipher.generate_iv()

        encrypted_data = AESCipher.encrypt(plaintext, aes_key, iv)
        encrypted_key = RSACipher.encrypt(aes_key, RSAKeyManager.get_public_key())

        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
        }

    def decrypt(self, payload: dict) -> str:
        encrypted_data = base64.b64decode(payload['encrypted_data'])
        encrypted_key = base64.b64decode(payload['encrypted_key'])
        iv = base64.b64decode(payload['iv'])

        aes_key = RSACipher.decrypt(encrypted_key, RSAKeyManager.get_private_key())
        return AESCipher.decrypt(encrypted_data, aes_key, iv)


_service = HybridEncryption()


def encrypt_sensitive_data(data: str) -> dict:
    if not data:
        return None
    return _service.encrypt(data)


def decrypt_sensitive_data(payload: dict) -> str:
    if not payload:
        return ''
    return _service.decrypt(payload)
