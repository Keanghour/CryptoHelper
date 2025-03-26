# aes_key_generator.py

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import os

class AESKeyGenerator:
    def __init__(self):
        pass

    def generate_key(self, passphrase: str, key_size: int):
        """
        Generate an AES key based on the passphrase and the key size.
        Uses scrypt to derive a key of the desired size.
        
        Args:
            passphrase (str): The passphrase to use for key generation.
            key_size (int): The key size in bits. Should be one of [128, 192, 256].
        
        Returns:
            str: The generated AES key in hexadecimal format.
        """
        salt = os.urandom(16)  # Random salt for key derivation
        key = scrypt(passphrase.encode(), salt, key_size // 8, N=2**14, r=8, p=1)
        return key.hex()  # Return the key in hex format

    def generate_aes_key(self, passphrase: str, key_size: int):
        """
        Wrapper method for generating the AES key.
        
        Args:
            passphrase (str): The passphrase to use for key generation.
            key_size (int): The AES key size (128, 192, or 256).
        
        Returns:
            str: The generated AES key.
        """
        return self.generate_key(passphrase, key_size)
