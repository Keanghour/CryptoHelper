from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import hashlib


class AESEncryptionDecryption:
    @staticmethod
    def set_key(secret):
        key = hashlib.sha1(secret.encode('utf-8')).digest()[:16]
        return key

    @staticmethod
    def encrypt_aes(data, secret):
        key = AESEncryptionDecryption.set_key(secret)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = data + (16 - len(data) % 16) * chr(16 - len(data) % 16)  # Padding to AES block size (16)
        encrypted = encryptor.update(padded_data.encode('utf-8')) + encryptor.finalize()
        return base64.b64encode(encrypted).decode('utf-8')  # Return base64-encoded encrypted data

    @staticmethod
    def decrypt_aes(encrypted_data, secret):
        key = AESEncryptionDecryption.set_key(secret)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Ensure base64 padding is correct
        try:
            encrypted_data_bytes = base64.b64decode(encrypted_data + '=='[(len(encrypted_data) % 4):])  # Fix padding issue
        except Exception as e:
            raise ValueError("Base64 decoding error: " + str(e))
        
        decrypted = decryptor.update(encrypted_data_bytes) + decryptor.finalize()
        padding_length = decrypted[-1]
        
        return decrypted[:-padding_length].decode('utf-8')  # Return decrypted data
