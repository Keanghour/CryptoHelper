from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

class AESEncryptionDecryption:
    def __init__(self):
        self.key = None
        self.secret_key = None

    def encrypt_aes(self, str_to_encrypt, secret):
        try:
            self.set_key(secret)
            cipher = AES.new(self.secret_key, AES.MODE_ECB)  # Using ECB mode
            encrypted_data = cipher.encrypt(pad(str_to_encrypt.encode(), AES.block_size))  # Padding to block size
            return base64.b64encode(encrypted_data).decode('utf-8')  # Return base64 encoded encrypted data
        except Exception as e:
            print(f"Error while encrypting: {e}")
        return None

    def decrypt_aes(self, str_to_decrypt, secret):
        try:
            self.set_key(secret)
            cipher = AES.new(self.secret_key, AES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(base64.b64decode(str_to_decrypt)), AES.block_size).decode('utf-8')  # Unpadding
            return decrypted_data
        except Exception as e:
            print(f"Error while decrypting: {e}")
        return None

    def set_key(self, my_key):
        try:
            self.key = hashlib.sha1(my_key.encode()).digest()[:16]  # Ensure the key is 16 bytes long
            self.secret_key = self.key
        except Exception as e:
            print(f"Error setting key: {e}")
