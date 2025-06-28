import struct
import base64
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Shared key (256-bit)
SECRET_KEY = os.environ.get("SHARED_KEY", None)

def derive_key_from_passphrase(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()  # 32-byte key

if SECRET_KEY:
    KEY = derive_key_from_passphrase(SECRET_KEY)
else:
    KEY = get_random_bytes(32)  # for local testing

class GCMEncryptor:
    def __init__(self, key: bytes=None):
        self.key = key if key is not None else KEY
        self.counter = 0
        self.initial_counter_set = False

    def set_initial_counter(self, counter: int):
        """Set the initial counter value"""
        self.counter = counter
        self.initial_counter_set = True
        
    def b32_encode_nopadding(self, data: bytes):
        b32_encoded = base64.b32encode(data) 
        return b32_encoded.decode().rstrip('=')
        
    def encrypt(self, data: str) -> str:
        # Use counter as nonce (96-bit)
        nonce = self.counter.to_bytes(12, 'big')
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        self.counter += 1  # Increment counter after each encryption

        # Structure: [2-byte length][ciphertext][tag]
        clen = len(ciphertext)
        packet = struct.pack(">H", clen) + ciphertext + tag

        # Return Base32-encoded version
        return self.b32_encode_nopadding(packet)

class GCMDecryptor:
    def __init__(self, key: bytes=None):
        self.key = key if key is not None else KEY
        self.counter = 0
        self.initial_counter_set = False

    def set_initial_counter(self, counter: int):
        """Set the initial counter value"""
        self.counter = counter
        self.initial_counter_set = True

    def base32_decode_unpadded(self, data: str) -> bytes:
        # Add padding if needed
        missing_padding = len(data) % 8
        if missing_padding:
            data += '=' * (8 - missing_padding)
        return base64.b32decode(data)

    def decrypt(self, b32_data: str) -> str:
        try:
            data = self.base32_decode_unpadded(b32_data)
        except Exception as e:
            raise ValueError("Invalid Base32 input") from e

        if len(data) < 2 + 16:  # Removed IV size check
            raise ValueError("Input too short to be valid")

        clen = struct.unpack(">H", data[:2])[0]
        ciphertext = data[2:2+clen]
        tag = data[2+clen:2+clen+16]

        # Use counter as nonce (96-bit)
        nonce = self.counter.to_bytes(12, 'big')
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            self.counter += 1  # Only increment counter if decryption succeeds
            return plaintext.decode()
        except ValueError:
            raise ValueError("Decryption failed: authentication tag mismatch")