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

    def b32_encode_nopadding(self, data : bytes):
        b32_encoded = base64.b32encode(data) 
        b32_nopadding = b32_encoded.decode().rstrip('=')
        return b32_nopadding
        
    def encrypt(self, data: str) -> str:
        iv = get_random_bytes(12)  # 96-bit IV
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        # Structure: [2-byte length][IV][ciphertext][tag]
        clen = len(ciphertext)
        packet = struct.pack(">H", clen) + iv + ciphertext + tag

        # Return Base32-encoded version
        return self.b32_encode_nopadding(packet)


class GCMDecryptor:
    def __init__(self, key: bytes=None):
        self.key = key if key is not None else KEY

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

        if len(data) < 2 + 12 + 16:
            raise ValueError("Input too short to be valid")

        clen = struct.unpack(">H", data[:2])[0]
        iv = data[2:14]
        ciphertext = data[14:14+clen]
        tag = data[14+clen:14+clen+16]

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
        except ValueError:
            raise ValueError("Decryption failed: authentication tag mismatch")
