import os
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set in the environment variables.")

_AES_KEY = hashlib.sha256(SECRET_KEY.encode()).digest()
_FIXED_IV = b'\x00' * 16

def hash_key(content: str) -> str:
    cleaned = content.replace(" ", "").replace("\t", "").replace("\n", "")
    combined = f"{cleaned}{SECRET_KEY}".encode('utf-8')
    return hashlib.sha256(combined).hexdigest()

def enco(content: str) -> str:
    if content is None:
        return ""

    cipher = AES.new(_AES_KEY, AES.MODE_CBC, _FIXED_IV)
    padded = pad(content.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode('utf-8')

def decr(b64_ciphertext: str) -> str:
    try:
        cipher = AES.new(_AES_KEY, AES.MODE_CBC, _FIXED_IV)
        ct_bytes = base64.b64decode(b64_ciphertext)
        decrypted = cipher.decrypt(ct_bytes)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded.decode('utf-8')
    except Exception:
        return b64_ciphertext
