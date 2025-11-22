import base64
import time
import hashlib

# -------------------------------
# 1. Current time in milliseconds
# -------------------------------
def now_ms() -> int:
    """
    Return current UTC timestamp in milliseconds
    """
    return int(time.time() * 1000)

# -------------------------------
# 2. Base64 encode bytes -> string
# -------------------------------
def b64e(b: bytes) -> str:
    """
    Base64 encode bytes -> string
    """
    return base64.b64encode(b).decode("utf-8")

# -------------------------------
# 3. Base64 decode string -> bytes
# -------------------------------
def b64d(s: str) -> bytes:
    """
    Base64 decode string -> bytes
    """
    return base64.b64decode(s.encode("utf-8"))

# -------------------------------
# 4. SHA-256 digest as hex string
# -------------------------------
def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 digest of data and return hex string
    """
    return hashlib.sha256(data).hexdigest()
