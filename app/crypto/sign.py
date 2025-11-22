from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# -------------------------------
# 1. Sign a message with RSA private key (PKCS#1 v1.5, SHA-256)
# -------------------------------
def rsa_sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """
    Sign a message using RSA PKCS#1 v1.5 + SHA-256.

    Args:
        private_key: RSAPrivateKey object
        message: bytes to sign
    Returns:
        signature as bytes
    """
    signature = private_key.sign(
        data=message,
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA256()
    )
    return signature

# -------------------------------
# 2. Verify a message signature with RSA public key
# -------------------------------
def rsa_verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """
    Verify an RSA PKCS#1 v1.5 + SHA-256 signature.

    Args:
        public_key: RSAPublicKey object
        message: original message bytes
        signature: signature bytes
    Returns:
        True if valid, False otherwise
    """
    try:
        public_key.verify(
            signature=signature,
            data=message,
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA256()
        )
        return True
    except Exception:
        return False

# -------------------------------
# 3. Helper: generate RSA keypair
# -------------------------------
def generate_rsa_keypair(key_size=2048):
    """
    Generate RSA private/public keypair.

    Returns:
        (private_key, public_key)
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key
