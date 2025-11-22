from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    AES-128 encryption in ECB mode with PKCS#7 padding.

    Args:
        plaintext: bytes to encrypt
        key: 16-byte AES key
    Returns:
        ciphertext as bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    # PKCS#7 padding
    padder = padding.PKCS7(128).padder()  # block size 128 bits = 16 bytes
    padded_data = padder.update(plaintext) + padder.finalize()

    # AES-128 ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    AES-128 decryption in ECB mode with PKCS#7 unpadding.

    Args:
        ciphertext: bytes to decrypt
        key: 16-byte AES key
    Returns:
        plaintext as bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    # AES-128 ECB decryption
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

