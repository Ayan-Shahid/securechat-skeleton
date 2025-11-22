from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

# -------------------------------
# 1. Generate DH parameters (safe prime group)
# -------------------------------
def generate_dh_parameters(key_size=2048):
    """
    Generate DH parameters (p, g)
    """
    parameters = dh.generate_parameters(generator=2, key_size=key_size)
    return parameters


# -------------------------------
# 2. Generate DH private/public key pair
# -------------------------------
def generate_dh_keypair(parameters):
    """
    Generate DH private key and corresponding public key
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


# -------------------------------
# 3. Compute shared secret
# -------------------------------
def compute_shared_secret(private_key, peer_public_key):
    """
    Compute the shared secret Ks
    """
    shared_key = private_key.exchange(peer_public_key)
    return shared_key  # raw bytes


# -------------------------------
# 4. Derive session key: Trunc16(SHA256(Ks))
# -------------------------------
def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derive 16-byte session key from shared secret using SHA-256
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    full_hash = digest.finalize()
    return full_hash[:16]  # Truncate to 16 bytes
