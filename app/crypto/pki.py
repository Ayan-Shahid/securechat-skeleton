from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

def validate_certificate(cert_path, ca_cert_path, expected_hostname=None):
    """
    Validate an X.509 certificate.

    Args:
        cert_path: path to the certificate to validate
        ca_cert_path: path to CA certificate
        expected_hostname: optional, hostname to check CN/SAN

    Returns:
        True if valid, raises ValueError if invalid
    """
    # -----------------------------
    # Load the certificate and CA cert
    # -----------------------------
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # -----------------------------
    # 1. Check validity window
    # -----------------------------
    now = datetime.utcnow()
    if not (cert.not_valid_before <= now <= cert.not_valid_after):
        raise ValueError("Certificate not valid at this time")

    # -----------------------------
    # 2. Check that certificate is signed by the CA
    # -----------------------------
    try:
        ca_cert.public_key().verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise ValueError(f"Certificate signature invalid or not signed by CA: {e}")

    # -----------------------------
    # 3. Check CN/SAN for hostname if provided
    # -----------------------------
    if expected_hostname:
        # Extract CN
        cn_list = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        cn_valid = any(expected_hostname == cn.value for cn in cn_list)

        # Extract SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_list = []

        if expected_hostname not in san_list and not cn_valid:
            raise ValueError(f"Hostname {expected_hostname} not in CN or SAN")

    # -----------------------------
    # Passed all checks
    # -----------------------------
    return True
