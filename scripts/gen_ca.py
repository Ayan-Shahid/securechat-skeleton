from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone


def create_root_ca():
    """Create Root CA (RSA + self-signed X.509) using cryptography."""

    # ------------------------
    # 1. Generate RSA Key Pair
    # ------------------------
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    # ------------------------
    # 2. Certificate Subject/Issuer (same for self-signed root)
    # ------------------------
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])

    # ------------------------
    # 3. Build certificate
    # ------------------------
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc).replace(tzinfo=None))
        .not_valid_after(datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                key_agreement=False,
                data_encipherment=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    # ------------------------
    # 4. Write private key
    # ------------------------
    with open("../certs/root/SecureChat-Root-CA.key", "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # ------------------------
    # 5. Write certificate
    # ------------------------
    with open("../certs/root/SecureChat-Root-CA.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Root CA created: SecureChat-Root-CA.key + SecureChat-Root-CA.crt")

create_root_ca()

