import os.path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta, timezone


def issue_certificate(common_name, output_dir, ca_key_path="../certs/root/SecureChat-Root-CA.key",
                      ca_cert_path="../certs/root/SecureChat-Root-CA.crt"):
    """Issue server/client cert signed by Root CA (SAN = DNSName(CN))."""

    # ---------------------------------------------------
    # 1. Load Root CA private key
    # ---------------------------------------------------
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # ---------------------------------------------------
    # 2. Load Root CA certificate
    # ---------------------------------------------------
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # ---------------------------------------------------
    # 3. Generate new RSA private key for the issued cert
    # ---------------------------------------------------
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # ---------------------------------------------------
    # 4. Build subject (CN = the name you pass)
    # ---------------------------------------------------
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # ---------------------------------------------------
    # 5. Build SAN extension (SAN = DNSName(CN))
    # ---------------------------------------------------
    san = x509.SubjectAlternativeName([x509.DNSName(common_name)])

    # ---------------------------------------------------
    # 6. Build certificate
    # ---------------------------------------------------
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)                  # Root CA is issuer
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc).replace(tzinfo=None))
        .not_valid_after(datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # ---------------------------------------------------
    # 7. Save key and cert
    # ---------------------------------------------------

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Build full file paths
    key_filename = os.path.join(output_dir, f"{common_name}.key")
    crt_filename = os.path.join(output_dir, f"{common_name}.crt")

    # Step 1: create empty files first
    for filepath in [key_filename, crt_filename]:
        with open(filepath, "wb") as f:
            pass  # just create an empty file

    # Step 2: write the actual key and cert
    with open(key_filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(crt_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Issued certificate: {crt_filename}")
    print(f"Issued private key: {key_filename}")


issue_certificate("api.securechat.local", "../certs/server/")
issue_certificate("Ayan", "../certs/client/")
