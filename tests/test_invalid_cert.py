"""Test: Invalid/Self-signed/Expired Certificate Rejection → BAD_CERT"""

import socket
import json
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import secrets

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5555

def b64e(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("utf-8")

def send_json(sock, data: dict):
    msg = json.dumps(data).encode("utf-8")
    length = len(msg).to_bytes(4, "big")
    sock.sendall(length + msg)

def recv_json(sock) -> dict:
    length_bytes = b""
    while len(length_bytes) < 4:
        chunk = sock.recv(4 - len(length_bytes))
        if not chunk:
            raise ConnectionError("Connection closed")
        length_bytes += chunk
    length = int.from_bytes(length_bytes, "big")
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return json.loads(data.decode("utf-8"))

def generate_self_signed_cert(cn="FakeClient", expired=False):
    """Generate a self-signed certificate (not signed by CA)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FakeOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    if expired:
        not_before = datetime.now(timezone.utc) - timedelta(days=365)
        not_after = datetime.now(timezone.utc) - timedelta(days=1)
    else:
        not_before = datetime.now(timezone.utc)
        not_after = datetime.now(timezone.utc) + timedelta(days=365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert, key

def test_self_signed_cert():
    """Test 1: Server should reject self-signed certificate."""
    print("\n" + "="*60)
    print("TEST 1: Self-Signed Certificate Rejection")
    print("="*60)
    cert, _ = generate_self_signed_cert("SelfSignedClient")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print("[*] Connected to server")
        nonce = b64e(secrets.token_bytes(16))
        send_json(sock, {
            "type": "hello",
            "client_cert": cert_pem,
            "nonce": nonce
        })
        print("[*] Sent hello with self-signed certificate")
        resp = recv_json(sock)
        print(f"[*] Server response: {resp}")
        if resp.get("type") == "error" and "BAD_CERT" in resp.get("message", ""):
            print("[+] TEST PASSED: Server rejected self-signed certificate")
            return True
        else:
            print("[-] TEST FAILED: Server did not reject self-signed certificate")
            return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    finally:
        sock.close()

def test_expired_cert():
    """Test 2: Server should reject expired certificate."""
    print("\n" + "="*60)
    print("TEST 2: Expired Certificate Rejection")
    print("="*60)
    cert, _ = generate_self_signed_cert("ExpiredClient", expired=True)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print("[*] Connected to server")
        nonce = b64e(secrets.token_bytes(16))
        send_json(sock, {
            "type": "hello",
            "client_cert": cert_pem,
            "nonce": nonce
        })
        print("[*] Sent hello with expired certificate")
        resp = recv_json(sock)
        print(f"[*] Server response: {resp}")
        if resp.get("type") == "error" and "BAD_CERT" in resp.get("message", ""):
            print("[+] TEST PASSED: Server rejected expired certificate")
            return True
        else:
            print("[-] TEST FAILED: Server did not reject expired certificate")
            return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    finally:
        sock.close()

def test_forged_cert():
    """Test 3: Server should reject certificate signed by different CA."""
    print("\n" + "="*60)
    print("TEST 3: Forged Certificate (Different CA) Rejection")
    print("="*60)
    # Create a fake CA
    fake_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    fake_ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FakeCA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Fake Root CA"),
    ])
    fake_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(fake_ca_subject)
        .issuer_name(fake_ca_subject)
        .public_key(fake_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=fake_ca_key, algorithm=hashes.SHA256())
    )
    # Issue client cert from fake CA
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ForgedClient"),
    ])
    forged_cert = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(fake_ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key=fake_ca_key, algorithm=hashes.SHA256())
    )
    cert_pem = forged_cert.public_bytes(serialization.Encoding.PEM).decode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print("[*] Connected to server")
        nonce = b64e(secrets.token_bytes(16))
        send_json(sock, {
            "type": "hello",
            "client_cert": cert_pem,
            "nonce": nonce
        })
        print("[*] Sent hello with forged certificate (different CA)")
        resp = recv_json(sock)
        print(f"[*] Server response: {resp}")
        if resp.get("type") == "error" and "BAD_CERT" in resp.get("message", ""):
            print("[+] TEST PASSED: Server rejected forged certificate")
            return True
        else:
            print("[-] TEST FAILED: Server did not reject forged certificate")
            return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    print("\n" + "#"*60)
    print("# CERTIFICATE VALIDATION TESTS")
    print("#"*60)
    results = []
    results.append(("Self-Signed Cert", test_self_signed_cert()))
    results.append(("Expired Cert", test_expired_cert()))
    results.append(("Forged Cert", test_forged_cert()))
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"  {name}: {status}")
    print("="*60)