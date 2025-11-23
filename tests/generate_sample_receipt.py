"""Generate sample transcript and receipt for offline verification testing."""

import json
import hashlib
import base64
import secrets
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Paths - adjust as needed
CLIENT_CERT_PATH = "../certs/client/Ayan.crt"
CLIENT_KEY_PATH = "../certs/client/Ayan.key"
OUTPUT_TRANSCRIPT = "sample_transcript.log"
OUTPUT_RECEIPT = "sample_receipt.json"


def b64e(b): return base64.b64encode(b).decode("utf-8")


def aes_encrypt_ecb(plaintext, key):
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def rsa_sign(private_key, message):
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def now_ms():
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def get_cert_fingerprint(cert):
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def main():
    print("=" * 60)
    print("GENERATING SAMPLE TRANSCRIPT AND RECEIPT")
    print("=" * 60)

    # Load credentials
    try:
        with open(CLIENT_CERT_PATH, "rb") as f:
            client_cert = x509.load_pem_x509_certificate(f.read())
        with open(CLIENT_KEY_PATH, "rb") as f:
            client_privkey = serialization.load_pem_private_key(f.read(), password=None)
        print("[+] Loaded client credentials")
    except FileNotFoundError as e:
        print(f"[!] Certificate not found: {e}")
        print("[*] Generating temporary keypair for demo...")
        client_privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Create self-signed cert for demo
        from cryptography.x509.oid import NameOID
        from datetime import timedelta
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DemoClient")])
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(client_privkey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(client_privkey, hashes.SHA256())
        )

    # Generate fake session key
    session_key = secrets.token_bytes(16)
    peer_fingerprint = get_cert_fingerprint(client_cert)

    # Sample messages
    messages = [
        "Hello server, this is my first message!",
        "Can you process this order for me?",
        "Thanks for the confirmation.",
        "Goodbye!"
    ]

    transcript_lines = []

    print(f"\n[*] Creating {len(messages)} sample messages...")

    for i, plaintext in enumerate(messages, 1):
        seqno = i
        ts = now_ms() + (i * 1000)  # Spread timestamps

        # Encrypt
        ct = aes_encrypt_ecb(plaintext.encode(), session_key)
        ct_b64 = b64e(ct)

        # Sign
        digest_data = f"{seqno}".encode() + f"{ts}".encode() + ct
        digest = hashlib.sha256(digest_data).digest()
        sig = rsa_sign(client_privkey, digest)
        sig_b64 = b64e(sig)

        # Transcript entry
        entry = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fingerprint}"
        transcript_lines.append(entry)
        print(f"  Message {seqno}: '{plaintext[:30]}...' -> encrypted & signed")

    # Save transcript
    with open(OUTPUT_TRANSCRIPT, "w") as f:
        f.write("\n".join(transcript_lines))
    print(f"\n[+] Transcript saved: {OUTPUT_TRANSCRIPT}")

    # Compute transcript hash
    transcript_hash = hashlib.sha256("\n".join(transcript_lines).encode()).hexdigest()
    print(f"[*] Transcript hash: {transcript_hash[:32]}...")

    # Sign transcript hash
    receipt_sig = rsa_sign(client_privkey, bytes.fromhex(transcript_hash))

    # Create receipt
    receipt = {
        "type": "receipt",
        "peer": "client",
        "first_seq": 1,
        "last_seq": len(messages),
        "transcript_sha256": transcript_hash,
        "sig": b64e(receipt_sig)
    }

    with open(OUTPUT_RECEIPT, "w") as f:
        json.dump(receipt, f, indent=2)
    print(f"[+] Receipt saved: {OUTPUT_RECEIPT}")

    # Save cert for verification
    cert_output = "sample_client.crt"
    with open(cert_output, "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved: {cert_output}")

    print("\n" + "=" * 60)
    print("TO VERIFY, RUN:")
    print("=" * 60)
    print(f"""
python verify_transcript.py \\
    --transcript {OUTPUT_TRANSCRIPT} \\
    --receipt {OUTPUT_RECEIPT} \\
    --cert {cert_output} \\
    --demo-tamper
""")

    print("\nThis will:")
    print("  1. Verify each message signature")
    print("  2. Verify receipt signature over transcript hash")
    print("  3. Demonstrate that tampering is detected")
    print("=" * 60)


if __name__ == "__main__":
    main()