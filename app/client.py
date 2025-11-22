"""SecureChat Client — plain TCP; no TLS. Implements full CIANR protocol."""

import socket
import json
import hashlib
import secrets
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from crypto.sign import rsa_sign, rsa_verify
from common.utils import b64e, b64d, now_ms

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5555
CA_CERT_PATH = "../certs/root/SecureChat-Root-CA.crt"
CLIENT_CERT_PATH = "../certs/client/Ayan.crt"
CLIENT_KEY_PATH = "../certs/client/Ayan.key"
TRANSCRIPT_FILE = "client_transcript.log"

# DH parameters (safe primes - in production use larger/standard groups)
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
           "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
           "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
           "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
           "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
           "FFFFFFFFFFFFFFFF", 16)
DH_G = 2


class SecureChatClient:
    def __init__(self):
        self.sock = None
        self.session_key = None
        self.seqno = 0
        self.expected_seqno = 0
        self.transcript = []
        self.username = None
        self.server_cert = None
        self.server_pubkey = None
        self.client_cert = None
        self.client_privkey = None
        self._load_client_credentials()

    def _load_client_credentials(self):
        """Load client certificate and private key."""
        with open(CLIENT_CERT_PATH, "rb") as f:
            self.client_cert = x509.load_pem_x509_certificate(f.read())
        with open(CLIENT_KEY_PATH, "rb") as f:
            self.client_privkey = serialization.load_pem_private_key(f.read(), password=None)
        print("[*] Client credentials loaded")

    def _load_ca_cert(self):
        """Load CA certificate for verification."""
        with open(CA_CERT_PATH, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def _send_json(self, data: dict):
        """Send JSON message over socket."""
        msg = json.dumps(data).encode("utf-8")
        length = len(msg).to_bytes(4, "big")
        self.sock.sendall(length + msg)

    def _recv_json(self) -> dict:
        """Receive JSON message from socket."""

        length_bytes = self._recv_exact(4)
        length = int.from_bytes(length_bytes, "big")
        data = self._recv_exact(length)

        return json.loads(data.decode("utf-8"))

    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes."""
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def _verify_certificate(self, cert_pem: str, expected_cn: str = None) -> x509.Certificate:
        """Verify certificate against CA and optionally check CN."""
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        ca_cert = self._load_ca_cert()
        now = datetime.now(timezone.utc)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise ValueError("BAD_CERT: Certificate expired or not yet valid")
        try:
            ca_cert.public_key().verify(
                cert.signature, cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(), cert.signature_hash_algorithm
            )
        except Exception as e:
            raise ValueError(f"BAD_CERT: Signature invalid - {e}")
        if expected_cn:
            cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if not any(expected_cn == cn.value for cn in cn_attrs):
                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san_list = san.value.get_values_for_type(x509.DNSName)
                    if expected_cn not in san_list:
                        raise ValueError(f"BAD_CERT: CN/SAN mismatch")
                except x509.ExtensionNotFound:
                    raise ValueError(f"BAD_CERT: CN mismatch, no SAN")
        return cert

    def _derive_aes_key(self, shared_secret: int) -> bytes:
        """Derive AES-128 key: Trunc16(SHA256(big-endian(Ks)))"""
        ks_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
        return hashlib.sha256(ks_bytes).digest()[:16]

    def _append_transcript(self, seqno, ts, ct, sig, peer_fingerprint):
        """Append message to transcript for non-repudiation."""
        entry = f"{seqno}|{ts}|{ct}|{sig}|{peer_fingerprint}"
        self.transcript.append(entry)
        with open(TRANSCRIPT_FILE, "a") as f:
            f.write(entry + "\n")

    def _compute_transcript_hash(self) -> str:
        """Compute SHA-256 hash of entire transcript."""
        concatenated = "\n".join(self.transcript)
        return hashlib.sha256(concatenated.encode()).hexdigest()

    def _get_cert_fingerprint(self, cert: x509.Certificate) -> str:
        """Get SHA-256 fingerprint of certificate."""
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    def connect(self):
        """Establish TCP connection to server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")

    def handshake(self):
        """Phase 1: Certificate exchange and mutual authentication."""
        client_nonce = b64e(secrets.token_bytes(16))
        client_cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM).decode()
        self._send_json({
            "type": "hello",
            "client_cert": client_cert_pem,
            "nonce": client_nonce
        })
        print("[*] Sent client hello")
        resp = self._recv_json()
        if resp.get("type") == "error":
            raise ValueError(f"Server error: {resp.get('message')}")
        if resp.get("type") != "server_hello":
            raise ValueError(f"Unexpected response: {resp.get('type')}")
        server_cert_pem = resp["server_cert"]
        self.server_cert = self._verify_certificate(server_cert_pem, "api.securechat.local")
        self.server_pubkey = self.server_cert.public_key()
        print("[*] Server certificate verified")
        return resp.get("nonce")

    def _temp_dh_exchange(self) -> bytes:
        """Temporary DH for encrypting registration/login."""
        a = secrets.randbelow(DH_P - 2) + 1
        A = pow(DH_G, a, DH_P)
        self._send_json({"type": "dh_temp", "g": DH_G, "p": str(DH_P), "A": str(A)})
        resp = self._recv_json()
        if resp.get("type") == "error":
            raise ValueError(f"DH error: {resp.get('message')}")
        B = int(resp["B"])
        Ks = pow(B, a, DH_P)
        return self._derive_aes_key(Ks)

    def register(self, email: str, username: str, password: str):
        """Phase 2a: Register new user (encrypted under temp DH key)."""
        temp_key = self._temp_dh_exchange()
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).digest()
        payload = json.dumps({
            "email": email,
            "username": username,
            "pwd": b64e(pwd_hash),
            "salt": b64e(salt)
        }).encode()
        ct = aes_encrypt_ecb(payload, temp_key)
        self._send_json({"type": "register", "data": b64e(ct)})
        resp = self._recv_json()
        if resp.get("type") == "error":
            print(f"[!] Registration failed: {resp.get('message')}")
            return False
        print(f"[+] Registration successful for {username}")
        self.username = username
        return True

    def login(self, email: str, password: str):
        """Phase 2b: Login existing user (encrypted under temp DH key)."""
        temp_key = self._temp_dh_exchange()
        nonce = b64e(secrets.token_bytes(16))
        # Request salt from server first
        self._send_json({"type": "get_salt", "email": email})
        salt_resp = self._recv_json()
        if salt_resp.get("type") == "error":
            print(f"[!] Login failed: {salt_resp.get('message')}")
            return False
        salt = b64d(salt_resp["salt"])
        pwd_hash = hashlib.sha256(salt + password.encode()).digest()
        payload = json.dumps({
            "email": email,
            "pwd": b64e(pwd_hash),
            "nonce": nonce
        }).encode()
        ct = aes_encrypt_ecb(payload, temp_key)
        self._send_json({"type": "login", "data": b64e(ct)})
        resp = self._recv_json()
        if resp.get("type") == "error":
            print(f"[!] Login failed: {resp.get('message')}")
            return False
        print(f"[+] Login successful")
        self.username = resp.get("username", email)
        return True

    def session_key_exchange(self):
        """Phase 3: Establish session key via DH after authentication."""
        a = secrets.randbelow(DH_P - 2) + 1
        A = pow(DH_G, a, DH_P)
        self._send_json({
            "type": "dh_client",
            "g": DH_G,
            "p": str(DH_P),
            "A": str(A)
        })
        print("[*] Sent DH client parameters")
        resp = self._recv_json()
        if resp.get("type") == "error":
            raise ValueError(f"DH error: {resp.get('message')}")
        B = int(resp["B"])
        Ks = pow(B, a, DH_P)
        self.session_key = self._derive_aes_key(Ks)
        print("[+] Session key established")

    def send_message(self, plaintext: str):
        """Phase 4: Send encrypted, signed message."""
        self.seqno += 1
        ts = now_ms()
        ct = aes_encrypt_ecb(plaintext.encode(), self.session_key)
        ct_b64 = b64e(ct)
        # Compute digest: SHA256(seqno || ts || ct)
        digest_data = f"{self.seqno}".encode() + f"{ts}".encode() + ct
        digest = hashlib.sha256(digest_data).digest()
        sig = rsa_sign(self.client_privkey, digest)
        self._send_json({
            "type": "msg",
            "seqno": self.seqno,
            "ts": ts,
            "ct": ct_b64,
            "sig": b64e(sig)
        })
        # Append to transcript
        self._append_transcript(
            self.seqno, ts, ct_b64, b64e(sig),
            self._get_cert_fingerprint(self.server_cert)
        )
        print(f"[>] Sent message (seqno={self.seqno})")

    def receive_message(self) -> str:
        """Receive and verify encrypted message."""
        resp = self._recv_json()
        if resp.get("type") == "error":
            raise ValueError(f"Error: {resp.get('message')}")
        if resp.get("type") == "receipt":
            return self._handle_receipt(resp)
        if resp.get("type") != "msg":
            raise ValueError(f"Unexpected type: {resp.get('type')}")
        seqno = resp["seqno"]
        ts = resp["ts"]
        ct_b64 = resp["ct"]
        sig_b64 = resp["sig"]
        # Replay protection
        if seqno <= self.expected_seqno:
            raise ValueError(f"REPLAY: seqno {seqno} <= expected {self.expected_seqno}")
        self.expected_seqno = seqno
        # Verify signature
        ct = b64d(ct_b64)
        sig = b64d(sig_b64)
        digest_data = f"{seqno}".encode() + f"{ts}".encode() + ct
        digest = hashlib.sha256(digest_data).digest()
        if not rsa_verify(self.server_pubkey, digest, sig):
            raise ValueError("SIG_FAIL: Message signature invalid")
        # Decrypt
        plaintext = aes_decrypt_ecb(ct, self.session_key).decode()
        # Append to transcript
        self._append_transcript(
            seqno, ts, ct_b64, sig_b64,
            self._get_cert_fingerprint(self.server_cert)
        )
        print(f"[<] Received message (seqno={seqno})")
        return plaintext

    def _handle_receipt(self, resp: dict) -> str:
        """Handle session receipt from server."""
        print("[*] Received session receipt")
        transcript_hash = resp["transcript_sha256"]
        sig = b64d(resp["sig"])
        if not rsa_verify(self.server_pubkey, bytes.fromhex(transcript_hash), sig):
            print("[!] Receipt signature invalid")
        else:
            print("[+] Receipt signature verified")
        return f"SESSION_RECEIPT: {resp}"

    def send_receipt(self):
        """Phase 5: Send session receipt for non-repudiation."""
        transcript_hash = self._compute_transcript_hash()
        sig = rsa_sign(self.client_privkey, bytes.fromhex(transcript_hash))
        first_seq = 1 if self.transcript else 0
        last_seq = self.seqno
        self._send_json({
            "type": "receipt",
            "peer": "client",
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": b64e(sig)
        })
        print(f"[+] Session receipt sent (hash={transcript_hash[:16]}...)")

    def close(self):
        """Close connection."""
        if self.sock:
            self.sock.close()
            print("[*] Connection closed")


def main():
    client = SecureChatClient()
    authenticated = False
    try:
        client.connect()
        client.handshake()
        print("\n=== SecureChat Client ===")
        print("Commands: /register, /login, /quit")
        print("After login, type messages to send.\n")

        while True:
            cmd = input("> ").strip()
            if cmd == "/quit":
                if authenticated:
                    client.send_receipt()
                break
            elif cmd == "/register":
                email = input("Email: ").strip()
                username = input("Username: ").strip()
                password = input("Password: ").strip()
                if client.register(email, username, password):
                    client.session_key_exchange()
                    authenticated = True
                    print("[+] Ready to chat!")
            elif cmd == "/login":
                email = input("Email: ").strip()
                password = input("Password: ").strip()
                if client.login(email, password):
                    client.session_key_exchange()
                    authenticated = True
                    print("[+] Ready to chat!")
            elif authenticated and cmd:
                client.send_message(cmd)
                try:
                    client.sock.settimeout(0.5)
                    msg = client.receive_message()
                    print(f"Server: {msg}")
                except socket.timeout:
                    pass
                finally:
                    client.sock.settimeout(None)
            elif not authenticated and cmd:
                print("[!] Please /login or /register first")
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
        if authenticated:
            client.send_receipt()
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
