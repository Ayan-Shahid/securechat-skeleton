"""SecureChat Server — plain TCP; no TLS. Implements full CIANR protocol."""

import socket
import json
import hashlib
import secrets
import threading
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from crypto.sign import rsa_sign, rsa_verify
from common.utils import b64e, b64d, now_ms
from storage.db import get_connection, create_users_table

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 5555
CA_CERT_PATH = "../certs/root/SecureChat-Root-CA.crt"
SERVER_CERT_PATH = "../certs/server/api.securechat.local.crt"
SERVER_KEY_PATH = "../certs/server/api.securechat.local.key"
TRANSCRIPT_DIR = "server_transcripts"

# DH parameters (must match client)
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
           "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
           "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
           "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
           "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
           "FFFFFFFFFFFFFFFF", 16)
DH_G = 2

class ClientHandler:
    def __init__(self, conn, addr, server_cert, server_privkey, ca_cert):
        self.conn = conn
        self.addr = addr
        self.server_cert = server_cert
        self.server_privkey = server_privkey
        self.ca_cert = ca_cert
        self.client_cert = None
        self.client_pubkey = None
        self.session_key = None
        self.temp_dh_key = None
        self.username = None
        self.seqno = 0
        self.expected_seqno = 0
        self.transcript = []
        self.authenticated = False

    def _send_json(self, data: dict):
        """Send JSON message over socket."""
        msg = json.dumps(data).encode("utf-8")
        length = len(msg).to_bytes(4, "big")
        self.conn.sendall(length + msg)

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
            chunk = self.conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def _send_error(self, message: str):
        """Send error response."""
        self._send_json({"type": "error", "message": message})

    def _verify_certificate(self, cert_pem: str) -> x509.Certificate:
        """Verify client certificate against CA."""
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        now = datetime.now(timezone.utc)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise ValueError("BAD_CERT: Certificate expired or not yet valid")
        try:
            self.ca_cert.public_key().verify(
                cert.signature, cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(), cert.signature_hash_algorithm
            )
        except Exception as e:
            raise ValueError(f"BAD_CERT: Signature invalid - {e}")
        return cert

    def _derive_aes_key(self, shared_secret: int) -> bytes:
        """Derive AES-128 key: Trunc16(SHA256(big-endian(Ks)))"""
        ks_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
        return hashlib.sha256(ks_bytes).digest()[:16]

    def _get_cert_fingerprint(self, cert: x509.Certificate) -> str:
        """Get SHA-256 fingerprint of certificate."""
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    def _append_transcript(self, seqno, ts, ct, sig, peer_fingerprint):
        """Append message to transcript."""
        entry = f"{seqno}|{ts}|{ct}|{sig}|{peer_fingerprint}"
        self.transcript.append(entry)

    def _compute_transcript_hash(self) -> str:
        """Compute SHA-256 hash of entire transcript."""
        concatenated = "\n".join(self.transcript)
        return hashlib.sha256(concatenated.encode()).hexdigest()

    def _save_transcript(self):
        """Save transcript to file."""
        import os
        os.makedirs(TRANSCRIPT_DIR, exist_ok=True)
        fname = f"{TRANSCRIPT_DIR}/{self.username or 'unknown'}_{now_ms()}.log"
        with open(fname, "w") as f:
            f.write("\n".join(self.transcript))
        print(f"[*] Transcript saved: {fname}")

    def handle_hello(self):
        """Handle client hello and send server hello."""
        msg = self._recv_json()
        if msg.get("type") != "hello":
            self._send_error("Expected hello message")
            return False
        try:
            self.client_cert = self._verify_certificate(msg["client_cert"])
            self.client_pubkey = self.client_cert.public_key()
            print(f"[+] Client certificate verified: {self.addr}")
        except ValueError as e:
            self._send_error(str(e))
            print(f"[!] {e}")
            return False
        server_cert_pem = self.server_cert.public_bytes(serialization.Encoding.PEM).decode()
        server_nonce = b64e(secrets.token_bytes(16))
        self._send_json({
            "type": "server_hello",
            "server_cert": server_cert_pem,
            "nonce": server_nonce
        })
        print(f"[*] Sent server hello to {self.addr}")
        return True

    def handle_temp_dh(self, msg: dict):
        """Handle temporary DH exchange for registration/login."""
        p = int(msg["p"])
        A = int(msg["A"])
        b = secrets.randbelow(p - 2) + 1
        B = pow(DH_G, b, p)
        Ks = pow(A, b, p)
        self.temp_dh_key = self._derive_aes_key(Ks)
        self._send_json({"type": "dh_temp_resp", "B": str(B)})
        print(f"[*] Temp DH exchange complete with {self.addr}")

    def handle_register(self, msg: dict):
        """Handle user registration."""
        try:
            ct = b64d(msg["data"])
            payload = aes_decrypt_ecb(ct, self.temp_dh_key)
            data = json.loads(payload.decode())
            email = data["email"]
            username = data["username"]
            pwd_hash = data["pwd"]
            salt = data["salt"]
            conn = get_connection()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM users WHERE email=%s OR username=%s", (email, username))
                    if cur.fetchone():
                        self._send_error("User already exists")
                        return False
                    cur.execute(
                        "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                        (email, username, salt, pwd_hash)
                    )
                conn.commit()
            finally:
                conn.close()
            self.username = username
            self.authenticated = True
            self._send_json({"type": "register_ok", "username": username})
            print(f"[+] User registered: {username}")
            return True
        except Exception as e:
            self._send_error(f"Registration failed: {e}")
            return False

    def handle_get_salt(self, msg: dict):
        """Return salt for user login."""
        email = msg["email"]
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT salt FROM users WHERE email=%s", (email,))
                row = cur.fetchone()
            if not row:
                self._send_error("User not found")
                return
            self._send_json({"type": "salt_resp", "salt": row["salt"]})
        finally:
            conn.close()

    def handle_login(self, msg: dict):
        """Handle user login."""
        try:
            ct = b64d(msg["data"])
            payload = aes_decrypt_ecb(ct, self.temp_dh_key)
            data = json.loads(payload.decode())
            email = data["email"]
            pwd_hash = data["pwd"]
            conn = get_connection()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT username, pwd_hash FROM users WHERE email=%s", (email,))
                    row = cur.fetchone()
            finally:
                conn.close()
            if not row:
                self._send_error("Invalid credentials")
                return False
            # Constant-time compare
            stored_hash = row["pwd_hash"]
            if not secrets.compare_digest(pwd_hash, stored_hash):
                self._send_error("Invalid credentials")
                return False
            self.username = row["username"]
            self.authenticated = True
            self._send_json({"type": "login_ok", "username": self.username})
            print(f"[+] User logged in: {self.username}")
            return True
        except Exception as e:
            self._send_error(f"Login failed: {e}")
            return False

    def handle_session_dh(self, msg: dict):
        """Handle session key DH exchange."""
        p = int(msg["p"])
        A = int(msg["A"])
        b = secrets.randbelow(p - 2) + 1
        B = pow(DH_G, b, p)
        Ks = pow(A, b, p)
        self.session_key = self._derive_aes_key(Ks)
        self._send_json({"type": "dh_server", "B": str(B)})
        print(f"[+] Session key established with {self.username}")

    def handle_message(self, msg: dict):
        """Handle encrypted message from client."""
        seqno = msg["seqno"]
        ts = msg["ts"]
        ct_b64 = msg["ct"]
        sig_b64 = msg["sig"]
        # Replay protection
        if seqno <= self.expected_seqno:
            self._send_error(f"REPLAY: seqno {seqno} already seen")
            return None
        self.expected_seqno = seqno
        # Verify signature
        ct = b64d(ct_b64)
        sig = b64d(sig_b64)
        digest_data = f"{seqno}".encode() + f"{ts}".encode() + ct
        digest = hashlib.sha256(digest_data).digest()
        if not rsa_verify(self.client_pubkey, digest, sig):
            self._send_error("SIG_FAIL: Invalid signature")
            return None
        # Decrypt
        plaintext = aes_decrypt_ecb(ct, self.session_key).decode()
        # Append to transcript
        self._append_transcript(seqno, ts, ct_b64, sig_b64, self._get_cert_fingerprint(self.client_cert))
        print(f"[<] {self.username}: {plaintext}")
        return plaintext

    def send_message(self, plaintext: str):
        """Send encrypted, signed message to client."""
        self.seqno += 1
        ts = now_ms()
        ct = aes_encrypt_ecb(plaintext.encode(), self.session_key)
        ct_b64 = b64e(ct)
        digest_data = f"{self.seqno}".encode() + f"{ts}".encode() + ct
        digest = hashlib.sha256(digest_data).digest()
        sig = rsa_sign(self.server_privkey, digest)
        self._send_json({
            "type": "msg",
            "seqno": self.seqno,
            "ts": ts,
            "ct": ct_b64,
            "sig": b64e(sig)
        })
        self._append_transcript(self.seqno, ts, ct_b64, b64e(sig), self._get_cert_fingerprint(self.client_cert))
        print(f"[>] Server: {plaintext}")

    def handle_receipt(self, msg: dict):
        """Handle client's session receipt."""
        transcript_hash = msg["transcript_sha256"]
        sig = b64d(msg["sig"])
        if rsa_verify(self.client_pubkey, bytes.fromhex(transcript_hash), sig):
            print(f"[+] Client receipt verified for {self.username}")
        else:
            print(f"[!] Client receipt INVALID for {self.username}")
        self._save_transcript()

    def send_receipt(self):
        """Send server's session receipt."""
        transcript_hash = self._compute_transcript_hash()
        sig = rsa_sign(self.server_privkey, bytes.fromhex(transcript_hash))
        self._send_json({
            "type": "receipt",
            "peer": "server",
            "first_seq": 1 if self.transcript else 0,
            "last_seq": self.seqno,
            "transcript_sha256": transcript_hash,
            "sig": b64e(sig)
        })
        print(f"[+] Session receipt sent to {self.username}")

    def run(self):
        """Main handler loop."""
        try:
            if not self.handle_hello():
                return
            while True:
                msg = self._recv_json()
                msg_type = msg.get("type")
                if msg_type == "dh_temp":
                    self.handle_temp_dh(msg)
                elif msg_type == "register":
                    self.handle_register(msg)
                elif msg_type == "get_salt":
                    self.handle_get_salt(msg)
                elif msg_type == "login":
                    self.handle_login(msg)
                elif msg_type == "dh_client":
                    if not self.authenticated:
                        self._send_error("Not authenticated")
                        continue
                    self.handle_session_dh(msg)
                elif msg_type == "msg":
                    if not self.session_key:
                        self._send_error("No session key")
                        continue
                    plaintext = self.handle_message(msg)
                    if plaintext:
                        # Echo back (or implement chat logic)
                        self.send_message(f"Echo: {plaintext}")
                elif msg_type == "receipt":
                    self.handle_receipt(msg)
                    self.send_receipt()
                    break
                else:
                    self._send_error(f"Unknown message type: {msg_type}")
        except ConnectionError:
            print(f"[*] Client disconnected: {self.addr}")
        except Exception as e:
            print(f"[!] Error handling {self.addr}: {e}")
        finally:
            self.conn.close()

class SecureChatServer:
    def __init__(self):
        self.server_cert = None
        self.server_privkey = None
        self.ca_cert = None
        self._load_credentials()

    def _load_credentials(self):
        """Load server certificate, key, and CA cert."""
        with open(SERVER_CERT_PATH, "rb") as f:
            self.server_cert = x509.load_pem_x509_certificate(f.read())
        with open(SERVER_KEY_PATH, "rb") as f:
            self.server_privkey = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())
        print("[*] Server credentials loaded")

    def start(self):
        """Start the server."""
        create_users_table()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[*] SecureChat Server listening on {HOST}:{PORT}")
        try:
            while True:
                conn, addr = sock.accept()
                print(f"[+] Connection from {addr}")
                handler = ClientHandler(conn, addr, self.server_cert, self.server_privkey, self.ca_cert)
                thread = threading.Thread(target=handler.run, daemon=True)
                thread.start()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down")
        finally:
            sock.close()

def main():
    server = SecureChatServer()
    server.start()

if __name__ == "__main__":
    main()