"""Test: Resend old seqno → REPLAY rejection

Run: python test_replay.py
Requires: Server running on port 5555
"""

import socket
import json
import hashlib
import secrets
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuration - adjust paths as needed
CLIENT_CERT_PATH = "../certs/client/Ayan.crt"
CLIENT_KEY_PATH = "../certs/client/Ayan.key"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5555

DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
           "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
           "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
           "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
           "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
           "FFFFFFFFFFFFFFFF", 16)
DH_G = 2


def b64e(b):
    return base64.b64encode(b).decode("utf-8")


def b64d(s):
    return base64.b64decode(s.encode("utf-8"))


def now_ms():
    import time
    return int(time.time() * 1000)


def send_json(sock, data):
    msg = json.dumps(data).encode("utf-8")
    sock.sendall(len(msg).to_bytes(4, "big") + msg)


def recv_json(sock):
    length = int.from_bytes(recv_exact(sock, 4), "big")
    return json.loads(recv_exact(sock, length).decode("utf-8"))


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def derive_aes_key(shared_secret):
    ks_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    return hashlib.sha256(ks_bytes).digest()[:16]


def aes_encrypt_ecb(plaintext, key):
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def rsa_sign(private_key, message):
    return private_key.sign(message, asym_padding.PKCS1v15(), hashes.SHA256())


def test_replay_attack():
    """Test: Replaying old message (same seqno) should be rejected."""
    print("\n" + "=" * 60)
    print("TEST: Replay Attack Detection")
    print("=" * 60)

    # Load client credentials
    with open(CLIENT_CERT_PATH, "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())
    with open(CLIENT_KEY_PATH, "rb") as f:
        client_privkey = serialization.load_pem_private_key(f.read(), password=None)
    print("[*] Loaded client credentials")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")

        # Step 1: Hello exchange
        cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
        send_json(sock, {
            "type": "hello",
            "client_cert": cert_pem,
            "nonce": b64e(secrets.token_bytes(16))
        })
        resp = recv_json(sock)
        if resp.get("type") == "error":
            print(f"[-] Hello failed: {resp.get('message')}")
            return False
        print("[*] Hello exchange complete")

        # Step 2: Temp DH
        a = secrets.randbelow(DH_P - 2) + 1
        A = pow(DH_G, a, DH_P)
        send_json(sock, {"type": "dh_temp", "g": DH_G, "p": str(DH_P), "A": str(A)})
        resp = recv_json(sock)
        if resp.get("type") == "error":
            print(f"[-] DH failed: {resp.get('message')}")
            return False
        B = int(resp["B"])
        temp_key = derive_aes_key(pow(B, a, DH_P))
        print("[*] Temp DH complete")

        # Step 3: Register
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.sha256(salt + b"replaytest123").digest()
        username = f"replayuser{secrets.token_hex(4)}"
        payload = json.dumps({
            "email": f"{username}@test.com",
            "username": username,
            "pwd": b64e(pwd_hash),
            "salt": b64e(salt)
        }).encode()
        ct = aes_encrypt_ecb(payload, temp_key)
        send_json(sock, {"type": "register", "data": b64e(ct)})
        resp = recv_json(sock)
        if resp.get("type") == "error":
            print(f"[!] Registration note: {resp.get('message')}")
        else:
            print(f"[*] Registered as: {username}")

        # Step 4: Session DH
        a2 = secrets.randbelow(DH_P - 2) + 1
        A2 = pow(DH_G, a2, DH_P)
        send_json(sock, {"type": "dh_client", "g": DH_G, "p": str(DH_P), "A": str(A2)})
        resp = recv_json(sock)
        if resp.get("type") == "error":
            print(f"[-] Session DH failed: {resp.get('message')}")
            return False
        B2 = int(resp["B"])
        session_key = derive_aes_key(pow(B2, a2, DH_P))
        print("[*] Session key established")

        # Helper to create signed message
        def create_message(seqno, plaintext):
            ts = now_ms()
            ct = aes_encrypt_ecb(plaintext.encode(), session_key)
            digest_data = f"{seqno}".encode() + f"{ts}".encode() + ct
            digest = hashlib.sha256(digest_data).digest()
            sig = rsa_sign(client_privkey, digest)
            return {
                "type": "msg",
                "seqno": seqno,
                "ts": ts,
                "ct": b64e(ct),
                "sig": b64e(sig)
            }

        # Step 5: Send first message (seqno=1)
        print("\n[*] Sending message with seqno=1...")
        msg1 = create_message(1, "First message - seqno 1")
        send_json(sock, msg1)
        resp = recv_json(sock)
        print(f"    Response: type={resp.get('type')}")

        # Step 6: Send second message (seqno=2)
        print("[*] Sending message with seqno=2...")
        msg2 = create_message(2, "Second message - seqno 2")
        send_json(sock, msg2)
        resp = recv_json(sock)
        print(f"    Response: type={resp.get('type')}")

        # Step 7: Send third message (seqno=3)
        print("[*] Sending message with seqno=3...")
        msg3 = create_message(3, "Third message - seqno 3")
        send_json(sock, msg3)
        resp = recv_json(sock)
        print(f"    Response: type={resp.get('type')}")

        # Step 8: REPLAY ATTACK - Try to send seqno=1 again!
        print("\n" + "-" * 60)
        print("[!] ATTEMPTING REPLAY ATTACK!")
        print("    Sending message with seqno=1 (already used)")
        print("-" * 60)

        replay_msg = create_message(1, "This is a REPLAYED message!")
        send_json(sock, replay_msg)

        resp = recv_json(sock)
        print(f"\n[*] Server response to replay: {resp}")

        if resp.get("type") == "error" and "REPLAY" in resp.get("message", ""):
            print("\n" + "=" * 60)
            print("[+] TEST PASSED: Server detected replay attack!")
            print("    Server correctly rejected message with REPLAY error")
            print("    Sequence number protection is working")
            print("=" * 60)
            return True
        else:
            print("\n" + "=" * 60)
            print("[-] TEST FAILED: Server did not detect replay attack")
            print(f"    Expected error with REPLAY, got: {resp}")
            print("=" * 60)
            return False

    except ConnectionRefusedError:
        print("[!] Connection refused. Is the server running?")
        print("    Start server: python server.py")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sock.close()


if __name__ == "__main__":
    print("#" * 60)
    print("# REPLAY ATTACK TEST")
    print("# Tests that reusing old sequence numbers is rejected")
    print("#" * 60)

    result = test_replay_attack()

    print("\n" + "=" * 60)
    print(f"FINAL RESULT: {'PASSED ✓' if result else 'FAILED ✗'}")
    print("=" * 60)