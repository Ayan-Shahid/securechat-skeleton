"""Offline Verification: Verify transcript and SessionReceipt for Non-Repudiation

Usage:
    python verify_transcript.py -t transcript.log -r receipt.json -c client.crt
    python verify_transcript.py -t transcript.log -r receipt.json -c client.crt --demo-tamper
"""

import hashlib
import json
import argparse
import base64
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def b64d(s):
    """Base64 decode string to bytes."""
    return base64.b64decode(s.encode("utf-8"))


def load_certificate(cert_path):
    """Load X.509 certificate from file."""
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """Verify RSA PKCS#1 v1.5 + SHA-256 signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def parse_transcript_line(line: str) -> dict:
    """Parse transcript line format: seqno|ts|ct|sig|fingerprint"""
    parts = line.strip().split("|")
    if len(parts) != 5:
        raise ValueError(f"Invalid transcript line format. Expected 5 parts, got {len(parts)}")
    return {
        "seqno": int(parts[0]),
        "ts": int(parts[1]),
        "ct": parts[2],
        "sig": parts[3],
        "fingerprint": parts[4]
    }


def verify_message(entry: dict, public_key) -> bool:
    """Verify a single message's RSA signature.

    Signature is over: SHA256(seqno || ts || ct)
    """
    seqno = entry["seqno"]
    ts = entry["ts"]
    ct = b64d(entry["ct"])
    sig = b64d(entry["sig"])

    # Reconstruct digest: SHA256(seqno || ts || ct)
    digest_data = f"{seqno}".encode() + f"{ts}".encode() + ct
    digest = hashlib.sha256(digest_data).digest()

    return verify_signature(public_key, digest, sig)


def compute_transcript_hash(lines: list) -> str:
    """Compute SHA-256 hash of entire transcript (newline-joined)."""
    concatenated = "\n".join(lines)
    return hashlib.sha256(concatenated.encode()).hexdigest()


def verify_transcript(transcript_path: str, cert_path: str):
    """Step 1: Verify all individual message signatures in transcript."""
    print("\n" + "=" * 60)
    print("STEP 1: Verify Individual Message Signatures")
    print("=" * 60)

    cert = load_certificate(cert_path)
    public_key = cert.public_key()

    # Get certificate subject for display
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    cert_cn = cn_attrs[0].value if cn_attrs else "Unknown"
    print(f"  Certificate CN: {cert_cn}")
    print(f"  Certificate file: {cert_path}")
    print("-" * 60)

    with open(transcript_path, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]

    if not lines:
        print("  [!] Transcript is empty!")
        return False, []

    print(f"  Found {len(lines)} message(s) in transcript\n")

    all_valid = True
    for i, line in enumerate(lines):
        try:
            entry = parse_transcript_line(line)
            valid = verify_message(entry, public_key)

            if valid:
                status = "✓ VALID"
            else:
                status = "✗ INVALID"
                all_valid = False

            print(f"  Message seqno={entry['seqno']:3d}: {status}")

        except Exception as e:
            print(f"  Message {i + 1}: ✗ ERROR - {e}")
            all_valid = False

    print("-" * 60)
    if all_valid:
        print("  ✓ All message signatures verified successfully")
    else:
        print("  ✗ Some message signatures failed verification")

    return all_valid, lines


def verify_receipt(receipt_path: str, transcript_lines: list, cert_path: str):
    """Step 2: Verify SessionReceipt signature over transcript hash."""
    print("\n" + "=" * 60)
    print("STEP 2: Verify SessionReceipt")
    print("=" * 60)

    cert = load_certificate(cert_path)
    public_key = cert.public_key()

    with open(receipt_path, "r") as f:
        receipt = json.load(f)

    print(f"  Receipt file: {receipt_path}")
    print(f"  Peer: {receipt.get('peer')}")
    print(f"  Sequence range: {receipt.get('first_seq')} - {receipt.get('last_seq')}")
    print(f"  Stored transcript hash: {receipt.get('transcript_sha256')[:40]}...")
    print("-" * 60)

    # Recompute transcript hash from lines
    computed_hash = compute_transcript_hash(transcript_lines)
    print(f"  Computed transcript hash: {computed_hash[:40]}...")

    # Compare hashes
    if computed_hash != receipt.get("transcript_sha256"):
        print("\n  ✗ HASH MISMATCH!")
        print("    Transcript may have been tampered with!")
        print("    Expected: " + receipt.get("transcript_sha256")[:40] + "...")
        print("    Got:      " + computed_hash[:40] + "...")
        return False

    print("  ✓ Transcript hash matches receipt")

    # Verify RSA signature over transcript hash
    sig = b64d(receipt["sig"])
    hash_bytes = bytes.fromhex(receipt["transcript_sha256"])
    valid = verify_signature(public_key, hash_bytes, sig)

    print("-" * 60)
    if valid:
        print("  ✓ Receipt signature VALID")
        print("    → Non-repudiation established!")
        print("    → Signer cannot deny sending these messages")
    else:
        print("  ✗ Receipt signature INVALID")
        print("    → Cannot establish non-repudiation")

    return valid


def test_tamper_detection(transcript_path: str, cert_path: str, receipt_path: str):
    """Step 3: Demonstrate that any modification breaks verification."""
    print("\n" + "=" * 60)
    print("STEP 3: Tamper Detection Demonstration")
    print("=" * 60)

    with open(transcript_path, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]

    if not lines:
        print("  [!] No transcript lines to demonstrate tampering")
        return

    # Tamper: modify the sequence number of first message
    original_line = lines[0]
    parts = original_line.split("|")
    original_seqno = parts[0]
    parts[0] = str(int(parts[0]) + 999)  # Change seqno dramatically
    tampered_line = "|".join(parts)
    tampered_lines = [tampered_line] + lines[1:]

    print(f"  Original first message seqno: {original_seqno}")
    print(f"  Tampered first message seqno: {parts[0]}")
    print("-" * 60)

    # Load receipt
    with open(receipt_path, "r") as f:
        receipt = json.load(f)

    original_hash = receipt.get("transcript_sha256")
    tampered_hash = compute_transcript_hash(tampered_lines)

    print(f"  Original transcript hash: {original_hash[:40]}...")
    print(f"  Tampered transcript hash: {tampered_hash[:40]}...")
    print("-" * 60)

    if original_hash != tampered_hash:
        print("  ✓ TAMPER DETECTED!")
        print("    → Hashes do not match")
        print("    → Receipt signature verification would FAIL")
        print("    → Integrity violation proven")
    else:
        print("  ✗ WARNING: Hashes unexpectedly match")

    # Also show that message signature would fail
    print("\n  Additionally, the tampered message signature check:")
    cert = load_certificate(cert_path)
    try:
        entry = parse_transcript_line(tampered_line)
        valid = verify_message(entry, cert.public_key())
        if not valid:
            print("  ✓ Message signature INVALID (as expected)")
        else:
            print("  ✗ Message signature still valid (unexpected)")
    except Exception as e:
        print(f"  ✓ Verification failed with error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Verify SecureChat transcript and SessionReceipt for non-repudiation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_transcript.py -t client_transcript.log -r receipt.json -c Ayan.crt
  python verify_transcript.py -t transcript.log -r receipt.json -c cert.crt --demo-tamper
        """
    )
    parser.add_argument("--transcript", "-t", required=True,
                        help="Path to transcript log file")
    parser.add_argument("--receipt", "-r", required=True,
                        help="Path to SessionReceipt JSON file")
    parser.add_argument("--cert", "-c", required=True,
                        help="Path to sender's X.509 certificate (.crt/.pem)")
    parser.add_argument("--demo-tamper", action="store_true",
                        help="Demonstrate that tampering is detected")

    args = parser.parse_args()

    print("\n" + "#" * 60)
    print("# SECURECHAT NON-REPUDIATION VERIFICATION")
    print("#" * 60)

    try:
        # Step 1: Verify all message signatures
        msgs_valid, lines = verify_transcript(args.transcript, args.cert)

        # Step 2: Verify receipt signature
        receipt_valid = verify_receipt(args.receipt, lines, args.cert)

        # Step 3: Tamper demo (optional)
        if args.demo_tamper:
            test_tamper_detection(args.transcript, args.cert, args.receipt)

        # Final Summary
        print("\n" + "=" * 60)
        print("VERIFICATION SUMMARY")
        print("=" * 60)
        print(f"  All message signatures valid:  {'YES ✓' if msgs_valid else 'NO ✗'}")
        print(f"  Receipt signature valid:       {'YES ✓' if receipt_valid else 'NO ✗'}")

        if msgs_valid and receipt_valid:
            print("-" * 60)
            print("  ✓ NON-REPUDIATION ESTABLISHED")
            print("    The signer cannot deny having sent these messages.")
            print("    Transcript integrity is cryptographically verified.")
        else:
            print("-" * 60)
            print("  ✗ NON-REPUDIATION CANNOT BE ESTABLISHED")
            print("    Verification failed. Evidence may be tampered or invalid.")

        print("=" * 60 + "\n")

        # Exit code
        sys.exit(0 if (msgs_valid and receipt_valid) else 1)

    except FileNotFoundError as e:
        print(f"\n[!] File not found: {e}")
        print("    Make sure all file paths are correct.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"\n[!] Invalid JSON in receipt file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during verification: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()