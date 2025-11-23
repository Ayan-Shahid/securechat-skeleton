"""Complete Test Suite for SecureChat - Run all security tests"""

import subprocess
import sys
import os
from datetime import datetime


def run_test(script_name, description):
    """Run a test script and capture result."""
    print(f"\n{'=' * 70}")
    print(f"RUNNING: {description}")
    print(f"Script: {script_name}")
    print('=' * 70)

    try:
        result = subprocess.run(
            [sys.executable, script_name],
            capture_output=True,
            text=True,
            timeout=60
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("[-] Test timed out!")
        return False
    except FileNotFoundError:
        print(f"[-] Script not found: {script_name}")
        return False
    except Exception as e:
        print(f"[-] Error running test: {e}")
        return False


def generate_test_report(results: dict):
    """Generate test report file."""
    report_name = f"TestReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(report_name, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("SECURECHAT SECURITY TEST REPORT\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 70 + "\n\n")

        f.write("TEST RESULTS SUMMARY\n")
        f.write("-" * 70 + "\n")

        passed = 0
        failed = 0
        for test_name, result in results.items():
            status = "PASSED" if result else "FAILED"
            if result:
                passed += 1
            else:
                failed += 1
            f.write(f"  {test_name}: {status}\n")

        f.write("-" * 70 + "\n")
        f.write(f"Total: {passed} passed, {failed} failed\n")
        f.write("=" * 70 + "\n")

        # Evidence checklist
        f.write("\nEVIDENCE CHECKLIST FOR SUBMISSION\n")
        f.write("-" * 70 + "\n")
        f.write("[ ] Wireshark PCAP showing encrypted payloads\n")
        f.write("[ ] Screenshot: Invalid certificate rejection (BAD_CERT)\n")
        f.write("[ ] Screenshot: Expired certificate rejection (BAD_CERT)\n")
        f.write("[ ] Screenshot: Forged certificate rejection (BAD_CERT)\n")
        f.write("[ ] Screenshot: Tampered message detection (SIG_FAIL)\n")
        f.write("[ ] Screenshot: Replay attack detection (REPLAY)\n")
        f.write("[ ] Transcript file (client_transcript.log)\n")
        f.write("[ ] Session receipt JSON file\n")
        f.write("[ ] Offline verification output\n")
        f.write("=" * 70 + "\n")

    print(f"\n[+] Test report saved: {report_name}")
    return report_name


def main():
    print("#" * 70)
    print("# SECURECHAT COMPLETE TEST SUITE")
    print("#" * 70)
    print("\nMake sure the server is running before executing tests!")
    print("Start server: python server.py\n")

    input("Press Enter to start tests (or Ctrl+C to cancel)...")

    results = {}

    # Test 1: Invalid Certificate Tests
    if os.path.exists("test_invalid_cert.py"):
        results["Certificate Validation"] = run_test(
            "test_invalid_cert.py",
            "Certificate Validation Tests (Self-signed, Expired, Forged)"
        )
    else:
        print("[!] test_invalid_cert.py not found")
        results["Certificate Validation"] = False

    # Test 2: Tampering Test
    if os.path.exists("test_tamper.py"):
        results["Tampering Detection"] = run_test(
            "test_tamper.py",
            "Message Tampering Detection (SIG_FAIL)"
        )
    else:
        print("[!] test_tamper.py not found")
        results["Tampering Detection"] = False

    # Test 3: Replay Test
    if os.path.exists("test_replay.py"):
        results["Replay Protection"] = run_test(
            "test_replay.py",
            "Replay Attack Detection"
        )
    else:
        print("[!] test_replay.py not found")
        results["Replay Protection"] = False

    # Summary
    print("\n" + "#" * 70)
    print("# TEST SUITE SUMMARY")
    print("#" * 70)

    for test_name, passed in results.items():
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"  {test_name}: {status}")

    passed_count = sum(1 for r in results.values() if r)
    total_count = len(results)
    print(f"\nTotal: {passed_count}/{total_count} tests passed")

    # Generate report
    report_file = generate_test_report(results)

    print("\n" + "=" * 70)
    print("NEXT STEPS FOR EVIDENCE COLLECTION:")
    print("=" * 70)
    print("""
1. WIRESHARK CAPTURE:
   - Start Wireshark, capture on loopback interface
   - Filter: tcp.port == 5555
   - Run client/server, perform login and chat
   - Save PCAP file, take screenshots showing encrypted data

2. CERTIFICATE TESTS:
   - Take screenshots of test_invalid_cert.py output
   - Show BAD_CERT errors for each case

3. INTEGRITY TESTS:
   - Screenshot test_tamper.py showing SIG_FAIL
   - Screenshot test_replay.py showing REPLAY rejection

4. NON-REPUDIATION:
   - Run a chat session, collect transcript and receipt
   - Run: python verify_transcript.py -t transcript.log -r receipt.json -c cert.crt --demo-tamper
   - Screenshot the verification output

5. COMPILE REPORT:
   - Include all screenshots in your report document
   - Reference PCAP file
   - Include MySQL schema dump
""")


if __name__ == "__main__":
    main()