# SecureChat — Console-Based CIANR Chat System

**Information Security — Assignment 02**
**FAST-NUCES**

This project implements a complete custom **secure chat protocol** that achieves:

* **C**onfidentiality (AES-128)
* **I**ntegrity (SHA-256 digests)
* **A**uthenticity (RSA signatures + certificates)
* **N**on-**R**epudiation (signed transcript receipts)

The system uses **no TLS/SSL**, and instead manually integrates crypto primitives at the **application layer**, as required by the assignment.

---

## 📌 Features Implemented

### ✔ 1. Public Key Infrastructure (PKI)

* Custom **Root CA**
* Issued **Server Certificate**
* Issued **Client Certificate**
* Mutual certificate validation
* Rejection of:

  * self-signed
  * forged
  * expired
  * untrusted certificates

Scripts:

```
scripts/gen_ca.py
scripts/gen_cert.py
```

---

### ✔ 2. Registration & Login (Encrypted)

* Temporary Diffie-Hellman for a **pre-authentication AES key**
* Credentials sent **only after certificate validation**
* Server generates:

  * Random 16-byte salt
  * `pwd_hash = SHA256(salt || password)`
* MySQL table:

```
users(email, username, salt, pwd_hash)
```

---

### ✔ 3. Session Key Establishment (DH)

After login:

* Fresh Diffie-Hellman exchange
* Shared secret `Ks = g^(ab) mod p`
* AES session key:

```
K = Trunc16( SHA256( big_endian(Ks) ) )
```

---

### ✔ 4. Encrypted Chat + Integrity + Replay Protection

Message format:

```
{
  "type": "msg",
  "seqno": n,
  "ts": unix_ms,
  "ct": base64(AES-128(ciphertext)),
  "sig": base64(RSA_SIGN(SHA256(seqno || ts || ct)))
}
```

Includes:

* PKCS#7 padding
* SHA-256 digest
* RSA signature
* Strict increasing `seqno`
* Timestamp freshness

---

### ✔ 5. Non-Repudiation (Session Evidence)

Server & client maintain full transcript:

```
seqno | timestamp | ciphertext | signature | cert-fingerprint
```

End-of-session:

* Both compute `TranscriptHash = SHA256(all lines)`
* Both sign it → **SessionReceipt**

Receipt format:

```
{
  "type": "receipt",
  "peer": "client|server",
  "first_seq": ...,
  "last_seq": ...,
  "transcript_sha256": "...",
  "sig": base64(signature)
}
```

---

## 📁 Project Structure

```
/scripts
    gen_ca.py
    gen_cert.py

/crypto
    aes.py
    sign.py

/common
    utils.py

/storage
    db.py

client.py
server.py
README.md
.gitignore
```

---

## 🛠️ Setup Instructions

### 1. Install Dependencies

```
pip install -r requirements.txt
```

### 2. Generate Certificates

```
python scripts/gen_ca.py
python scripts/gen_cert.py --server
python scripts/gen_cert.py --client
```

Certificates are stored in:

```
/certs/root
/certs/server
/certs/client
```

---

### 3. MySQL Setup

Create database:

```sql
CREATE DATABASE securechat;
```

Update `.env` with:

```
DB_HOST=localhost
DB_USER=root
DB_PASS=*****
DB_NAME=securechat
```

---

## ▶ Running the System

### Start Server

```
python server.py
```

### Start Client

```
python client.py
```

---

## 🧪 Testing & Evidence (Required for Report)

### ✔ Wireshark Tests

* All chat messages appear as encrypted ciphertext
* No plaintext passwords
* Display filters included in report

### ✔ Invalid Certificate Tests

* Self-signed → rejected
* Expired → rejected
* Wrong CA → rejected

### ✔ Tampering Test

* Modify ciphertext → `SIG_FAIL`

### ✔ Replay Test

* Resend old `seqno` → `REPLAY`

### ✔ Non-Repudiation Verification

* Export transcript
* Export SessionReceipt
* Offline verification:

  * recompute digests
  * verify RSA signatures
  * verify receipt signature over transcript hash

---

## 🔐 Security Notes

* No TLS/SSL used
* Uses **AES-128 in ECB mode** (assignment requirement)
* All sensitive data encrypted before transmission
* Private keys **never** committed to Git
* `.env`, `.venv`, `.idea`, `certs/` ignored via `.gitignore`

---

## 📜 Assignment Requirements Checklist

| Requirement                     | Status |
| ------------------------------- | ------ |
| Root CA + issued certificates   | ✅      |
| Mutual certificate validation   | ✅      |
| Encrypted registration/login    | ✅      |
| Salted SHA-256 password hashing | ✅      |
| DH session key exchange         | ✅      |
| AES-128 + PKCS#7                | ✅      |
| Per-message RSA signatures      | ✅      |
| Replay protection               | ✅      |
| Append-only transcript          | ✅      |
| Signed SessionReceipt           | ✅      |
| Wireshark + attack tests        | ✅      |

---

## 👨‍💻 Author

Ayan Shahid
22K-5082
FAST-NUCES

---
