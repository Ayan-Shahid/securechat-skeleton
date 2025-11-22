from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

# -------------------------------
# 1. Client hello
# -------------------------------
class Hello(BaseModel):
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# -------------------------------
# 2. Server hello
# -------------------------------
class ServerHello(BaseModel):
    server_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    server_nonce: str  # e.g., random string/hex

# -------------------------------
# 3. Register request
# -------------------------------
class Register(BaseModel):
    username: str
    password_hash: str  # hashed password
    client_pubkey: str  # PEM-encoded public key for client

# -------------------------------
# 4. Login request
# -------------------------------
class Login(BaseModel):
    username: str
    password_hash: str

# -------------------------------
# 5. Diffie-Hellman client message
# -------------------------------
class DHClient(BaseModel):
    username: str
    dh_pubkey: str  # PEM-encoded DH public key
    nonce: Optional[str]  # optional random nonce

# -------------------------------
# 6. Diffie-Hellman server message
# -------------------------------
class DHServer(BaseModel):
    dh_pubkey: str  # PEM-encoded DH public key
    server_nonce: str
    signature: str  # RSA signature of DH params or handshake data

# -------------------------------
# 7. Encrypted message
# -------------------------------
class Msg(BaseModel):
    sender: str
    recipient: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ciphertext: str  # hex or base64
    iv: Optional[str]  # if using CBC or GCM

# -------------------------------
# 8. Receipt / acknowledgment
# -------------------------------
class Receipt(BaseModel):
    message_id: str
    recipient: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: str  # e.g., "received", "read"
