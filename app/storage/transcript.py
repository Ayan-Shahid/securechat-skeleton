import hashlib
from typing import List, Optional
from datetime import datetime

class TranscriptEntry:
    def __init__(self, sender: str, recipient: str, message: str, timestamp: Optional[float] = None):
        self.sender = sender
        self.recipient = recipient
        self.message = message
        self.timestamp = timestamp or datetime.utcnow().timestamp()

    def to_bytes(self) -> bytes:
        """
        Convert entry to bytes for hashing
        """
        return f"{self.timestamp}|{self.sender}|{self.recipient}|{self.message}".encode("utf-8")


class Transcript:
    def __init__(self):
        self.entries: List[TranscriptEntry] = []

    def append(self, sender: str, recipient: str, message: str):
        entry = TranscriptEntry(sender, recipient, message)
        self.entries.append(entry)
        return entry

    def transcript_hash(self) -> str:
        """
        Compute a single SHA-256 hash over all transcript entries
        """
        h = hashlib.sha256()
        for entry in self.entries:
            h.update(entry.to_bytes())
        return h.hexdigest()

    def last_entry_hash(self) -> Optional[str]:
        """
        Hash of last entry only (useful for chaining)
        """
        if not self.entries:
            return None
        return hashlib.sha256(self.entries[-1].to_bytes()).hexdigest()

    def append_with_chain(self, sender: str, recipient: str, message: str):
        """
        Append entry including previous entry hash for tamper-evident chaining
        """
        prev_hash = self.last_entry_hash() or ""
        chained_message = f"{message}|prev_hash={prev_hash}"
        return self.append(sender, recipient, chained_message)
