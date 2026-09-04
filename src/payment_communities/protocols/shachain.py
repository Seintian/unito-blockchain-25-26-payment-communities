"""
BOLT #3 48-Order Shachain Revocation Secret Generation & Storage Engine.

Implements:
- Derivation of up to 2^48 per-commitment secrets from a single 32-byte root seed in O(1) time.
- ShachainReceiver storing up to 2^48 revealed secrets in at most 48 32-byte storage slots (O(log N) space).
- Deterministic derivation of any past revealed secret from the compact tree.
"""

import hashlib
import secrets

from pydantic import BaseModel, Field


def derive_shachain_secret(seed: bytes, index: int) -> bytes:
    """
    Derives the 32-byte per-commitment secret for commitment index `index` from a 32-byte seed
    according to BOLT #3 specification:
    For each bit b from 47 down to 0:
        if index & (1 << b):
            flip bit b of secret, and hash with SHA-256.
    """
    if len(seed) != 32:
        raise ValueError(f"Shachain seed must be 32 bytes, got {len(seed)}")
    if index < 0 or index >= (1 << 48):
        raise ValueError(f"Shachain index out of range [0, 2^48 - 1]: {index}")

    p = bytearray(seed)
    for b in range(47, -1, -1):
        if (index >> b) & 1:
            byte_idx = b // 8
            bit_idx = b % 8
            p[byte_idx] ^= 1 << bit_idx
            p = bytearray(hashlib.sha256(p).digest())
    return bytes(p)


def can_derive(source_index: int, target_index: int) -> bool:
    """
    Returns True if target_index can be derived from source_index according to Shachain rules.
    A source secret can derive a target secret if source_index and target_index agree on all
    higher bits, and where source_index has a 0, target_index can have a 1 or 0 (source is an ancestor).
    """
    if source_index == target_index:
        return True
    # Count trailing zeros of source_index
    if source_index == 0:
        trailing_zeros = 48
    else:
        trailing_zeros = (source_index & -source_index).bit_length() - 1

    mask = ~((1 << trailing_zeros) - 1) & ((1 << 48) - 1)
    return (source_index & mask) == (target_index & mask)


def derive_from_ancestor(
    ancestor_secret: bytes, ancestor_index: int, target_index: int
) -> bytes:
    """
    Derives target_index secret from an ancestor secret at ancestor_index.
    """
    if ancestor_index == target_index:
        return ancestor_secret

    p = bytearray(ancestor_secret)
    # Walk from the trailing zeros of ancestor_index down to 0
    if ancestor_index == 0:
        start_bit = 47
    else:
        start_bit = (ancestor_index & -ancestor_index).bit_length() - 2

    for b in range(start_bit, -1, -1):
        if (target_index >> b) & 1:
            byte_idx = b // 8
            bit_idx = b % 8
            p[byte_idx] ^= 1 << bit_idx
            p = bytearray(hashlib.sha256(p).digest())
    return bytes(p)


class ShachainGenerator:
    """
    Generates per-commitment revocation secrets from a local private seed.
    Channels use index = (2^48 - 1 - commitment_number) as per BOLT #3.
    """

    def __init__(self, seed: bytes | None = None) -> None:
        self.seed = seed or secrets.token_bytes(32)

    def get_secret(self, index: int) -> bytes:
        """Derives the 32-byte secret for index."""
        return derive_shachain_secret(self.seed, index)

    def get_commitment_secret(self, commitment_number: int) -> bytes:
        """Derives the secret for a commitment number using BOLT #3 index reversal: index = 2^48 - 1 - commitment_number."""
        max_idx = (1 << 48) - 1
        return self.get_secret(max_idx - commitment_number)


class ShachainReceiver(BaseModel):
    """
    Stores up to 2^48 counterparty revealed revocation secrets in at most 48 elements.
    Provides O(log N) storage and O(1) - O(log N) derivation of past secrets.
    """

    elements: dict[int, str] = Field(default_factory=dict)  # slot (0..47) -> secret_hex
    last_index: int = -1

    def add_secret(self, secret: bytes, index: int) -> None:
        """
        Adds a revealed secret for index to the compact Shachain tree.
        Compresses ancestor slots as new secrets are revealed.
        """
        if len(secret) != 32:
            raise ValueError(f"Secret must be 32 bytes, got {len(secret)}")

        # Check if secret can be derived from existing slots to prevent tampering
        for slot, s_hex in list(self.elements.items()):
            s_bytes = bytes.fromhex(s_hex)
            if can_derive(slot, index):
                derived = derive_from_ancestor(s_bytes, slot, index)
                if derived != secret:
                    raise ValueError(f"Shachain secret mismatch at index {index}")
                return

        # Place secret into its slot
        self.elements[index] = secret.hex()
        self.last_index = index

        # Prune redundant derived nodes
        slots = sorted(self.elements.keys())
        for s1 in slots:
            if s1 in self.elements:
                for s2 in slots:
                    if s2 in self.elements and s1 != s2 and can_derive(s1, s2):
                        del self.elements[s2]

    def get_secret(self, index: int) -> bytes | None:
        """
        Retrieves the secret for index if it has been previously added or can be derived from an ancestor.
        """
        if index in self.elements:
            return bytes.fromhex(self.elements[index])

        for slot, s_hex in self.elements.items():
            if can_derive(slot, index):
                return derive_from_ancestor(bytes.fromhex(s_hex), slot, index)
        return None

    def get_commitment_secret(self, commitment_number: int) -> bytes | None:
        """Retrieves revealed secret for commitment_number using reversed indexing."""
        max_idx = (1 << 48) - 1
        return self.get_secret(max_idx - commitment_number)
