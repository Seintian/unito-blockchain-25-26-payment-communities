"""
BOLT #13 Autonomous Watchtower Daemon & Encrypted Hint Session Engine.
Provides encrypted justice payload registration and real-time transaction monitoring.
"""

import json
from typing import Any

from bitcoin.core import CMutableTransaction
from pydantic import BaseModel, ConfigDict, Field

from payment_communities.bitcoin.utils import hex_to_bytes, sha256
from payment_communities.config import (
    AES_GCM_NONCE_BYTES,
    AES_GCM_TAG_BYTES,
    WATCHTOWER_HINT_BYTES,
)


def derive_watchtower_hint(revoked_txid_hex: str) -> str:
    """
    Derives 16-byte (32 hex char) watchtower locator hint from revoked commitment TXID.
    Hint = SHA256(txid)[:16]
    """
    digest = sha256(hex_to_bytes(revoked_txid_hex))
    return digest[:WATCHTOWER_HINT_BYTES].hex()


def encrypt_justice_payload(
    revoked_txid_hex: str, justice_package: dict[str, Any]
) -> str:
    """
    Encrypts justice blob payload using SHA256(revoked_txid) key with AES-256-GCM.
    Format: <nonce_hex>:<ciphertext_and_tag_hex>
    """
    import secrets

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    payload_bytes = json.dumps(justice_package).encode("utf-8")
    key = sha256(hex_to_bytes(revoked_txid_hex))
    nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)

    return f"{nonce.hex()}:{ciphertext.hex()}"


def decrypt_justice_payload(
    revoked_txid_hex: str, encrypted_blob: str
) -> dict[str, Any]:
    """
    Decrypts AES-256-GCM encrypted justice blob back into structured package dict.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = sha256(hex_to_bytes(revoked_txid_hex))

    if ":" in encrypted_blob:
        nonce_hex, cipher_hex = encrypted_blob.split(":", 1)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(cipher_hex)
        aesgcm = AESGCM(key)
        plain_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    else:
        # Fallback for mock_cipher legacy format
        hex_str = encrypted_blob.replace("mock_cipher_", "")
        cipher_bytes = bytes.fromhex(hex_str)
        plain_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(cipher_bytes)])

    return json.loads(plain_bytes.decode("utf-8"))


class WatchtowerSession(BaseModel):
    session_id: str = "wt_session_01"
    hint_map: dict[str, str] = Field(default_factory=dict)  # hint -> encrypted_blob
    registered_txids: dict[str, str] = Field(
        default_factory=dict
    )  # hint -> revoked_txid

    def register_justice_package(
        self,
        revoked_txid_hex: str,
        sweeper_pubkey_hex: str,
        amount_sat: int,
        revocation_sig_hex: str,
        revocation_pubkey_hex: str,
        local_pubkey_hex: str,
        to_self_delay: int,
    ) -> str:
        """
        Encrypted registration protocol: client sends locator hint and encrypted justice blob.
        """
        hint = derive_watchtower_hint(revoked_txid_hex)
        package = {
            "revoked_txid": revoked_txid_hex,
            "sweeper_pubkey": sweeper_pubkey_hex,
            "amount_sat": amount_sat,
            "revocation_sig": revocation_sig_hex,
            "revocation_pubkey": revocation_pubkey_hex,
            "local_pubkey": local_pubkey_hex,
            "to_self_delay": to_self_delay,
            "nonce_len": AES_GCM_NONCE_BYTES,
            "tag_len": AES_GCM_TAG_BYTES,
        }
        encrypted_blob = encrypt_justice_payload(revoked_txid_hex, package)
        self.hint_map[hint] = encrypted_blob
        self.registered_txids[hint] = revoked_txid_hex
        return hint


class WatchtowerDaemon(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session: WatchtowerSession = Field(default_factory=WatchtowerSession)
    swept_transactions: list[CMutableTransaction] = Field(default_factory=list)

    def scan_transaction(self, broadcast_txid_hex: str) -> CMutableTransaction | None:
        """
        Monitors blockchain transactions against locator hints.
        If a match is found, decrypts blob and builds justice penalty sweep transaction.
        """
        hint = derive_watchtower_hint(broadcast_txid_hex)
        if hint not in self.session.hint_map:
            return None

        encrypted_blob = self.session.hint_map[hint]
        package = decrypt_justice_payload(broadcast_txid_hex, encrypted_blob)

        # Build Justice Penalty Sweep Transaction
        from payment_communities.protocols.revocation import (
            create_breach_remedy_transaction,
            create_revocable_output_script,
        )

        redeem_script = create_revocable_output_script(
            revocation_pubkey=hex_to_bytes(package["revocation_pubkey"]),
            local_pubkey=hex_to_bytes(package["local_pubkey"]),
            to_self_delay=package["to_self_delay"],
        )

        justice_tx = create_breach_remedy_transaction(
            revoked_txid=broadcast_txid_hex,
            revoked_vout=0,
            sweeper_pubkey_bytes=hex_to_bytes(package["sweeper_pubkey"]),
            amount_sat=package["amount_sat"],
            revocation_secret_signature=hex_to_bytes(package["revocation_sig"]),
            revocable_redeem_script=redeem_script,
        )
        self.swept_transactions.append(justice_tx)
        return justice_tx
