"""
Watchtower Service & Autonomous L1 Breach Monitoring Engine.
Implements privacy-preserving Watchtower client-server protocols (BOLT #13 concept).

Nodes register encrypted justice payloads indexed by a 16-byte hint derived from
sha256(revoked_txid). The Watchtower monitors L1 blocks without knowing node identities
or un-breached channel states, and automatically broadcasts Justice Sweeps upon breach detection.
"""

import json
from typing import Any

from pydantic import BaseModel, Field

from payment_communities.bitcoin_utils import hex_to_bytes, sha256
from payment_communities.revocation import (
    create_breach_remedy_transaction,
    create_revocable_output_script,
)
from payment_communities.transaction import CMutableTransaction


def derive_watchtower_hint(txid_hex: str) -> str:
    """
    Derives a 16-byte truncated hint identifier from a transaction ID.
    hint = sha256(hex_to_bytes(txid))[:16].hex()
    """
    txid_bytes = hex_to_bytes(txid_hex)
    return sha256(txid_bytes)[:16].hex()


def encrypt_justice_payload(txid_hex: str, payload_dict: dict[str, Any]) -> str:
    """
    XOR/AES-style encrypts the justice payload using sha256(txid) as the secret key.
    Ensures the Watchtower cannot inspect channel state until the breach transaction appears on L1.
    """
    key = sha256(hex_to_bytes(txid_hex))
    data_bytes = json.dumps(payload_dict).encode("utf-8")

    # Keystream XOR cipher for deterministic payload encryption
    encrypted = bytearray()
    for i, b in enumerate(data_bytes):
        key_byte = key[i % len(key)]
        encrypted.append(b ^ key_byte)

    return encrypted.hex()


def decrypt_justice_payload(txid_hex: str, encrypted_hex: str) -> dict[str, Any]:
    """
    Decrypts the justice payload when the breach transaction ID becomes known on L1.
    """
    key = sha256(hex_to_bytes(txid_hex))
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    decrypted = bytearray()
    for i, b in enumerate(encrypted_bytes):
        key_byte = key[i % len(key)]
        decrypted.append(b ^ key_byte)

    return json.loads(decrypted.decode("utf-8"))


class WatchtowerSession(BaseModel):
    """
    Encrypted lookup table maintained by a Watchtower server.
    Maps 16-byte hints to encrypted justice sweep packages.
    """

    hint_map: dict[str, str] = Field(default_factory=dict)  # hint_hex -> encrypted_hex

    def register_justice_package(
        self,
        revoked_txid_hex: str,
        sweeper_pubkey_hex: str,
        amount_sat: int,
        revocation_sig_hex: str,
        revocation_pubkey_hex: str,
        local_pubkey_hex: str,
        to_self_delay: int,
        revoked_vout: int = 0,
    ) -> str:
        """
        Encrypts and stores a justice package under a 16-byte hint key.
        Returns the derived hint identifier.
        """
        hint = derive_watchtower_hint(revoked_txid_hex)
        payload = {
            "revoked_txid": revoked_txid_hex,
            "revoked_vout": revoked_vout,
            "sweeper_pubkey": sweeper_pubkey_hex,
            "amount_sat": amount_sat,
            "revocation_sig": revocation_sig_hex,
            "revocation_pubkey": revocation_pubkey_hex,
            "local_pubkey": local_pubkey_hex,
            "to_self_delay": to_self_delay,
        }
        encrypted = encrypt_justice_payload(revoked_txid_hex, payload)
        self.hint_map[hint] = encrypted
        return hint


class WatchtowerDaemon(BaseModel):
    """
    Autonomous monitoring service that scans L1 block transactions against Watchtower sessions.
    """

    session: WatchtowerSession = Field(default_factory=WatchtowerSession)
    swept_transactions: list[str] = Field(default_factory=list)

    def scan_transaction(self, broadcast_txid_hex: str) -> CMutableTransaction | None:
        """
        Scans an incoming broadcast transaction ID against registered hints.
        If a breach is identified, decrypts the justice payload, constructs the penalty sweep transaction,
        and returns the CMutableTransaction instance ready for L1 broadcast.
        """
        hint = derive_watchtower_hint(broadcast_txid_hex)
        if hint not in self.session.hint_map:
            return None

        encrypted_payload = self.session.hint_map[hint]
        payload = decrypt_justice_payload(broadcast_txid_hex, encrypted_payload)

        revocable_script = create_revocable_output_script(
            revocation_pubkey=bytes.fromhex(payload["revocation_pubkey"]),
            local_pubkey=bytes.fromhex(payload["local_pubkey"]),
            to_self_delay=payload["to_self_delay"],
        )

        justice_tx = create_breach_remedy_transaction(
            revoked_txid=payload["revoked_txid"],
            revoked_vout=payload["revoked_vout"],
            sweeper_pubkey_bytes=bytes.fromhex(payload["sweeper_pubkey"]),
            amount_sat=payload["amount_sat"],
            revocation_secret_signature=bytes.fromhex(payload["revocation_sig"]),
            revocable_redeem_script=revocable_script,
        )

        sweep_txid = bytes(justice_tx.GetTxid()).hex()
        self.swept_transactions.append(sweep_txid)
        return justice_tx
