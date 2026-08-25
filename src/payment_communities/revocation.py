"""
Poon-Dryja (LN-Penalty) Revocation & Breach Remedy Protocol Engine.
Provides per-commitment secret generation, revocable output script construction,
state revocation tracking, and justice sweep breach remedy transactions.
"""

import secrets

from bitcoin.core import (
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    CTxInWitness,
    CTxWitness,
)
from bitcoin.core.script import (
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    CScript,
    CScriptWitness,
)
from pydantic import BaseModel

from payment_communities.bitcoin_utils import (
    hex_to_bytes,
    pubkey_to_p2wpkh_address,
    sha256,
)


def generate_revocation_secret() -> tuple[bytes, bytes]:
    """
    Generates a 32-byte per-commitment revocation secret and its corresponding public revocation hash.
    Returns:
        (revocation_secret_bytes, revocation_hash_bytes)
    """
    secret = secrets.token_bytes(32)
    rev_hash = sha256(secret)
    return secret, rev_hash


def create_revocable_output_script(
    revocation_pubkey: bytes, local_pubkey: bytes, to_self_delay: int = 144
) -> CScript:
    """
    Constructs a Poon-Dryja Revocable Output Script for asymmetric commitment transactions.
    Script Logic:
    OP_IF
        <revocation_pubkey> OP_CHECKSIG
    OP_ELSE
        <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP <local_pubkey> OP_CHECKSIG
    OP_ENDIF
    """
    return CScript(
        [
            OP_IF,
            revocation_pubkey,
            OP_CHECKSIG,
            OP_ELSE,
            to_self_delay,
            OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            local_pubkey,
            OP_CHECKSIG,
            OP_ENDIF,
        ]
    )


def create_breach_remedy_transaction(
    revoked_txid: str,
    revoked_vout: int,
    sweeper_pubkey_bytes: bytes,
    amount_sat: int,
    revocation_secret_signature: bytes,
    revocable_redeem_script: CScript,
) -> CMutableTransaction:
    """
    Constructs a Breach Remedy (Justice Sweep) Transaction punishing a node broadcasting a revoked state.
    Sweeps 100% of the channel output to the non-breaching peer.
    Witness Stack: [<revocation_sig>, b"\x01", <revocable_redeem_script>]
    """
    txid_bytes = hex_to_bytes(revoked_txid)
    txin = CMutableTxIn(COutPoint(txid_bytes, revoked_vout))
    sweeper_addr = pubkey_to_p2wpkh_address(sweeper_pubkey_bytes)
    txout = CMutableTxOut(amount_sat, sweeper_addr.to_scriptPubKey())

    tx = CMutableTransaction([txin], [txout])
    witness_stack = [
        revocation_secret_signature,
        b"\x01",
        bytes(revocable_redeem_script),
    ]
    tx.wit = CTxWitness([CTxInWitness(CScriptWitness(witness_stack))])
    return tx


class RevocationStore(BaseModel):
    """Stores historical per-commitment secrets and revokes past channel states."""

    local_secrets: dict[int, str] = {}  # commitment_number -> hex(secret)
    remote_revealed_secrets: dict[int, str] = {}  # commitment_number -> hex(secret)

    def register_remote_secret(self, commitment_number: int, secret_hex: str) -> None:
        """Stores a revealed remote secret, marking that commitment state as revoked."""
        self.remote_revealed_secrets[commitment_number] = secret_hex

    def is_state_revoked(self, commitment_number: int) -> bool:
        """Checks whether a commitment number has been revoked by receiving its secret."""
        return commitment_number in self.remote_revealed_secrets

    def get_revocation_secret(self, commitment_number: int) -> str | None:
        """Returns the revealed revocation secret for a revoked state, if available."""
        return self.remote_revealed_secrets.get(commitment_number)
