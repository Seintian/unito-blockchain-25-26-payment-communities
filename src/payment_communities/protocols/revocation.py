"""
Poon-Dryja (LN-Penalty) Revocation & Breach Remedy Protocol Engine.
Provides per-commitment secret generation, revocable output script construction,
state revocation tracking, and justice sweep breach remedy transactions.
"""

import secrets
from typing import Any, cast

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import (
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    CScript,
)
from pydantic import BaseModel, ConfigDict, Field

from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import (
    ec_point_mul,
)
from payment_communities.config import (
    DEFAULT_TO_SELF_DELAY_BLOCKS,
    SECP256K1_ORDER,
    SECRET_KEY_SIZE_BYTES,
)
from payment_communities.domain.core.policies import RevocationPolicy


def generate_revocation_secret() -> tuple[bytes, bytes]:
    """
    Generates a 32-byte per-commitment revocation secret scalar and its corresponding public commitment point:
    PerCommitPoint = secret * G (secp256k1).
    Returns:
        (per_commitment_secret_bytes, per_commitment_point_bytes)
    """
    secret = secrets.token_bytes(SECRET_KEY_SIZE_BYTES)
    scalar = int.from_bytes(secret, "big") % SECP256K1_ORDER
    if scalar == 0:
        scalar = 1
        secret = scalar.to_bytes(32, "big")
    per_commit_point = ec_point_mul(scalar)
    return secret, per_commit_point


def create_revocable_output_script(
    revocation_pubkey: bytes,
    local_pubkey: bytes,
    to_self_delay: int = DEFAULT_TO_SELF_DELAY_BLOCKS,
) -> CScript:
    """
    Constructs a Poon-Dryja Revocable Output Script for asymmetric commitment transactions (BOLT #3).
    Script:
        OP_IF
            <revocation_pubkey> OP_CHECKSIG
        OP_ELSE
            <to_self_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
            <local_pubkey> OP_CHECKSIG
        OP_ENDIF
    """
    return CScript(
        cast(
            Any,
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
            ],
        )
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
    """
    witness_stack = [
        revocation_secret_signature,
        b"\x01",
        bytes(revocable_redeem_script),
    ]

    return (
        TransactionBuilder()
        .add_input(revoked_txid, revoked_vout)
        .add_p2wpkh_output(amount_sat, sweeper_pubkey_bytes)
        .add_witness_stack(witness_stack)
        .build()
    )


class RevocationStore(BaseModel):
    """Stores historical per-commitment secrets and revokes past channel states with Shachain support."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    local_secrets: dict[int, str] = Field(default_factory=dict)
    remote_revealed_secrets: dict[int, str] = Field(default_factory=dict)
    policy: RevocationPolicy = Field(default_factory=RevocationPolicy, exclude=True)

    def register_remote_secret(self, commitment_number: int, secret_hex: str) -> None:
        """Stores a revealed remote secret, marking that commitment state as revoked."""
        self.remote_revealed_secrets[commitment_number] = secret_hex

    def is_state_revoked(self, commitment_number: int) -> bool:
        """Checks whether a commitment number has been revoked by receiving its secret."""
        return self.policy.is_state_revoked(
            commitment_number, set(self.remote_revealed_secrets.keys())
        )

    def get_revocation_secret(self, commitment_number: int) -> str | None:
        """Returns the revealed revocation secret for a revoked state, if available."""
        return self.remote_revealed_secrets.get(commitment_number)
