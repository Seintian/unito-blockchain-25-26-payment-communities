"""
Poon-Dryja (LN-Penalty) Revocation & Breach Remedy Protocol Engine.
Provides per-commitment secret generation, revocable output script construction,
state revocation tracking, and justice sweep breach remedy transactions.
"""

import secrets
from typing import TYPE_CHECKING, Any, cast

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import (
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
    CScript,
    SignatureHash,
)
from pydantic import BaseModel, ConfigDict, Field
from rich.console import Console

from payment_communities.bitcoin.transaction import (
    TransactionBuilder,
    create_asymmetric_commitment_transaction,
)
from payment_communities.bitcoin.utils import sha256, sign_sighash
from payment_communities.config import (
    DEFAULT_SIMULATION_CAPACITY_SAT,
    DEFAULT_TO_SELF_DELAY_BLOCKS,
    SECRET_KEY_SIZE_BYTES,
)
from payment_communities.domain.core.policies import RevocationPolicy

if TYPE_CHECKING:
    from payment_communities.domain.node import Node
    from payment_communities.network.client import EsploraClient




def generate_revocation_secret() -> tuple[bytes, bytes]:
    """
    Generates a 32-byte per-commitment revocation secret and its corresponding public revocation hash.
    Returns:
        (revocation_secret_bytes, revocation_hash_bytes)
    """
    secret = secrets.token_bytes(SECRET_KEY_SIZE_BYTES)
    rev_hash = sha256(secret)
    return secret, rev_hash


def create_revocable_output_script(
    revocation_pubkey: bytes,
    local_pubkey: bytes,
    to_self_delay: int = DEFAULT_TO_SELF_DELAY_BLOCKS,
) -> CScript:
    """
    Constructs a Poon-Dryja Revocable Output Script for asymmetric commitment transactions.
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
    """Stores historical per-commitment secrets and revokes past channel states."""

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


def run_breach_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates Poon-Dryja State Revocation and Breach Remedy Justice Sweep Penalty with real keys and live network state."""
    from payment_communities.domain.channel import ChannelState

    console = Console()

    console.print(
        "\n[bold red]=== Poon-Dryja Breach Remedy Penalty Demonstration ===[/bold red]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )

    console.print(
        f"[cyan]1. Setting up Channel Alice -> Bob ({DEFAULT_SIMULATION_CAPACITY_SAT:,} sat capacity)...[/cyan]"
    )
    ch = alice_node.open_channel(bob_node, capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT)
    ch.funding_txid = alice_txid
    ch.funding_vout = alice_vout

    rev_secret_bytes, rev_hash = generate_revocation_secret()
    revocable_script = create_revocable_output_script(
        revocation_pubkey=rev_hash,
        local_pubkey=alice_node.pubkey_bytes,
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )

    revoked_commit_tx = create_asymmetric_commitment_transaction(
        funding_txid=alice_txid,
        funding_vout=alice_vout,
        local_pubkey_bytes=alice_node.pubkey_bytes,
        remote_pubkey_bytes=bob_node.pubkey_bytes,
        revocation_pubkey_bytes=rev_hash,
        local_balance_sat=80_000,
        remote_balance_sat=20_000,
    )
    revoked_txid = revoked_commit_tx.GetTxid().hex()

    console.print(
        "  • Alice & Bob execute Payment #1 (Alice: 80,000 sat, Bob: 20,000 sat). State #1 is REVOKED."
    )
    ch.revoke_prior_state(1, rev_secret_bytes.hex())

    half_capacity = DEFAULT_SIMULATION_CAPACITY_SAT // 2
    console.print(
        f"  • Current State #2 active (Alice: {half_capacity:,} sat, Bob: {half_capacity:,} sat)."
    )
    ch.balance_sender_sat = half_capacity
    ch.balance_receiver_sat = half_capacity

    console.print(
        "\n[bold yellow]⚠️  MALICIOUS ATTEMPT:[/bold yellow] Alice attempts to broadcast revoked State #1 on-chain to steal 80,000 sat!"
    )
    console.print(f"  • Revoked State #1 Commitment TXID: {revoked_txid[:24]}...")

    if ch.revocation_store.is_state_revoked(1):
        console.print(
            "  [bold red]🚨 BREACH DETECTED![/bold red] Bob identifies Alice's broadcast as a REVOKED state!"
        )

        revealed_secret = ch.revocation_store.get_revocation_secret(1)

        # Generate real cryptographic justice signature from Bob's secret key
        dummy_rev_tx = create_breach_remedy_transaction(
            revoked_txid=revoked_txid,
            revoked_vout=0,
            sweeper_pubkey_bytes=bob_node.pubkey_bytes,
            amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
            revocation_secret_signature=b"\x00" * 70,
            revocable_redeem_script=revocable_script,
        )
        sighash = SignatureHash(
            revocable_script,
            dummy_rev_tx,
            0,
            SIGHASH_ALL,
            amount=DEFAULT_SIMULATION_CAPACITY_SAT,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        real_justice_sig = sign_sighash(bob_node.secret, sighash)

        justice_tx = create_breach_remedy_transaction(
            revoked_txid=revoked_txid,
            revoked_vout=0,
            sweeper_pubkey_bytes=bob_node.pubkey_bytes,
            amount_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
            revocation_secret_signature=real_justice_sig,
            revocable_redeem_script=revocable_script,
        )

        secret_disp = (revealed_secret or "")[:16]
        console.print(
            f"  [bold green]⚡ BREACH REMEDY EXECUTED![/bold green] Bob uses revealed secret ({secret_disp}...) to sweep 100% of channel capacity!"
        )
        console.print(
            f"  [dim]Justice Sweep TXID:[/dim] {justice_tx.GetTxid().hex()[:24]}..."
        )

        ch.balance_sender_sat = 0
        ch.balance_receiver_sat = DEFAULT_SIMULATION_CAPACITY_SAT
        ch.state = ChannelState.SETTLED

        console.print(
            "\n[bold green]=== Alice Punished! Final Channel Balances: ===[/bold green]\n"
        )
        console.print(f"  • Alice: {ch.balance_sender_sat:,} sat (PUNISHED: 0 sat)")
        console.print(
            f"  • Bob:   {ch.balance_receiver_sat:,} sat (SWEEPS 100% OF CAPACITY)"
        )
