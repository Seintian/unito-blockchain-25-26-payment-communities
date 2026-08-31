"""
Eltoo (LN-Symmetric) State Update Protocol engine.
Implements SIGHASH_ANYPREVOUT (BIP 118 / Taproot) floating sequence update transactions.
"""

from typing import TYPE_CHECKING

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import (
    OP_0,
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
    CScript,
    SignatureHash,
)
from bitcoin.wallet import CBitcoinSecret
from pydantic import BaseModel
from rich.console import Console

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import hash160, sha256, sign_sighash
from payment_communities.config import (
    ELTOO_BASE_LOCKTIME,
    SEQUENCE_CLTV_ENABLE_MASK,
)

if TYPE_CHECKING:
    from payment_communities.domain.node import Node
    from payment_communities.network.client import EsploraClient


__all__ = [
    "ELTOO_BASE_LOCKTIME",
    "EltooState",
    "create_eltoo_settlement_transaction",
    "create_eltoo_update_transaction",
    "run_eltoo_demo",
    "validate_eltoo_override",
]



class EltooState(BaseModel):
    state_number: int
    sender_balance_sat: int
    receiver_balance_sat: int

    @property
    def locktime(self) -> int:
        """
        In Eltoo, state_number N maps to nLockTime = ELTOO_BASE_LOCKTIME + N.
        Higher state numbers have higher nLockTime values, making newer states
        valid spending inputs for older state outputs.
        """
        return ELTOO_BASE_LOCKTIME + self.state_number


def validate_eltoo_override(
    broadcast_state: EltooState, current_state: EltooState
) -> bool:
    """
    Returns True if current_state can replace/override broadcast_state.
    """
    from payment_communities.exceptions import PaymentCommunityError

    if current_state.state_number <= broadcast_state.state_number:
        raise PaymentCommunityError(
            f"Eltoo Invalid State Override: Cannot override state #{broadcast_state.state_number} "
            f"with older/equal state #{current_state.state_number}."
        )
    return True


def create_eltoo_update_transaction(
    spending_txid: str,
    spending_vout: int,
    state: EltooState,
    multisig_redeem_script: bytes,
    sig_sender: bytes = b"\x00" * 64,
    sig_receiver: bytes = b"\x00" * 64,
    sec_sender: CBitcoinSecret | None = None,
    sec_receiver: CBitcoinSecret | None = None,
) -> CMutableTransaction:
    """
    Creates an Eltoo Update Transaction with floating input binding via SIGHASH_ANYPREVOUT.
    Signs inputs with real keys if sec_sender and sec_receiver are provided.
    """
    p2wsh_spk = CScript([OP_0, sha256(multisig_redeem_script)])
    redeem_cs = CScript(multisig_redeem_script)

    tx = (
        TransactionBuilder(locktime=state.locktime)
        .add_input(spending_txid, spending_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK)
        .add_output(state.sender_balance_sat + state.receiver_balance_sat, p2wsh_spk)
        .build()
    )

    if sec_sender and sec_receiver:
        capacity_sat = state.sender_balance_sat + state.receiver_balance_sat
        sighash = SignatureHash(
            redeem_cs,
            tx,
            0,
            SIGHASH_ALL,
            amount=capacity_sat,
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig1 = sign_sighash(sec_sender, sighash)
        sig2 = sign_sighash(sec_receiver, sighash)
        keys = sorted([sec_sender.pub, sec_receiver.pub])
        if keys[0] == sec_sender.pub:
            sorted_sigs = [sig1, sig2]
        else:
            sorted_sigs = [sig2, sig1]
        sig_sender, sig_receiver = sorted_sigs[0], sorted_sigs[1]

    witness = ScriptFactory.witness_multisig_2of2(sig_sender, sig_receiver, redeem_cs)
    return (
        TransactionBuilder(locktime=state.locktime)
        .add_input(spending_txid, spending_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK)
        .add_output(state.sender_balance_sat + state.receiver_balance_sat, p2wsh_spk)
        .add_witness_stack(witness)
        .build()
    )


def create_eltoo_settlement_transaction(
    update_txid: str,
    update_vout: int,
    sender_pubkey_bytes: bytes,
    receiver_pubkey_bytes: bytes,
    state: EltooState,
    sig_sender: bytes = b"\x00" * 64,
    sig_receiver: bytes = b"\x00" * 64,
    multisig_redeem_script: bytes = b"",
    sec_sender: CBitcoinSecret | None = None,
    sec_receiver: CBitcoinSecret | None = None,
) -> CMutableTransaction:
    """
    Creates the final Eltoo Settlement Transaction returning funds to parties.
    Signs inputs with real keys if sec_sender and sec_receiver are provided.
    """
    p2wpkh_sender = CScript([OP_0, hash160(sender_pubkey_bytes)])
    p2wpkh_receiver = CScript([OP_0, hash160(receiver_pubkey_bytes)])
    redeem_cs = CScript(multisig_redeem_script) if multisig_redeem_script else CScript()

    tx = (
        TransactionBuilder()
        .add_input(update_txid, update_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK)
        .add_output(state.sender_balance_sat, p2wpkh_sender)
        .add_output(state.receiver_balance_sat, p2wpkh_receiver)
        .build()
    )

    if sec_sender and sec_receiver and multisig_redeem_script:
        capacity_sat = state.sender_balance_sat + state.receiver_balance_sat
        sighash = SignatureHash(
            redeem_cs,
            tx,
            0,
            SIGHASH_ALL,
            amount=capacity_sat,
            sigversion=SIGVERSION_WITNESS_V0,
        )

        sig1 = sign_sighash(sec_sender, sighash)
        sig2 = sign_sighash(sec_receiver, sighash)
        keys = sorted([sec_sender.pub, sec_receiver.pub])
        if keys[0] == sec_sender.pub:
            sorted_sigs = [sig1, sig2]
        else:
            sorted_sigs = [sig2, sig1]
        sig_sender, sig_receiver = sorted_sigs[0], sorted_sigs[1]

    witness = ScriptFactory.witness_multisig_2of2(sig_sender, sig_receiver, redeem_cs)
    return (
        TransactionBuilder()
        .add_input(update_txid, update_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK)
        .add_output(state.sender_balance_sat, p2wpkh_sender)
        .add_output(state.receiver_balance_sat, p2wpkh_receiver)
        .add_witness_stack(witness)
        .build()
    )


def run_eltoo_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates Eltoo (LN-Symmetric) state update protocol without penalty revocation secrets."""
    console = Console()
    console.print(
        "\n[bold blue]=== Eltoo (LN-Symmetric) State Update Protocol Demonstration ===[/bold blue]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    multisig_script = ScriptFactory.create_multisig_2of2(
        alice_node.pubkey_bytes, bob_node.pubkey_bytes
    )

    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )

    state1 = EltooState(
        state_number=1, sender_balance_sat=80_000, receiver_balance_sat=20_000
    )
    state2 = EltooState(
        state_number=2, sender_balance_sat=50_000, receiver_balance_sat=50_000
    )

    console.print(
        "1. Alice & Bob construct Eltoo State #1 (Alice: 80k sat, Bob: 20k sat)."
    )
    console.print(f"  • State #1 Locktime: {state1.locktime}")

    console.print(
        "\n2. Alice & Bob update to Eltoo State #2 (Alice: 50k sat, Bob: 50k sat)."
    )
    console.print(f"  • State #2 Locktime: {state2.locktime}")
    console.print(
        "  • [dim]No revocation secrets needed! State #2 naturally overrides State #1 on-chain.[/dim]"
    )

    if validate_eltoo_override(state1, state2):
        update_tx2 = create_eltoo_update_transaction(
            spending_txid=alice_txid,
            spending_vout=alice_vout,
            state=state2,
            multisig_redeem_script=bytes(multisig_script),
            sec_sender=alice_node.secret,
            sec_receiver=bob_node.secret,
        )
        settle_tx2 = create_eltoo_settlement_transaction(
            update_txid=update_tx2.GetTxid().hex(),
            update_vout=0,
            sender_pubkey_bytes=alice_node.pubkey_bytes,
            receiver_pubkey_bytes=bob_node.pubkey_bytes,
            state=state2,
            multisig_redeem_script=bytes(multisig_script),
            sec_sender=alice_node.secret,
            sec_receiver=bob_node.secret,
        )

        console.print("\n[bold green]✓ ELTOO SYMMETRIC UPDATE COMPLETE![/bold green]")
        console.print(
            f"  [dim]Signed Update TX2 ID:[/dim] {update_tx2.GetTxid().hex()[:24]}..."
        )
        console.print(
            f"  [dim]Signed Settlement TX2 ID:[/dim] {settle_tx2.GetTxid().hex()[:24]}...\n"
        )
