"""
Eltoo (LN-Symmetric) State Update Protocol engine.
Implements SIGHASH_ANYPREVOUT (BIP 118 / Taproot) floating sequence update transactions.
"""

from typing import Any, cast

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import OP_0, CScript
from pydantic import BaseModel

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import sha256
from payment_communities.config import (
    ELTOO_BASE_LOCKTIME,
    SEQUENCE_CLTV_ENABLE_MASK,
)

__all__ = [
    "ELTOO_BASE_LOCKTIME",
    "EltooState",
    "create_eltoo_settlement_transaction",
    "create_eltoo_update_transaction",
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
) -> CMutableTransaction:
    """
    Creates an Eltoo Update Transaction with floating input binding via SIGHASH_ANYPREVOUT.
    """
    p2wsh_spk = CScript(cast(Any, [OP_0, sha256(multisig_redeem_script)]))
    witness = ScriptFactory.witness_multisig_2of2(
        sig_sender, sig_receiver, CScript(multisig_redeem_script)
    )

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
    sig_sender: bytes,
    sig_receiver: bytes,
    multisig_redeem_script: bytes,
) -> CMutableTransaction:
    """
    Creates the final Eltoo Settlement Transaction returning funds to parties.
    """
    p2wpkh_sender = CScript(cast(Any, [OP_0, sha256(sender_pubkey_bytes)]))
    p2wpkh_receiver = CScript(cast(Any, [OP_0, sha256(receiver_pubkey_bytes)]))
    witness = ScriptFactory.witness_multisig_2of2(
        sig_sender, sig_receiver, CScript(multisig_redeem_script)
    )

    return (
        TransactionBuilder()
        .add_input(update_txid, update_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK)
        .add_output(state.sender_balance_sat, p2wpkh_sender)
        .add_output(state.receiver_balance_sat, p2wpkh_receiver)
        .add_witness_stack(witness)
        .build()
    )
