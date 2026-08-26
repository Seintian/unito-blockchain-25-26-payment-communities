"""
Eltoo (LN-Symmetric) State Update Protocol Engine (BIP 118 / SIGHASH_ANYPREVOUT concept).
Replaces Poon-Dryja revocation penalty mechanisms with symmetric sequence-numbered update transactions.
"""

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import CScript
from pydantic import BaseModel

from payment_communities.exceptions import PaymentCommunityError
from payment_communities.transaction import TransactionBuilder

ELTOO_BASE_LOCKTIME: int = 500_000_000
"""Base locktime threshold for Eltoo state sequence encoding."""


class EltooState(BaseModel):
    """Encapsulates a sequence-numbered Eltoo channel state."""

    state_number: int
    sender_balance_sat: int
    receiver_balance_sat: int

    @property
    def locktime(self) -> int:
        """Eltoo state locktime encoding: Base + state_number."""
        return ELTOO_BASE_LOCKTIME + self.state_number


def create_eltoo_update_transaction(
    spending_txid: str,
    spending_vout: int,
    state: EltooState,
    multisig_redeem_script: bytes,
    sig_sender: bytes = b"",
    sig_receiver: bytes = b"",
) -> CMutableTransaction:
    """
    Constructs an Eltoo Symmetric Update Transaction.
    """
    total_capacity = state.sender_balance_sat + state.receiver_balance_sat

    builder = (
        TransactionBuilder(locktime=state.locktime)
        .add_input(spending_txid, spending_vout, sequence=state.state_number)
        .add_p2wsh_output(total_capacity, CScript(multisig_redeem_script))
    )

    if sig_sender and sig_receiver:
        witness_stack = [b"", sig_sender, sig_receiver, multisig_redeem_script]
        builder.add_witness_stack(witness_stack)

    return builder.build()


def create_eltoo_settlement_transaction(
    update_txid: str,
    update_vout: int,
    sender_pubkey_bytes: bytes,
    receiver_pubkey_bytes: bytes,
    state: EltooState,
    sig_sender: bytes = b"",
    sig_receiver: bytes = b"",
    multisig_redeem_script: bytes = b"",
) -> CMutableTransaction:
    """
    Constructs the final Eltoo Settlement Transaction settling balances on-chain after state update timeout.
    """
    builder = (
        TransactionBuilder()
        .add_input(update_txid, update_vout)
        .add_p2wpkh_output(state.sender_balance_sat, sender_pubkey_bytes)
        .add_p2wpkh_output(state.receiver_balance_sat, receiver_pubkey_bytes)
    )

    if sig_sender and sig_receiver and multisig_redeem_script:
        witness_stack = [b"", sig_sender, sig_receiver, multisig_redeem_script]
        builder.add_witness_stack(witness_stack)

    return builder.build()


def validate_eltoo_override(
    current_state: EltooState, proposed_state: EltooState
) -> bool:
    """
    Validates whether proposed_state can legally override current_state under Eltoo rules.
    Rule: proposed_state.state_number > current_state.state_number
    """
    if proposed_state.state_number <= current_state.state_number:
        raise PaymentCommunityError(
            f"Eltoo Invalid State Override: Proposed state #{proposed_state.state_number} "
            f"cannot override current state #{current_state.state_number}!"
        )
    return True
