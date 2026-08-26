"""
Eltoo (LN-Symmetric) State Update Protocol Engine (BIP 118 / SIGHASH_ANYPREVOUT concept).
Replaces Poon-Dryja revocation penalty mechanisms with symmetric sequence-numbered update transactions.

Any higher state transaction (State N) can spend any lower state transaction output (State N-K),
eliminating revocation secrets and allowing penalty-free channel updates.
"""

from bitcoin.core import (
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    CTxInWitness,
    CTxWitness,
)
from bitcoin.core.script import CScript, CScriptWitness
from pydantic import BaseModel

from payment_communities.bitcoin_utils import (
    hex_to_bytes,
    pubkey_to_p2wpkh_address,
    script_to_p2wsh_address,
)
from payment_communities.config import BITCOIN_DUST_LIMIT_SAT
from payment_communities.exceptions import PaymentCommunityError

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
    Uses nLocktime = ELTOO_BASE_LOCKTIME + state_number to enforce strict state ordering on L1.
    """
    txid_bytes = hex_to_bytes(spending_txid)
    txin = CMutableTxIn(
        COutPoint(txid_bytes, spending_vout), nSequence=state.state_number
    )

    # Output pays to 2-of-2 multisig script for next update or settlement
    total_capacity = state.sender_balance_sat + state.receiver_balance_sat
    p2wsh_addr = script_to_p2wsh_address(CScript(multisig_redeem_script))
    txout = CMutableTxOut(total_capacity, p2wsh_addr.to_scriptPubKey())

    tx = CMutableTransaction([txin], [txout], nLockTime=state.locktime)

    if sig_sender and sig_receiver:
        witness_stack = [b"", sig_sender, sig_receiver, multisig_redeem_script]
        tx.wit = CTxWitness([CTxInWitness(CScriptWitness(witness_stack))])

    return tx


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
    txid_bytes = hex_to_bytes(update_txid)
    txin = CMutableTxIn(COutPoint(txid_bytes, update_vout))

    txouts = []
    if state.sender_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        sender_addr = pubkey_to_p2wpkh_address(sender_pubkey_bytes)
        txouts.append(
            CMutableTxOut(state.sender_balance_sat, sender_addr.to_scriptPubKey())
        )

    if state.receiver_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        receiver_addr = pubkey_to_p2wpkh_address(receiver_pubkey_bytes)
        txouts.append(
            CMutableTxOut(state.receiver_balance_sat, receiver_addr.to_scriptPubKey())
        )

    tx = CMutableTransaction([txin], txouts)

    if sig_sender and sig_receiver and multisig_redeem_script:
        witness_stack = [b"", sig_sender, sig_receiver, multisig_redeem_script]
        tx.wit = CTxWitness([CTxInWitness(CScriptWitness(witness_stack))])

    return tx


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
