"""
Bitcoin CMutableTransaction Construction & Script Verification Engine.
Provides a fluent TransactionBuilder and high-level transaction construction functions.
"""

from collections.abc import Sequence
from typing import Self, cast

from bitcoin.core import (
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    CTxInWitness,
    CTxWitness,
)
from bitcoin.core.script import CScript, CScriptWitness
from bitcoin.core.scripteval import (
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CLEANSTACK,
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_P2SH,
    EvalScriptError,
    VerifyScript,
)

from payment_communities.bitcoin_utils import (
    hex_to_bytes,
    pubkey_to_p2wpkh_address,
    script_to_p2wsh_address,
)
from payment_communities.config import (
    BITCOIN_DUST_LIMIT_SAT,
    SEQUENCE_CLTV_ENABLE_MASK,
)
from payment_communities.contracts import (
    ScriptFactory,
    build_htlc_fulfill_witness,
    build_htlc_refund_witness,
    build_multisig_witness,
)
from payment_communities.exceptions import ScriptVerificationError


class TransactionBuilder:
    """
    Fluent Builder pattern for assembling Bitcoin transactions (CMutableTransaction).
    """

    def __init__(self, locktime: int = 0):
        self._inputs: list[CMutableTxIn] = []
        self._outputs: list[CMutableTxOut] = []
        self._witnesses: list[list[bytes]] = []
        self._locktime: int = locktime

    def add_input(self, txid_hex: str, vout: int, sequence: int = 0xFFFFFFFF) -> Self:
        txid_bytes = hex_to_bytes(txid_hex)
        outpoint = COutPoint(txid_bytes, vout)
        self._inputs.append(CMutableTxIn(outpoint, nSequence=sequence))
        return self

    def add_output(self, amount_sat: int, script_pubkey: CScript) -> Self:
        self._outputs.append(CMutableTxOut(amount_sat, script_pubkey))
        return self

    def add_p2wpkh_output(self, amount_sat: int, pubkey_bytes: bytes) -> Self:
        if amount_sat >= BITCOIN_DUST_LIMIT_SAT:
            addr = pubkey_to_p2wpkh_address(pubkey_bytes)
            self._outputs.append(CMutableTxOut(amount_sat, addr.to_scriptPubKey()))
        return self

    def add_p2wsh_output(self, amount_sat: int, redeem_script: CScript) -> Self:
        if amount_sat >= BITCOIN_DUST_LIMIT_SAT:
            addr = script_to_p2wsh_address(redeem_script)
            self._outputs.append(CMutableTxOut(amount_sat, addr.to_scriptPubKey()))
        return self

    def add_witness_stack(self, stack: list[bytes]) -> Self:
        self._witnesses.append(stack)
        return self

    def set_locktime(self, locktime: int) -> Self:
        self._locktime = locktime
        return self

    def build(self) -> CMutableTransaction:
        tx = CMutableTransaction(self._inputs, self._outputs, nLockTime=self._locktime)
        if self._witnesses:
            witnesses = [
                CTxInWitness(CScriptWitness(stack)) for stack in self._witnesses
            ]
            tx.wit = CTxWitness(witnesses)
        return tx


def create_funding_transaction(
    funder_utxo_txid: str,
    funder_utxo_vout: int,
    funder_pubkey_bytes: bytes,
    counterparty_pubkey_bytes: bytes,
    capacity_sat: int,
) -> tuple[CMutableTransaction, CScript]:
    """
    Constructs a 2-of-2 Multisig P2WSH Funding Transaction.
    """
    redeem_script = ScriptFactory.create_multisig_2of2(
        funder_pubkey_bytes, counterparty_pubkey_bytes
    )
    tx = (
        TransactionBuilder()
        .add_input(funder_utxo_txid, funder_utxo_vout)
        .add_p2wsh_output(capacity_sat, redeem_script)
        .build()
    )
    return tx, redeem_script


def create_commitment_transaction(
    funding_txid: str,
    funding_vout: int,
    sender_pubkey_bytes: bytes,
    receiver_pubkey_bytes: bytes,
    sender_balance_sat: int,
    receiver_balance_sat: int,
    htlc_outputs: Sequence[tuple[int, CScript]] | None = None,
    sequence_number: int = 0,
) -> CMutableTransaction:
    """
    Constructs an off-chain Commitment Transaction spending the 2-of-2 Multisig Funding UTXO.
    """
    builder = TransactionBuilder().add_input(
        funding_txid, funding_vout, sequence=sequence_number
    )

    builder.add_p2wpkh_output(sender_balance_sat, sender_pubkey_bytes)
    builder.add_p2wpkh_output(receiver_balance_sat, receiver_pubkey_bytes)

    if htlc_outputs:
        for htlc_sat, htlc_script in htlc_outputs:
            builder.add_p2wsh_output(htlc_sat, htlc_script)

    return builder.build()


def create_cooperative_close_transaction(
    funding_txid: str,
    funding_vout: int,
    sender_pubkey_bytes: bytes,
    receiver_pubkey_bytes: bytes,
    final_sender_sat: int,
    final_receiver_sat: int,
    sig_sender: bytes = b"",
    sig_receiver: bytes = b"",
    redeem_script: CScript | None = None,
) -> CMutableTransaction:
    """
    Constructs and signs a Cooperative Close Settlement Transaction returning funds on-chain.
    """
    builder = (
        TransactionBuilder()
        .add_input(funding_txid, funding_vout)
        .add_p2wpkh_output(final_sender_sat, sender_pubkey_bytes)
        .add_p2wpkh_output(final_receiver_sat, receiver_pubkey_bytes)
    )

    if sig_sender and sig_receiver and redeem_script:
        witness_stack = build_multisig_witness(sig_sender, sig_receiver, redeem_script)
        builder.add_witness_stack(witness_stack)

    return builder.build()


def create_htlc_claim_transaction(
    commitment_txid: str,
    htlc_vout: int,
    claimer_pubkey_bytes: bytes,
    amount_sat: int,
    preimage_bytes: bytes,
    htlc_redeem_script: CScript,
    claimer_signature: bytes = b"",
) -> CMutableTransaction:
    """
    Constructs an HTLC Success (Claim) Transaction redeeming an HTLC output with secret preimage.
    """
    builder = (
        TransactionBuilder()
        .add_input(commitment_txid, htlc_vout)
        .add_p2wpkh_output(amount_sat, claimer_pubkey_bytes)
    )

    if claimer_signature:
        witness_stack = build_htlc_fulfill_witness(
            claimer_signature, preimage_bytes, htlc_redeem_script
        )
        builder.add_witness_stack(witness_stack)

    return builder.build()


def create_htlc_refund_transaction(
    commitment_txid: str,
    htlc_vout: int,
    sender_pubkey_bytes: bytes,
    amount_sat: int,
    locktime: int,
    htlc_redeem_script: CScript,
    sender_signature: bytes = b"",
) -> CMutableTransaction:
    """
    Constructs an HTLC Timeout (Refund) Transaction reclaiming an HTLC output after locktime.
    """
    builder = (
        TransactionBuilder(locktime=locktime)
        .add_input(commitment_txid, htlc_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK)
        .add_p2wpkh_output(amount_sat, sender_pubkey_bytes)
    )

    if sender_signature:
        witness_stack = build_htlc_refund_witness(sender_signature, htlc_redeem_script)
        builder.add_witness_stack(witness_stack)

    return builder.build()


def verify_transaction_witness(
    tx: CMutableTransaction,
    input_index: int,
    spent_script_pub_key: CScript,
    amount_sat: int,
) -> bool:
    """
    Evaluates and verifies transaction witness stack against spent scriptPubKey using Bitcoin Core rules.
    Raises:
        ScriptVerificationError: If consensus script verification fails.
    """
    try:
        verify_flags = (
            cast(int, SCRIPT_VERIFY_P2SH)
            | cast(int, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
            | cast(int, SCRIPT_VERIFY_DERSIG)
            | cast(int, SCRIPT_VERIFY_CLEANSTACK)
        )
        VerifyScript(
            tx.vin[input_index].scriptSig,
            spent_script_pub_key,
            tx,
            input_index,
            verify_flags,
        )
        return True
    except EvalScriptError as e:
        raise ScriptVerificationError(f"Bitcoin Script verification failed: {e}") from e
