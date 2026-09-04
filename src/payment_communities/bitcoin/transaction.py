"""
Bitcoin CMutableTransaction Construction & Script Verification Engine.
Provides a fluent TransactionBuilder and high-level transaction construction functions.
"""

from collections.abc import Sequence
from typing import Self

from bitcoin.core import (
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    CTxInWitness,
    CTxWitness,
    lx,
)
from bitcoin.core.script import CScript, CScriptWitness
from bitcoin.wallet import CBitcoinSecret

from payment_communities.bitcoin.contracts import (
    ScriptFactory,
    build_htlc_fulfill_witness,
    build_htlc_refund_witness,
    build_multisig_witness,
)
from payment_communities.bitcoin.utils import (
    pubkey_to_p2wpkh_address,
    script_to_p2wsh_address,
)
from payment_communities.config import (
    BITCOIN_DUST_LIMIT_SAT,
    SEQUENCE_CLTV_ENABLE_MASK,
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
        outpoint = COutPoint(lx(txid_hex), vout)
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

    def add_p2tr_output(self, amount_sat: int, output_key_x_only: bytes) -> Self:
        if amount_sat >= BITCOIN_DUST_LIMIT_SAT:
            from payment_communities.bitcoin.contracts import ScriptFactory

            spk = ScriptFactory.create_p2tr(output_key_x_only)
            self._outputs.append(CMutableTxOut(amount_sat, spk))
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


def create_asymmetric_commitment_transaction(
    funding_txid: str,
    funding_vout: int,
    local_pubkey_bytes: bytes,
    remote_pubkey_bytes: bytes,
    revocation_pubkey_bytes: bytes,
    local_balance_sat: int,
    remote_balance_sat: int,
    to_self_delay: int = 144,
    htlc_outputs: Sequence[tuple[int, CScript]] | None = None,
    sequence_number: int = 0,
) -> CMutableTransaction:
    """
    Constructs a BOLT #3 Asymmetric Commitment Transaction.
    Local balance pays to P2WSH revocable script (to_local_delay).
    Remote balance pays directly to remote P2WPKH address (to_remote).
    """
    from payment_communities.protocols.revocation import create_revocable_output_script

    revocable_script = create_revocable_output_script(
        revocation_pubkey=revocation_pubkey_bytes,
        local_pubkey=local_pubkey_bytes,
        to_self_delay=to_self_delay,
    )

    builder = TransactionBuilder().add_input(
        funding_txid, funding_vout, sequence=sequence_number
    )

    if local_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        builder.add_p2wsh_output(local_balance_sat, revocable_script)

    if remote_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        builder.add_p2wpkh_output(remote_balance_sat, remote_pubkey_bytes)

    if htlc_outputs:
        for htlc_sat, htlc_script in htlc_outputs:
            builder.add_p2wsh_output(htlc_sat, htlc_script)

    return builder.build()


def sign_commitment_transaction(
    tx: CMutableTransaction,
    input_index: int,
    redeem_script: CScript,
    capacity_sat: int,
    sec1: CBitcoinSecret,
    sec2: CBitcoinSecret,
) -> CMutableTransaction:
    """
    Signs a 2-of-2 multisig commitment transaction input with two private keys using BIP 143 sighashes.
    """
    from bitcoin.core import CTxInWitness, CTxWitness
    from bitcoin.core.script import (
        SIGHASH_ALL,
        SIGVERSION_WITNESS_V0,
        CScriptWitness,
        SignatureHash,
    )

    from payment_communities.bitcoin.utils import sign_sighash

    sighash = SignatureHash(
        redeem_script,
        tx,
        input_index,
        SIGHASH_ALL,
        amount=capacity_sat,
        sigversion=SIGVERSION_WITNESS_V0,
    )

    sig1 = sign_sighash(sec1, sighash)
    sig2 = sign_sighash(sec2, sighash)

    keys = sorted([sec1.pub, sec2.pub])
    if keys[0] == sec1.pub:
        sorted_sigs = [sig1, sig2]
    else:
        sorted_sigs = [sig2, sig1]

    witness_stack = build_multisig_witness(
        sorted_sigs[0], sorted_sigs[1], redeem_script
    )
    wit_item = CTxInWitness(CScriptWitness(witness_stack))

    if not tx.wit or not tx.wit.vtxinwit:
        tx.wit = CTxWitness([wit_item])
    else:
        tx.wit.vtxinwit[input_index] = wit_item

    return tx


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
        if sender_pubkey_bytes < receiver_pubkey_bytes:
            sig1, sig2 = sig_sender, sig_receiver
        else:
            sig1, sig2 = sig_receiver, sig_sender
        witness_stack = build_multisig_witness(sig1, sig2, redeem_script)
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


def create_bolt3_second_stage_htlc_transaction(
    commitment_txid: str,
    htlc_vout: int,
    amount_sat: int,
    revocation_pubkey_bytes: bytes,
    local_delayed_pubkey_bytes: bytes,
    to_self_delay: int = 144,
    locktime: int = 0,
    witness_stack: list[bytes] | None = None,
) -> tuple[CMutableTransaction, CScript]:
    """
    Constructs a BOLT #3 Second-Stage HTLC Transaction (HTLC-Success or HTLC-Timeout).
    Crucial Security Feature: Spends a commitment HTLC output and creates an output
    encumbered by a revocable CSV delay script (create_second_stage_htlc_script).
    This ensures that if a revoked state is broadcast, the honest party can sweep
    both the direct commitment balance and any in-flight HTLCs!
    """
    from payment_communities.bitcoin.contracts import create_second_stage_htlc_script

    second_stage_script = create_second_stage_htlc_script(
        revocation_pubkey=revocation_pubkey_bytes,
        local_delayed_pubkey=local_delayed_pubkey_bytes,
        to_self_delay=to_self_delay,
    )

    builder = TransactionBuilder(locktime=locktime).add_input(
        commitment_txid, htlc_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK
    )
    builder.add_p2wsh_output(amount_sat, second_stage_script)

    if witness_stack:
        builder.add_witness_stack(witness_stack)

    return builder.build(), second_stage_script


def verify_transaction_witness(
    tx: CMutableTransaction,
    input_index: int,
    spent_script_pub_key: CScript,
    amount_sat: int,
) -> bool:
    """
    Evaluates and verifies BIP 143 SegWit V0 transaction witness stack against spent scriptPubKey
    using Bitcoin Core consensus rules.
    Delegates to polymorphic WitnessProgram and ScriptInterpreter architecture.

    Raises:
        ScriptVerificationError: If consensus script verification fails.
    """
    from payment_communities.bitcoin.interpreter import WitnessProgram

    if not tx.wit or input_index >= len(tx.wit.vtxinwit):
        raise ScriptVerificationError(
            f"Transaction missing witness stack for input #{input_index}"
        )

    witness_stack = list(tx.wit.vtxinwit[input_index].scriptWitness.stack)
    program = WitnessProgram.from_script_pub_key(spent_script_pub_key)
    return program.verify(
        tx=tx,
        input_index=input_index,
        witness_stack=witness_stack,
        amount_sat=amount_sat,
    )
