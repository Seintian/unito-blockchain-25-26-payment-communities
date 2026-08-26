"""
Bitcoin CMutableTransaction Construction & Script Verification Engine.
Handles real Bitcoin transaction serialization, witness stack assembly, and script verification.
"""

from collections.abc import Sequence
from typing import cast

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
    build_htlc_fulfill_witness,
    build_htlc_refund_witness,
    build_multisig_witness,
    create_2of2_multisig_script,
)
from payment_communities.exceptions import ScriptVerificationError


def create_funding_transaction(
    funder_utxo_txid: str,
    funder_utxo_vout: int,
    funder_pubkey_bytes: bytes,
    counterparty_pubkey_bytes: bytes,
    capacity_sat: int,
) -> tuple[CMutableTransaction, CScript]:
    """
    Constructs a 2-of-2 Multisig P2WSH Funding Transaction.
    Input: Funder P2WPKH UTXO
    Output: 2-of-2 P2WSH Funding Output
    Returns:
        (funding_tx, multisig_redeem_script)
    """
    txid_bytes = hex_to_bytes(funder_utxo_txid)
    # COutPoint in bitcoinlib expects hash in byte order
    outpoint = COutPoint(txid_bytes, funder_utxo_vout)
    txin = CMutableTxIn(outpoint)

    redeem_script = create_2of2_multisig_script(
        funder_pubkey_bytes, counterparty_pubkey_bytes
    )
    p2wsh_address = script_to_p2wsh_address(redeem_script)
    txout = CMutableTxOut(capacity_sat, p2wsh_address.to_scriptPubKey())

    tx = CMutableTransaction([txin], [txout])
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
    Outputs:
        1. Sender balance output (P2WPKH or CSV locked)
        2. Receiver balance output (P2WPKH)
        3. Optional HTLC P2WSH contract outputs
    """
    funding_txid_bytes = hex_to_bytes(funding_txid)
    outpoint = COutPoint(funding_txid_bytes, funding_vout)
    txin = CMutableTxIn(outpoint, nSequence=sequence_number)

    txouts = []

    # Sender P2WPKH balance output if > dust limit (546 sat)
    if sender_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        sender_addr = pubkey_to_p2wpkh_address(sender_pubkey_bytes)
        txouts.append(CMutableTxOut(sender_balance_sat, sender_addr.to_scriptPubKey()))

    # Receiver P2WPKH balance output if > dust limit (546 sat)
    if receiver_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        receiver_addr = pubkey_to_p2wpkh_address(receiver_pubkey_bytes)
        txouts.append(
            CMutableTxOut(receiver_balance_sat, receiver_addr.to_scriptPubKey())
        )

    # HTLC contract outputs
    if htlc_outputs:
        for htlc_sat, htlc_script in htlc_outputs:
            p2wsh_addr = script_to_p2wsh_address(htlc_script)
            txouts.append(CMutableTxOut(htlc_sat, p2wsh_addr.to_scriptPubKey()))

    return CMutableTransaction([txin], txouts)


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
    funding_txid_bytes = hex_to_bytes(funding_txid)
    outpoint = COutPoint(funding_txid_bytes, funding_vout)
    txin = CMutableTxIn(outpoint)

    txouts = []
    if final_sender_sat >= BITCOIN_DUST_LIMIT_SAT:
        sender_addr = pubkey_to_p2wpkh_address(sender_pubkey_bytes)
        txouts.append(CMutableTxOut(final_sender_sat, sender_addr.to_scriptPubKey()))

    if final_receiver_sat >= BITCOIN_DUST_LIMIT_SAT:
        receiver_addr = pubkey_to_p2wpkh_address(receiver_pubkey_bytes)
        txouts.append(
            CMutableTxOut(final_receiver_sat, receiver_addr.to_scriptPubKey())
        )

    tx = CMutableTransaction([txin], txouts)

    if sig_sender and sig_receiver and redeem_script:
        witness_stack = build_multisig_witness(sig_sender, sig_receiver, redeem_script)
        tx.wit = CTxWitness([CTxInWitness(CScriptWitness(witness_stack))])

    return tx


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
    txid_bytes = hex_to_bytes(commitment_txid)
    txin = CMutableTxIn(COutPoint(txid_bytes, htlc_vout))
    claimer_addr = pubkey_to_p2wpkh_address(claimer_pubkey_bytes)
    txout = CMutableTxOut(amount_sat, claimer_addr.to_scriptPubKey())

    tx = CMutableTransaction([txin], [txout])

    if claimer_signature:
        witness_stack = build_htlc_fulfill_witness(
            claimer_signature, preimage_bytes, htlc_redeem_script
        )
        tx.wit = CTxWitness([CTxInWitness(CScriptWitness(witness_stack))])

    return tx


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
    txid_bytes = hex_to_bytes(commitment_txid)
    txin = CMutableTxIn(
        COutPoint(txid_bytes, htlc_vout), nSequence=SEQUENCE_CLTV_ENABLE_MASK
    )
    sender_addr = pubkey_to_p2wpkh_address(sender_pubkey_bytes)
    txout = CMutableTxOut(amount_sat, sender_addr.to_scriptPubKey())

    tx = CMutableTransaction([txin], [txout], nLockTime=locktime)

    if sender_signature:
        witness_stack = build_htlc_refund_witness(sender_signature, htlc_redeem_script)
        tx.wit = CTxWitness([CTxInWitness(CScriptWitness(witness_stack))])

    return tx


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
