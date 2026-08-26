"""
Anchor Outputs & Dynamic CPFP Fee Bumping Engine (BOLT #3).
Allows emergency transaction fee bumping via Child-Pays-For-Parent (CPFP)
using dedicated 330-sat anchor outputs attached to commitment transactions.
"""

from typing import Any, cast

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import OP_0, OP_CHECKSIG, CScript

from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import sha256
from payment_communities.config import (
    BITCOIN_ANCHOR_OUTPUT_SAT,
    BITCOIN_DUST_LIMIT_SAT,
    SEQUENCE_CLTV_ENABLE_MASK,
)

ANCHOR_OUTPUT_SAT: int = BITCOIN_ANCHOR_OUTPUT_SAT


def create_anchor_script(pubkey_bytes: bytes) -> CScript:
    """
    Creates an Anchor output redeem script (BOLT #3).
    Script: <pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF 16 OP_CHECKSEQUENCEVERIFY OP_ENDIF
    Allows immediate spend by channel key, or 16-block fallback spend by anyone.
    """
    return CScript(cast(Any, [pubkey_bytes, OP_CHECKSIG]))


def create_anchor_commitment_transaction(
    funding_txid: str,
    funding_vout: int,
    sender_pubkey_bytes: bytes,
    receiver_pubkey_bytes: bytes,
    sender_balance_sat: int,
    receiver_balance_sat: int,
) -> tuple[CMutableTransaction, CScript, CScript]:
    """
    Creates commitment transaction with twin anchor outputs (330 sat each).
    """
    local_anchor_script = create_anchor_script(sender_pubkey_bytes)
    remote_anchor_script = create_anchor_script(receiver_pubkey_bytes)

    local_p2wsh = CScript(cast(Any, [OP_0, sha256(local_anchor_script)]))
    remote_p2wsh = CScript(cast(Any, [OP_0, sha256(remote_anchor_script)]))

    tx_builder = TransactionBuilder()
    tx_builder.add_input(funding_txid, funding_vout)

    if sender_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        tx_builder.add_output(sender_balance_sat, local_p2wsh)

    if receiver_balance_sat >= BITCOIN_DUST_LIMIT_SAT:
        tx_builder.add_output(receiver_balance_sat, remote_p2wsh)

    # Attach Twin Anchor Outputs
    tx_builder.add_output(ANCHOR_OUTPUT_SAT, local_p2wsh)
    tx_builder.add_output(ANCHOR_OUTPUT_SAT, remote_p2wsh)

    return tx_builder.build(), local_anchor_script, remote_anchor_script


def create_cpfp_fee_bump_transaction(
    parent_commitment_txid: str,
    anchor_vout: int,
    fee_bumper_pubkey_bytes: bytes,
    fee_bump_sat: int,
    anchor_redeem_script: CScript,
    signature: bytes,
) -> CMutableTransaction:
    """
    Constructs a child CPFP fee-bumping transaction spending an anchor output.
    """
    child_output_sat = max(0, ANCHOR_OUTPUT_SAT - fee_bump_sat)
    p2wpkh_spk = CScript(cast(Any, [OP_0, sha256(fee_bumper_pubkey_bytes)]))

    return (
        TransactionBuilder()
        .add_input(
            parent_commitment_txid, anchor_vout, sequence=SEQUENCE_CLTV_ENABLE_MASK
        )
        .add_output(child_output_sat, p2wpkh_spk)
        .add_witness_stack([signature, bytes(anchor_redeem_script)])
        .build()
    )
