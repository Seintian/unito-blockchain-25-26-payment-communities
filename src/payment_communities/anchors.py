"""
Anchor Outputs & Dynamic CPFP (Child-Pays-For-Parent) Fee Bumping Engine (BOLT #3).
Adds 330 sat anchor outputs to commitment transactions, enabling nodes to dynamically
bump unconfirmed parent transaction fees via CPFP during L1 mempool fee spikes.
"""

from typing import Any, cast

from bitcoin.core import (
    CMutableTransaction,
    CMutableTxOut,
)
from bitcoin.core.script import (
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_ENDIF,
    OP_IFDUP,
    OP_NOTIF,
    CScript,
)

from payment_communities.bitcoin_utils import (
    script_to_p2wsh_address,
)
from payment_communities.config import BITCOIN_DUST_LIMIT_SAT
from payment_communities.transaction import (
    TransactionBuilder,
    create_commitment_transaction,
)

ANCHOR_OUTPUT_SAT: int = 330
"""Standard Lightning Anchor Output allocation (330 satoshis)."""


def create_anchor_script(pubkey_bytes: bytes) -> CScript:
    """
    Constructs a BOLT #3 Anchor Output Redeem Script.
    """
    return CScript(
        cast(
            Any,
            [
                pubkey_bytes,
                OP_CHECKSIG,
                OP_IFDUP,
                OP_NOTIF,
                16,
                OP_CHECKSEQUENCEVERIFY,
                OP_ENDIF,
            ],
        )
    )


def create_anchor_commitment_transaction(
    funding_txid: str,
    funding_vout: int,
    sender_pubkey_bytes: bytes,
    receiver_pubkey_bytes: bytes,
    sender_balance_sat: int,
    receiver_balance_sat: int,
    htlc_outputs: list[tuple[int, CScript]] | None = None,
) -> tuple[CMutableTransaction, CScript, CScript]:
    """
    Constructs an off-chain Commitment Transaction augmented with 330 sat anchor outputs.
    """
    tx = create_commitment_transaction(
        funding_txid=funding_txid,
        funding_vout=funding_vout,
        sender_pubkey_bytes=sender_pubkey_bytes,
        receiver_pubkey_bytes=receiver_pubkey_bytes,
        sender_balance_sat=sender_balance_sat,
        receiver_balance_sat=receiver_balance_sat,
        htlc_outputs=htlc_outputs,
    )

    local_anchor_script = create_anchor_script(sender_pubkey_bytes)
    remote_anchor_script = create_anchor_script(receiver_pubkey_bytes)

    local_addr = script_to_p2wsh_address(local_anchor_script)
    remote_addr = script_to_p2wsh_address(remote_anchor_script)

    tx.vout.append(CMutableTxOut(ANCHOR_OUTPUT_SAT, local_addr.to_scriptPubKey()))
    tx.vout.append(CMutableTxOut(ANCHOR_OUTPUT_SAT, remote_addr.to_scriptPubKey()))

    return tx, local_anchor_script, remote_anchor_script


def create_cpfp_fee_bump_transaction(
    parent_commitment_txid: str,
    anchor_vout: int,
    fee_bumper_pubkey_bytes: bytes,
    fee_bump_sat: int,
    anchor_redeem_script: CScript,
    signature: bytes = b"",
) -> CMutableTransaction:
    """
    Constructs a Child-Pays-For-Parent (CPFP) Child Transaction spending an anchor output.
    """
    payout_sat = max(BITCOIN_DUST_LIMIT_SAT, ANCHOR_OUTPUT_SAT - fee_bump_sat)
    builder = (
        TransactionBuilder()
        .add_input(parent_commitment_txid, anchor_vout)
        .add_p2wpkh_output(payout_sat, fee_bumper_pubkey_bytes)
    )

    if signature:
        witness_stack = [signature, bytes(anchor_redeem_script)]
        builder.add_witness_stack(witness_stack)

    return builder.build()
