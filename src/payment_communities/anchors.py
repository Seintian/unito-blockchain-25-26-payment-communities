"""
Anchor Outputs & Dynamic CPFP (Child-Pays-For-Parent) Fee Bumping Engine (BOLT #3).
Adds 330 sat anchor outputs to commitment transactions, enabling nodes to dynamically
bump unconfirmed parent transaction fees via CPFP during L1 mempool fee spikes.
"""

from bitcoin.core import (
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    CTxInWitness,
    CTxWitness,
)
from bitcoin.core.script import (
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_ENDIF,
    OP_IFDUP,
    OP_NOTIF,
    CScript,
    CScriptWitness,
)

from payment_communities.bitcoin_utils import (
    hex_to_bytes,
    pubkey_to_p2wpkh_address,
    script_to_p2wsh_address,
)
from payment_communities.config import BITCOIN_DUST_LIMIT_SAT
from payment_communities.transaction import create_commitment_transaction

ANCHOR_OUTPUT_SAT: int = 330
"""Standard Lightning Anchor Output allocation (330 satoshis)."""


def create_anchor_script(pubkey_bytes: bytes) -> CScript:
    """
    Constructs a BOLT #3 Anchor Output Redeem Script.
    Script: <pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF 16 OP_CHECKSEQUENCEVERIFY OP_ENDIF
    Allows immediate spending by key owner, or spending by anyone after 16 blocks.
    """
    return CScript(
        [
            pubkey_bytes,
            OP_CHECKSIG,
            OP_IFDUP,
            OP_NOTIF,
            16,
            OP_CHECKSEQUENCEVERIFY,
            OP_ENDIF,
        ]
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
    Returns:
        (commitment_tx, local_anchor_script, remote_anchor_script)
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
    Pays a high miner fee to incentivize mempool package inclusion for unconfirmed parent commitment tx.
    Witness Stack: [<signature>, <anchor_redeem_script>]
    """
    txid_bytes = hex_to_bytes(parent_commitment_txid)
    txin = CMutableTxIn(COutPoint(txid_bytes, anchor_vout))

    # Child payout after mining fee
    payout_sat = max(BITCOIN_DUST_LIMIT_SAT, ANCHOR_OUTPUT_SAT - fee_bump_sat)
    payout_addr = pubkey_to_p2wpkh_address(fee_bumper_pubkey_bytes)
    txout = CMutableTxOut(payout_sat, payout_addr.to_scriptPubKey())

    tx = CMutableTransaction([txin], [txout])

    if signature:
        witness_stack = [signature, bytes(anchor_redeem_script)]
        tx.wit = CTxWitness([CTxInWitness(CScriptWitness(witness_stack))])

    return tx
