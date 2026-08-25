"""
Tests for CMutableTransaction building and Bitcoin Script execution verification.
"""

import pytest
from bitcoin.core.script import CScript

from payment_communities.bitcoin_utils import generate_keypair, generate_secret
from payment_communities.contracts import (
    create_2of2_multisig_script,
    create_htlc_script,
)
from payment_communities.transaction import (
    create_commitment_transaction,
    create_cooperative_close_transaction,
    create_funding_transaction,
    create_htlc_claim_transaction,
    create_htlc_refund_transaction,
)


@pytest.fixture
def keys():
    sec1, pub1 = generate_keypair()
    sec2, pub2 = generate_keypair()
    return sec1, pub1, sec2, pub2


def test_funding_transaction_construction(keys):
    _, pub1, _, pub2 = keys
    dummy_utxo_txid = "00" * 32

    tx, redeem_script = create_funding_transaction(
        funder_utxo_txid=dummy_utxo_txid,
        funder_utxo_vout=0,
        funder_pubkey_bytes=pub1,
        counterparty_pubkey_bytes=pub2,
        capacity_sat=100_000,
    )

    assert len(tx.vin) == 1, "Funding transaction must have 1 input"
    assert len(tx.vout) == 1, "Funding transaction must have 1 output"
    assert tx.vout[0].nValue == 100_000, "Funding output value must equal capacity"
    assert isinstance(redeem_script, CScript), "Redeem script must be CScript"


def test_commitment_transaction_construction(keys):
    _, pub1, _, pub2 = keys
    dummy_funding_txid = "11" * 32

    tx = create_commitment_transaction(
        funding_txid=dummy_funding_txid,
        funding_vout=0,
        sender_pubkey_bytes=pub1,
        receiver_pubkey_bytes=pub2,
        sender_balance_sat=60_000,
        receiver_balance_sat=40_000,
    )

    assert len(tx.vin) == 1, "Commitment transaction input count mismatch"
    assert len(tx.vout) == 2, "Commitment transaction output count mismatch"
    assert tx.vout[0].nValue == 60_000, "Sender output value mismatch"
    assert tx.vout[1].nValue == 40_000, "Receiver output value mismatch"


def test_cooperative_close_transaction_building(keys):
    _sec1, pub1, _sec2, pub2 = keys
    dummy_funding_txid = "22" * 32
    redeem_script = create_2of2_multisig_script(pub1, pub2)

    tx = create_cooperative_close_transaction(
        funding_txid=dummy_funding_txid,
        funding_vout=0,
        sender_pubkey_bytes=pub1,
        receiver_pubkey_bytes=pub2,
        final_sender_sat=70_000,
        final_receiver_sat=30_000,
        sig_sender=b"\x30\x44" + b"\x00" * 68,
        sig_receiver=b"\x30\x44" + b"\x00" * 68,
        redeem_script=redeem_script,
    )

    assert len(tx.vin) == 1, "Cooperative close input count mismatch"
    assert len(tx.vout) == 2, "Cooperative close output count mismatch"
    assert len(tx.wit.vtxinwit) == 1, "Witness stack must be attached to input"


def test_htlc_claim_and_refund_transaction_building(keys):
    _sec1, pub1, _sec2, pub2 = keys
    preimage, payment_hash = generate_secret()
    htlc_script = create_htlc_script(pub1, pub2, payment_hash, locktime=500)
    mock_sig = b"\x30\x44" + b"\x00" * 68

    claim_tx = create_htlc_claim_transaction(
        commitment_txid="33" * 32,
        htlc_vout=0,
        claimer_pubkey_bytes=pub2,
        amount_sat=25_000,
        preimage_bytes=preimage,
        htlc_redeem_script=htlc_script,
        claimer_signature=mock_sig,
    )
    assert len(claim_tx.vout) == 1, "Claim transaction output count mismatch"
    assert claim_tx.vout[0].nValue == 25_000, "Claim value mismatch"

    refund_tx = create_htlc_refund_transaction(
        commitment_txid="33" * 32,
        htlc_vout=0,
        sender_pubkey_bytes=pub1,
        amount_sat=25_000,
        locktime=500,
        htlc_redeem_script=htlc_script,
        sender_signature=mock_sig,
    )
    assert refund_tx.nLockTime == 500, "Refund transaction locktime mismatch"
    assert refund_tx.vout[0].nValue == 25_000, "Refund value mismatch"
