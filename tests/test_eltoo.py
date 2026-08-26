"""
Unit tests for Eltoo (LN-Symmetric) State Update Protocol.
"""

import pytest

from payment_communities.bitcoin.contracts import create_2of2_multisig_script
from payment_communities.bitcoin.utils import generate_keypair
from payment_communities.exceptions import PaymentCommunityError
from payment_communities.protocols.eltoo import (
    ELTOO_BASE_LOCKTIME,
    EltooState,
    create_eltoo_settlement_transaction,
    create_eltoo_update_transaction,
    validate_eltoo_override,
)


def test_eltoo_state_locktime_and_validation():
    s1 = EltooState(
        state_number=1, sender_balance_sat=80000, receiver_balance_sat=20000
    )
    s2 = EltooState(
        state_number=2, sender_balance_sat=50000, receiver_balance_sat=50000
    )

    assert s1.locktime == ELTOO_BASE_LOCKTIME + 1
    assert s2.locktime == ELTOO_BASE_LOCKTIME + 2

    assert validate_eltoo_override(s1, s2) is True

    with pytest.raises(PaymentCommunityError, match="Eltoo Invalid State Override"):
        validate_eltoo_override(s2, s1)


def test_create_eltoo_update_and_settlement_transactions():
    _alice_sec, alice_pub = generate_keypair()
    _bob_sec, bob_pub = generate_keypair()
    multisig_script = create_2of2_multisig_script(alice_pub, bob_pub)

    state2 = EltooState(
        state_number=2, sender_balance_sat=60000, receiver_balance_sat=40000
    )

    update_tx = create_eltoo_update_transaction(
        spending_txid="00" * 32,
        spending_vout=0,
        state=state2,
        multisig_redeem_script=bytes(multisig_script),
        sig_sender=b"\x00" * 64,
        sig_receiver=b"\x00" * 64,
    )

    assert len(update_tx.vin) == 1
    assert len(update_tx.vout) == 1
    assert update_tx.nLockTime == ELTOO_BASE_LOCKTIME + 2

    settle_tx = create_eltoo_settlement_transaction(
        update_txid=update_tx.GetTxid().hex(),
        update_vout=0,
        sender_pubkey_bytes=alice_pub,
        receiver_pubkey_bytes=bob_pub,
        state=state2,
        sig_sender=b"\x00" * 64,
        sig_receiver=b"\x00" * 64,
        multisig_redeem_script=bytes(multisig_script),
    )

    assert len(settle_tx.vin) == 1
    assert len(settle_tx.vout) == 2
    assert settle_tx.vout[0].nValue == 60000
    assert settle_tx.vout[1].nValue == 40000
