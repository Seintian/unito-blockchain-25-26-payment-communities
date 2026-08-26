"""
Unit tests for Anchor Outputs & Dynamic CPFP Fee Bumping Engine.
"""

from payment_communities.bitcoin.utils import generate_keypair
from payment_communities.protocols.anchors import (
    ANCHOR_OUTPUT_SAT,
    create_anchor_commitment_transaction,
    create_anchor_script,
    create_cpfp_fee_bump_transaction,
)


def test_create_anchor_script():
    _sec, pub = generate_keypair()
    script = create_anchor_script(pub)
    assert len(script) > 0
    assert pub in bytes(script)


def test_create_anchor_commitment_transaction():
    _alice_sec, alice_pub = generate_keypair()
    _bob_sec, bob_pub = generate_keypair()

    tx, _local_script, _remote_script = create_anchor_commitment_transaction(
        funding_txid="00" * 32,
        funding_vout=0,
        sender_pubkey_bytes=alice_pub,
        receiver_pubkey_bytes=bob_pub,
        sender_balance_sat=70_000,
        receiver_balance_sat=30_000,
    )

    assert len(tx.vout) >= 4  # 2 balance outputs + 2 anchor outputs
    assert tx.vout[-2].nValue == ANCHOR_OUTPUT_SAT
    assert tx.vout[-1].nValue == ANCHOR_OUTPUT_SAT


def test_create_cpfp_fee_bump_transaction():
    _alice_sec, alice_pub = generate_keypair()
    anchor_script = create_anchor_script(alice_pub)
    mock_sig = b"\x30\x44" + b"\x00" * 68

    child_tx = create_cpfp_fee_bump_transaction(
        parent_commitment_txid="aa" * 32,
        anchor_vout=2,
        fee_bumper_pubkey_bytes=alice_pub,
        fee_bump_sat=1000,
        anchor_redeem_script=anchor_script,
        signature=mock_sig,
    )

    assert len(child_tx.vin) == 1
    assert len(child_tx.vout) == 1
    assert child_tx.vin[0].prevout.hash == bytes.fromhex("aa" * 32)
    assert len(child_tx.wit.vtxinwit) == 1
