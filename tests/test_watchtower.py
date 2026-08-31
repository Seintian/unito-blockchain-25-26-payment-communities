"""
Unit tests for Watchtower Service & Autonomous Breach Monitoring.
"""

from payment_communities.bitcoin.utils import generate_keypair
from payment_communities.config import DEFAULT_TO_SELF_DELAY_BLOCKS
from payment_communities.protocols.watchtower import (
    WatchtowerDaemon,
    WatchtowerSession,
    decrypt_justice_payload,
    derive_watchtower_hint,
    encrypt_justice_payload,
)


def test_watchtower_hint_derivation():
    txid = "aa" * 32
    hint = derive_watchtower_hint(txid)
    assert len(hint) == 32  # 16 bytes = 32 hex chars
    assert hint == derive_watchtower_hint(txid)


def test_justice_payload_encryption_decryption():
    txid = "bb" * 32
    payload = {"amount_sat": 50000, "node": "Alice"}
    encrypted = encrypt_justice_payload(txid, payload)
    assert encrypted != str(payload)

    decrypted = decrypt_justice_payload(txid, encrypted)
    assert decrypted == payload


def test_watchtower_session_registration_and_daemon_sweep():
    _alice_sec, alice_pub = generate_keypair()
    _bob_sec, bob_pub = generate_keypair()
    _rev_sec, rev_pub = generate_keypair()

    revoked_txid = "cc" * 32
    mock_sig = b"\x30\x44" + b"\x00" * 68

    session = WatchtowerSession()
    hint = session.register_justice_package(
        revoked_txid_hex=revoked_txid,
        sweeper_pubkey_hex=bob_pub.hex(),
        amount_sat=100_000,
        revocation_sig_hex=mock_sig.hex(),
        revocation_pubkey_hex=rev_pub.hex(),
        local_pubkey_hex=alice_pub.hex(),
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
    )

    assert hint in session.hint_map

    daemon = WatchtowerDaemon(session=session)

    # 1. Non-matching broadcast tx returns None
    assert daemon.scan_transaction("dd" * 32) is None

    # 2. Matching revoked broadcast tx triggers Justice Sweep
    justice_tx = daemon.scan_transaction(revoked_txid)
    assert justice_tx is not None
    assert len(justice_tx.vin) == 1
    assert len(justice_tx.vout) == 1
    assert justice_tx.vout[0].nValue == 100_000
    assert justice_tx.vin[0].prevout.n == 0
    assert len(daemon.swept_transactions) == 1


def test_watchtower_session_registration_with_custom_vout():
    """Tests Watchtower sweep targeting non-zero output index (revoked_vout > 0)."""
    _alice_sec, alice_pub = generate_keypair()
    _bob_sec, bob_pub = generate_keypair()
    _rev_sec, rev_pub = generate_keypair()

    revoked_txid = "ee" * 32
    mock_sig = b"\x30\x44" + b"\x00" * 68

    session = WatchtowerSession()
    hint = session.register_justice_package(
        revoked_txid_hex=revoked_txid,
        sweeper_pubkey_hex=bob_pub.hex(),
        amount_sat=75_000,
        revocation_sig_hex=mock_sig.hex(),
        revocation_pubkey_hex=rev_pub.hex(),
        local_pubkey_hex=alice_pub.hex(),
        to_self_delay=DEFAULT_TO_SELF_DELAY_BLOCKS,
        revoked_vout=3,
    )
    assert hint in session.hint_map

    daemon = WatchtowerDaemon(session=session)
    justice_tx = daemon.scan_transaction(revoked_txid)
    assert justice_tx is not None
    assert justice_tx.vin[0].prevout.n == 3
    assert justice_tx.vout[0].nValue == 75_000
