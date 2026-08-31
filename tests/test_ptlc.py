"""
Unit tests for Point Time-Locked Contracts (PTLCs) & Adaptor Signatures.
"""

from payment_communities.bitcoin.utils import generate_keypair, sha256
from payment_communities.protocols.ptlc import (
    adapt_signature,
    create_adaptor_signature,
    create_ptlc_script,
    create_ptlc_settlement_transaction,
    extract_adaptor_secret,
    verify_adaptor_signature,
)


def test_create_ptlc_script():
    _s_sec, s_pub = generate_keypair()
    _r_sec, r_pub = generate_keypair()

    script = create_ptlc_script(s_pub, r_pub, locktime=144)
    assert len(script) > 0
    assert r_pub in bytes(script)


def test_adaptor_signature_adapt_and_extract_secret():
    sender_sec, sender_pub = generate_keypair()
    from payment_communities.bitcoin.utils import ec_point_mul
    from payment_communities.protocols.ptlc import verify_schnorr_signature

    secret_scalar = sha256(b"secret_preimage")
    scalar_int = int.from_bytes(secret_scalar, "big")
    payment_point = ec_point_mul(scalar_int)
    msg_hash = sha256(b"ptlc_transaction_data")

    # 1. Create Adaptor Signature (s')
    adaptor_sig = create_adaptor_signature(bytes(sender_sec), payment_point, msg_hash)
    assert verify_adaptor_signature(adaptor_sig, sender_pub, msg_hash, payment_point)

    # 2. Adapt signature using secret scalar t (s = s' + t)
    final_sig = adapt_signature(adaptor_sig, secret_scalar)
    assert len(final_sig) == 32
    assert final_sig != bytes.fromhex(adaptor_sig.s_prime_hex)

    # Verify that (R', final_sig) is a valid Schnorr signature
    r_prime = bytes.fromhex(adaptor_sig.r_hex)
    assert verify_schnorr_signature(sender_pub, msg_hash, r_prime, final_sig)

    # 3. Extract secret scalar t when final signature s appears on-chain (t = s - s')
    extracted_secret = extract_adaptor_secret(adaptor_sig, final_sig)
    assert extracted_secret == secret_scalar


def test_create_ptlc_settlement_transaction():
    _alice_sec, alice_pub = generate_keypair()
    _bob_sec, bob_pub = generate_keypair()
    script = create_ptlc_script(alice_pub, bob_pub, locktime=144)

    mock_sig = b"\x00" * 32
    tx = create_ptlc_settlement_transaction(
        ptlc_txid="aa" * 32,
        ptlc_vout=0,
        claimer_pubkey_bytes=bob_pub,
        amount_sat=50_000,
        final_signature_bytes=mock_sig,
        ptlc_redeem_script=script,
    )

    assert len(tx.vin) == 1
    assert len(tx.vout) == 1
    assert tx.vout[0].nValue == 50_000
    assert len(tx.wit.vtxinwit) == 1
