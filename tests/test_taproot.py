"""
Unit tests for BIP 340 Schnorr signatures, BIP 341 Taproot output tweaks, and Tapscript consensus verification.
"""

from payment_communities.bitcoin.contracts import create_p2tr_scriptPubKey
from payment_communities.bitcoin.interpreter import WitnessV1TaprootProgram
from payment_communities.bitcoin.taproot import (
    pubkey_to_p2tr_address,
    schnorr_sign,
    schnorr_verify,
    tagged_hash,
    taproot_tweak_pubkey,
)
from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import generate_keypair, sha256


def test_tagged_hash():
    tag = "BIP0340/challenge"
    msg = b"test message"
    h1 = tagged_hash(tag, msg)
    assert len(h1) == 32
    # Verify deterministic
    h2 = tagged_hash(tag, msg)
    assert h1 == h2


def test_schnorr_sign_and_verify():
    sec, pub = generate_keypair()
    msg = sha256(b"hello schnorr")

    sig = schnorr_sign(sec, msg)
    assert len(sig) == 64

    # Verify with 33-byte pubkey
    assert schnorr_verify(pub, msg, sig) is True

    # Verify with 32-byte x-only pubkey
    assert schnorr_verify(pub[1:33], msg, sig) is True

    # Tampered message fails
    bad_msg = sha256(b"tampered message")
    assert schnorr_verify(pub, bad_msg, sig) is False

    # Tampered signature fails
    bad_sig = bytearray(sig)
    bad_sig[10] ^= 0xFF
    assert schnorr_verify(pub, msg, bytes(bad_sig)) is False


def test_taproot_tweak_pubkey():
    _sec, pub = generate_keypair()
    tweak = sha256(b"h_taptweak")

    tweaked_x, parity = taproot_tweak_pubkey(pub, tweak)
    assert len(tweaked_x) == 32
    assert parity in (0, 1)

    # Address generation
    addr = pubkey_to_p2tr_address(tweaked_x)
    assert addr.startswith(("bc1p", "tb1p", "bcrt1p"))


def test_witness_v1_taproot_interpreter_keypath():
    from payment_communities.bitcoin.taproot import taproot_tweak_seckey

    sec, pub = generate_keypair()
    internal_x = pub[1:33]
    output_x, _parity = taproot_tweak_pubkey(internal_x)

    spk = create_p2tr_scriptPubKey(output_x)
    assert spk[0] == 0x51  # OP_1

    prog = WitnessV1TaprootProgram.from_script_pub_key(spk)
    assert prog.version == 1
    assert prog.program == output_x

    # Derive tweaked private key
    tweaked_sec = taproot_tweak_seckey(bytes(sec)[:32])

    dummy_tx = (
        TransactionBuilder().add_input("00" * 32, 0).add_output(50_000, spk).build()
    )
    tap_msg = tagged_hash("TapSighash", dummy_tx.serialize() + b"\x00")
    sig = schnorr_sign(tweaked_sec, tap_msg)

    tx = (
        TransactionBuilder()
        .add_input("00" * 32, 0)
        .add_output(50_000, spk)
        .add_witness_stack([sig])
        .build()
    )

    # Key-path verification (single 64-byte signature)
    assert (
        prog.verify(tx, 0, list(tx.wit.vtxinwit[0].scriptWitness.stack), 50_000) is True
    )
