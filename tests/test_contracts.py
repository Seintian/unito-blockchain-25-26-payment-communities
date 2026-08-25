import pytest
from bitcoin.core.script import CScript, OP_0, OP_CHECKMULTISIG, OP_IF, OP_ELSE, OP_ENDIF, OP_CHECKLOCKTIMEVERIFY
from src.bitcoin_utils import generate_keypair, generate_secret, sha256
from src.contracts import (
    create_2of2_multisig_script,
    create_p2wsh_scriptPubKey,
    create_htlc_script,
    build_htlc_fulfill_witness,
    build_htlc_refund_witness,
    build_multisig_witness
)

def test_multisig_script_construction():
    _, pk1 = generate_keypair()
    _, pk2 = generate_keypair()
    script = create_2of2_multisig_script(pk1, pk2)
    assert isinstance(script, CScript)
    script_ops = list(script)
    assert 2 in script_ops
    assert OP_CHECKMULTISIG in script_ops

def test_p2wsh_scriptPubKey():
    _, pk1 = generate_keypair()
    _, pk2 = generate_keypair()
    redeem = create_2of2_multisig_script(pk1, pk2)
    p2wsh = create_p2wsh_scriptPubKey(redeem)
    assert list(p2wsh)[0] == OP_0
    assert len(list(p2wsh)[1]) == 32  # SHA256 script hash

def test_htlc_script_construction():
    _, sender_pk = generate_keypair()
    _, receiver_pk = generate_keypair()
    _, payment_hash = generate_secret()
    locktime = 1000

    htlc_script = create_htlc_script(sender_pk, receiver_pk, payment_hash, locktime)
    assert isinstance(htlc_script, CScript)
    ops = list(htlc_script)
    assert OP_IF in ops
    assert OP_ELSE in ops
    assert OP_ENDIF in ops
    assert OP_CHECKLOCKTIMEVERIFY in ops
    assert payment_hash in ops

def test_witness_builders():
    sig = b"\x30\x44" + b"\x00" * 68
    preimage = b"\x01" * 32
    redeem = CScript([OP_0])

    fulfill_witness = build_htlc_fulfill_witness(sig, preimage, redeem)
    assert len(fulfill_witness) == 4
    assert fulfill_witness[1] == preimage
    assert fulfill_witness[2] == b"\x01"

    refund_witness = build_htlc_refund_witness(sig, redeem)
    assert len(refund_witness) == 3
    assert refund_witness[1] == b""

    multisig_witness = build_multisig_witness(sig, sig, redeem)
    assert len(multisig_witness) == 4
    assert multisig_witness[0] == b""
