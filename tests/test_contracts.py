import pytest
from bitcoin.core.script import (
    OP_0,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    CScript,
)

from payment_communities.bitcoin_utils import generate_keypair, generate_secret
from payment_communities.contracts import (
    build_htlc_fulfill_witness,
    build_htlc_refund_witness,
    build_multisig_witness,
    create_2of2_multisig_script,
    create_htlc_script,
    create_p2wsh_scriptPubKey,
)


@pytest.fixture
def keypairs():
    _, pubkey1 = generate_keypair()
    _, pubkey2 = generate_keypair()
    return pubkey1, pubkey2


def test_multisig_script_construction(keypairs):
    pubkey1, pubkey2 = keypairs
    script = create_2of2_multisig_script(pubkey1, pubkey2)

    assert isinstance(script, CScript), "Multisig script must be an instance of CScript"
    script_opcodes = list(script)
    assert 2 in script_opcodes, "Script must specify 2 signatures required"
    assert OP_CHECKMULTISIG in script_opcodes, "Script must end with OP_CHECKMULTISIG"


def test_p2wsh_script_pub_key(keypairs):
    pubkey1, pubkey2 = keypairs
    redeem_script = create_2of2_multisig_script(pubkey1, pubkey2)
    p2wsh_script = create_p2wsh_scriptPubKey(redeem_script)

    assert next(iter(p2wsh_script)) == OP_0, "SegWit v0 P2WSH must start with OP_0"
    script_ops = list(p2wsh_script)
    assert len(bytes(script_ops[1])) == 32, (
        "P2WSH program must be a 32-byte SHA256 script hash"
    )


@pytest.mark.parametrize("locktime", [100, 1000, 500_000])
def test_htlc_script_construction(keypairs, locktime):
    sender_pubkey, receiver_pubkey = keypairs
    _, payment_hash = generate_secret()

    htlc_script = create_htlc_script(
        sender_pubkey=sender_pubkey,
        receiver_pubkey=receiver_pubkey,
        payment_hash=payment_hash,
        locktime=locktime,
    )
    assert isinstance(htlc_script, CScript), "HTLC script must be a CScript instance"
    opcodes = list(htlc_script)
    assert OP_IF in opcodes, "HTLC script must contain OP_IF for success branch"
    assert OP_ELSE in opcodes, "HTLC script must contain OP_ELSE for refund branch"
    assert OP_ENDIF in opcodes, "HTLC script must conclude with OP_ENDIF"
    assert OP_CHECKLOCKTIMEVERIFY in opcodes, (
        "HTLC script must use OP_CHECKLOCKTIMEVERIFY"
    )
    assert payment_hash in opcodes, "HTLC script must include payment hash digest"


def test_witness_builders():
    mock_signature = b"\x30\x44" + b"\x00" * 68
    mock_preimage = b"\x01" * 32
    mock_redeem_script = CScript(b"\x00")

    fulfill_witness = build_htlc_fulfill_witness(
        mock_signature, mock_preimage, mock_redeem_script
    )
    assert len(fulfill_witness) == 4, "Fulfill witness stack must contain 4 items"
    assert fulfill_witness[1] == mock_preimage, (
        "Second witness item must be secret preimage"
    )
    assert fulfill_witness[2] == b"\x01", (
        "Third witness item must be 1 for success branch"
    )

    refund_witness = build_htlc_refund_witness(mock_signature, mock_redeem_script)
    assert len(refund_witness) == 3, "Refund witness stack must contain 3 items"
    assert refund_witness[1] == b"", (
        "Second witness item must be empty bytes for refund branch"
    )

    multisig_witness = build_multisig_witness(
        mock_signature, mock_signature, mock_redeem_script
    )
    assert len(multisig_witness) == 4, "Multisig witness stack must contain 4 items"
    assert multisig_witness[0] == b"", (
        "First item must be empty bytes (CHECKMULTISIG off-by-one fix)"
    )
