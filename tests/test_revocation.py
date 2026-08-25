"""
Tests for Poon-Dryja (LN-Penalty) revocation secrets and breach remedy justice sweep transactions.
"""

import pytest
from bitcoin.core.script import OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, CScript

from payment_communities.bitcoin_utils import generate_keypair
from payment_communities.revocation import (
    RevocationStore,
    create_breach_remedy_transaction,
    create_revocable_output_script,
    generate_revocation_secret,
)


@pytest.fixture
def keypairs():
    _, pub1 = generate_keypair()
    _, pub2 = generate_keypair()
    return pub1, pub2


def test_revocation_secret_generation():
    secret, rev_hash = generate_revocation_secret()
    assert len(secret) == 32, "Revocation secret must be 32 bytes"
    assert len(rev_hash) == 32, "Revocation hash must be 32 bytes"


def test_revocable_output_script_construction(keypairs):
    rev_pubkey, local_pubkey = keypairs
    script = create_revocable_output_script(rev_pubkey, local_pubkey, to_self_delay=144)

    assert isinstance(script, CScript), "Revocable output script must be CScript"
    opcodes = list(script)
    assert OP_CHECKSIG in opcodes, "Script must contain OP_CHECKSIG"
    assert OP_CHECKSEQUENCEVERIFY in opcodes, "Script must contain OP_CHECKSEQUENCEVERIFY"


def test_revocation_store_tracking():
    store = RevocationStore()
    assert store.is_state_revoked(1) is False, "Initial state 1 must not be revoked"

    sec_bytes, _ = generate_revocation_secret()
    sec_hex = sec_bytes.hex()

    store.register_remote_secret(1, sec_hex)
    assert store.is_state_revoked(1) is True, "State 1 must be marked revoked after secret registration"
    assert store.get_revocation_secret(1) == sec_hex, "Revealed secret must match registered secret"


def test_breach_remedy_transaction_construction(keypairs):
    rev_pubkey, local_pubkey = keypairs
    redeem_script = create_revocable_output_script(rev_pubkey, local_pubkey, to_self_delay=144)
    mock_sig = b"\x30\x44" + b"\x00" * 68

    justice_tx = create_breach_remedy_transaction(
        revoked_txid="aa" * 32,
        revoked_vout=0,
        sweeper_pubkey_bytes=local_pubkey,
        amount_sat=100_000,
        revocation_secret_signature=mock_sig,
        revocable_redeem_script=redeem_script,
    )

    assert len(justice_tx.vin) == 1, "Justice sweep must have 1 input"
    assert len(justice_tx.vout) == 1, "Justice sweep must have 1 output"
    assert justice_tx.vout[0].nValue == 100_000, "Justice sweep output must claim 100% capacity"
    assert len(justice_tx.wit.vtxinwit) == 1, "Justice sweep witness stack must be attached"
