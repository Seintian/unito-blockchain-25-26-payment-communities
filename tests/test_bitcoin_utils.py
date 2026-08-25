import pytest

from bitcoin_utils import (
    bytes_to_hex,
    generate_keypair,
    generate_secret,
    hash160,
    hash256,
    hex_to_bytes,
    pubkey_to_p2pkh_address,
    pubkey_to_p2wpkh_address,
    script_to_p2wsh_address,
    sha256,
)
from contracts import create_2of2_multisig_script


@pytest.fixture
def sample_keypair():
    secret, pubkey = generate_keypair()
    return secret, pubkey


def test_generate_secret():
    preimage, hash_digest = generate_secret()
    assert len(preimage) == 32, "Secret preimage must be exactly 32 bytes"
    assert len(hash_digest) == 32, "SHA256 digest must be exactly 32 bytes"
    assert sha256(preimage) == hash_digest, "Hash digest must match SHA256 of preimage"


@pytest.mark.parametrize(
    "data_input",
    [
        b"payment_communities_test_1",
        b"bitcoin_micropayment_channels",
        b"",
    ],
)
def test_hashing_functions(data_input):
    assert len(sha256(data_input)) == 32, "SHA256 digest length mismatch"
    assert len(hash256(data_input)) == 32, "Hash256 digest length mismatch"
    assert len(hash160(data_input)) == 20, "Hash160 digest length mismatch"


def test_generate_keypair(sample_keypair):
    secret, pubkey_bytes = sample_keypair
    assert secret is not None, "Derived Bitcoin secret key must not be None"
    assert len(pubkey_bytes) == 33, "Compressed public key must be 33 bytes"
    assert pubkey_bytes[0] in (0x02, 0x03), (
        "Compressed pubkey prefix must be 0x02 or 0x03"
    )


def test_onchain_addresses_derivation(sample_keypair):
    _, pubkey_bytes = sample_keypair
    p2pkh_address = pubkey_to_p2pkh_address(pubkey_bytes)
    p2wpkh_address = pubkey_to_p2wpkh_address(pubkey_bytes)

    assert p2pkh_address is not None, "Derived P2PKH address must not be None"
    assert p2wpkh_address is not None, "Derived P2WPKH address must not be None"
    assert str(p2wpkh_address).startswith(("tb1q", "bc1q", "bcrt1q")), (
        "SegWit address prefix invalid"
    )


def test_p2wsh_address_derivation():
    _, pubkey1 = generate_keypair()
    _, pubkey2 = generate_keypair()
    redeem_script = create_2of2_multisig_script(pubkey1, pubkey2)
    address = script_to_p2wsh_address(redeem_script)

    assert address is not None, "P2WSH address must not be None"
    assert str(address).startswith(("tb1q", "bc1q", "bcrt1q")), (
        "P2WSH address prefix invalid"
    )


@pytest.mark.parametrize(
    "raw_bytes",
    [
        b"\x00\x01\x02\x03",
        b"\xde\xad\xbe\xef",
    ],
)
def test_hex_conversion_symmetry(raw_bytes):
    hex_str = bytes_to_hex(raw_bytes)
    assert hex_to_bytes(hex_str) == raw_bytes, "Hex encoding/decoding must be symmetric"
