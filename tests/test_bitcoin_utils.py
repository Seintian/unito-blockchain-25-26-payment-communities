from bitcoin_utils import (
    generate_keypair,
    generate_secret,
    hash160,
    hash256,
    pubkey_to_p2pkh_address,
    pubkey_to_p2wpkh_address,
    script_to_p2wsh_address,
    sha256,
)
from contracts import create_2of2_multisig_script


def test_generate_secret():
    preimage, hash_digest = generate_secret()
    assert len(preimage) == 32
    assert len(hash_digest) == 32
    assert sha256(preimage) == hash_digest

def test_hashing_functions():
    data = b"payment_communities_test"
    assert len(sha256(data)) == 32
    assert len(hash256(data)) == 32
    assert len(hash160(data)) == 20

def test_generate_keypair():
    secret, pubkey_bytes = generate_keypair()
    assert secret is not None
    assert len(pubkey_bytes) == 33  # Compressed pubkey length
    assert pubkey_bytes[0] in (0x02, 0x03)

def test_onchain_addresses_derivation():
    _, pk = generate_keypair()
    p2pkh_addr = pubkey_to_p2pkh_address(pk)
    p2wpkh_addr = pubkey_to_p2wpkh_address(pk)
    assert p2pkh_addr is not None
    assert p2wpkh_addr is not None
    assert str(p2wpkh_addr).startswith(("tb1q", "bc1q", "bcrt1q"))

def test_p2wsh_address_derivation():
    _sec1, pk1 = generate_keypair()
    _sec2, pk2 = generate_keypair()
    redeem_script = create_2of2_multisig_script(pk1, pk2)
    address = script_to_p2wsh_address(redeem_script)
    assert address is not None
    assert str(address).startswith(("tb1q", "bc1q", "bcrt1q"))
