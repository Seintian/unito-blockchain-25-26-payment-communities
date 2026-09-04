"""
Unit tests for BOLT #3 48-order Shachain secret derivation and compact tree receiver.
"""

import secrets

import pytest

from payment_communities.protocols.shachain import (
    ShachainGenerator,
    ShachainReceiver,
    can_derive,
    derive_shachain_secret,
)


def test_derive_shachain_secret_deterministic():
    seed = secrets.token_bytes(32)
    s0 = derive_shachain_secret(seed, 0)
    assert len(s0) == 32
    assert derive_shachain_secret(seed, 0) == s0
    s1 = derive_shachain_secret(seed, 1)
    assert s1 != s0


def test_can_derive_relationship():
    # Index 0 can derive any index
    assert can_derive(0, 0) is True
    assert can_derive(0, 1) is True
    assert can_derive(0, 255) is True

    # Trailing zero index derivation
    # 2 = 0b10 (1 trailing zero), mask is ~1
    assert can_derive(2, 2) is True
    assert can_derive(2, 3) is True
    assert can_derive(2, 4) is False


def test_shachain_compact_receiver_storage():
    seed = secrets.token_bytes(32)
    gen = ShachainGenerator(seed)
    receiver = ShachainReceiver()

    # Add 100 sequential secrets
    for i in range(100):
        sec = gen.get_secret(i)
        receiver.add_secret(sec, i)

    # Receiver must store <= 48 elements (actually around 1-7 for 100 secrets)
    assert len(receiver.elements) <= 48
    assert len(receiver.elements) < 15

    # Verify all 100 secrets can be reconstructed deterministically
    for i in range(100):
        reconstructed = receiver.get_secret(i)
        expected = gen.get_secret(i)
        assert reconstructed == expected, f"Mismatch at index {i}"


def test_shachain_commitment_number_indexing():
    seed = secrets.token_bytes(32)
    gen = ShachainGenerator(seed)
    receiver = ShachainReceiver()

    # Add commitment secrets using BOLT #3 reversed indices
    for commit_num in range(10):
        sec = gen.get_commitment_secret(commit_num)
        max_idx = (1 << 48) - 1
        receiver.add_secret(sec, max_idx - commit_num)

    for commit_num in range(10):
        assert receiver.get_commitment_secret(commit_num) == gen.get_commitment_secret(
            commit_num
        )


def test_shachain_tamper_detection():
    seed = secrets.token_bytes(32)
    gen = ShachainGenerator(seed)
    receiver = ShachainReceiver()

    sec0 = gen.get_secret(0)
    receiver.add_secret(sec0, 0)

    # Now attempt to insert an invalid secret for index 1 (should derive from 0)
    fake_sec1 = b"\xff" * 32
    with pytest.raises(ValueError, match="Shachain secret mismatch"):
        receiver.add_secret(fake_sec1, 1)
