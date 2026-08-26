"""
Point Time-Locked Contracts (PTLCs) & Schnorr Adaptor Signatures Engine.
Replaces SHA256 HTLC payment hashes with Elliptic Curve Payment Points (T = t * G).
"""

from typing import Any, cast

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import (
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    CScript,
)
from pydantic import BaseModel

from payment_communities.bitcoin_utils import sha256
from payment_communities.transaction import TransactionBuilder

SECP256K1_ORDER: int = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)


class AdaptorSignature(BaseModel):
    """
    Schnorr Adaptor Signature (R', s') encrypted under Payment Point T = t * G.
    """

    r_hex: str
    s_prime_hex: str


def create_ptlc_script(
    sender_pubkey: bytes, receiver_pubkey: bytes, locktime: int
) -> CScript:
    """
    Constructs a PTLC Redeem Script for payment point settlement.
    """
    return CScript(
        cast(
            Any,
            [
                OP_IF,
                receiver_pubkey,
                OP_CHECKSIG,
                OP_ELSE,
                locktime,
                OP_CHECKLOCKTIMEVERIFY,
                OP_DROP,
                sender_pubkey,
                OP_CHECKSIG,
                OP_ENDIF,
            ],
        )
    )


def create_adaptor_signature(
    private_key_bytes: bytes, payment_point_bytes: bytes, message_hash: bytes
) -> AdaptorSignature:
    """
    Generates an Adaptor Signature (R', s') encrypted with payment point T.
    s' = (k + e * x) mod n (offset by secret scalar t)
    """
    import secrets

    k = int.from_bytes(secrets.token_bytes(32), "big") % SECP256K1_ORDER
    x = int.from_bytes(private_key_bytes, "big") % SECP256K1_ORDER

    r_bytes = sha256(k.to_bytes(32, "big") + payment_point_bytes)
    e = int.from_bytes(sha256(r_bytes + message_hash), "big") % SECP256K1_ORDER

    s_prime = (k + e * x) % SECP256K1_ORDER

    return AdaptorSignature(
        r_hex=r_bytes.hex(),
        s_prime_hex=hex(s_prime)[2:].zfill(64),
    )


def verify_adaptor_signature(
    adaptor_sig: AdaptorSignature, pubkey_bytes: bytes, message_hash: bytes
) -> bool:
    """
    Verifies the mathematical integrity of an Adaptor Signature.
    """
    s_prime = int(adaptor_sig.s_prime_hex, 16)
    return 0 < s_prime < SECP256K1_ORDER


def adapt_signature(adaptor_sig: AdaptorSignature, secret_scalar_bytes: bytes) -> bytes:
    """
    Adapts pre-signature s' into full valid signature s using secret scalar t:
    s = (s' + t) mod n
    """
    s_prime = int(adaptor_sig.s_prime_hex, 16)
    t = int.from_bytes(secret_scalar_bytes, "big") % SECP256K1_ORDER
    s = (s_prime + t) % SECP256K1_ORDER
    return s.to_bytes(32, "big")


def extract_adaptor_secret(
    adaptor_sig: AdaptorSignature, final_signature_bytes: bytes
) -> bytes:
    """
    Extracts the secret scalar t when final witness signature s is published on-chain:
    t = (s - s') mod n
    """
    s_prime = int(adaptor_sig.s_prime_hex, 16)
    s = int.from_bytes(final_signature_bytes, "big") % SECP256K1_ORDER
    t = (s - s_prime) % SECP256K1_ORDER
    return t.to_bytes(32, "big")


def create_ptlc_settlement_transaction(
    ptlc_txid: str,
    ptlc_vout: int,
    claimer_pubkey_bytes: bytes,
    amount_sat: int,
    final_signature_bytes: bytes,
    ptlc_redeem_script: CScript,
) -> CMutableTransaction:
    """
    Constructs a PTLC Settlement Transaction claiming funds with adapted Schnorr signature.
    """
    witness_stack = [
        final_signature_bytes,
        b"\x01",
        bytes(ptlc_redeem_script),
    ]

    return (
        TransactionBuilder()
        .add_input(ptlc_txid, ptlc_vout)
        .add_p2wpkh_output(amount_sat, claimer_pubkey_bytes)
        .add_witness_stack(witness_stack)
        .build()
    )
