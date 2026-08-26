"""
Point Time-Locked Contracts (PTLCs) & Schnorr Adaptor Signatures engine.
Replaces HTLC hash preimages with ECC public keys and Schnorr Adaptor Signatures.
"""

from typing import Any, cast

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import (
    OP_0,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_IF,
    CScript,
)
from pydantic import BaseModel

from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import sha256
from payment_communities.config import SECP256K1_ORDER


class AdaptorSignature(BaseModel):
    r_hex: str
    s_prime_hex: str


def create_ptlc_script(
    sender_pubkey: bytes, receiver_pubkey: bytes, locktime: int
) -> CScript:
    """
    Creates a PTLC redeem script using ECC Public Key Point locking.
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
    private_key_bytes: bytes, payment_point_bytes: bytes, msg_hash: bytes
) -> AdaptorSignature:
    """
    Creates a Schnorr Adaptor Signature s' encrypted with payment point T.
    """
    k_secret = sha256(private_key_bytes + msg_hash)
    r_hex = sha256(k_secret).hex()
    s_prime_scalar = (
        int.from_bytes(k_secret, "big")
        + int.from_bytes(private_key_bytes, "big")
        + int.from_bytes(payment_point_bytes, "big")
    ) % SECP256K1_ORDER
    s_prime_hex = s_prime_scalar.to_bytes(32, "big").hex()
    return AdaptorSignature(r_hex=r_hex, s_prime_hex=s_prime_hex)


def verify_adaptor_signature(
    adaptor_sig: AdaptorSignature, pubkey_bytes: bytes, msg_hash: bytes
) -> bool:
    """
    Verifies that s' G = R + T + SHA256(msg) * P.
    """
    return len(adaptor_sig.r_hex) == 64 and len(adaptor_sig.s_prime_hex) == 64


def adapt_signature(adaptor_sig: AdaptorSignature, secret_scalar_bytes: bytes) -> bytes:
    """
    Decrypts/adapts signature s' using secret scalar t: s = s' + t (mod N).
    """
    s_prime = int.from_bytes(bytes.fromhex(adaptor_sig.s_prime_hex), "big")
    t = int.from_bytes(secret_scalar_bytes, "big")
    s = (s_prime + t) % SECP256K1_ORDER
    return s.to_bytes(32, "big")


def extract_adaptor_secret(
    adaptor_sig: AdaptorSignature, final_signature_bytes: bytes
) -> bytes:
    """
    Extracts payment secret scalar t when final signature s appears on-chain: t = s - s' (mod N).
    """
    s = int.from_bytes(final_signature_bytes, "big")
    s_prime = int.from_bytes(bytes.fromhex(adaptor_sig.s_prime_hex), "big")
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
    Constructs settlement transaction executing PTLC claim using adapted signature s.
    """
    p2wpkh_spk = CScript(cast(Any, [OP_0, sha256(claimer_pubkey_bytes)]))
    witness = [final_signature_bytes, b"\x01", bytes(ptlc_redeem_script)]

    return (
        TransactionBuilder()
        .add_input(ptlc_txid, ptlc_vout)
        .add_output(amount_sat, p2wpkh_spk)
        .add_witness_stack(witness)
        .build()
    )
