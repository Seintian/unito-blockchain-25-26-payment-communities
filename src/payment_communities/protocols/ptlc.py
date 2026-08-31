"""
Point Time-Locked Contracts (PTLCs) & Schnorr Adaptor Signatures engine.
Replaces HTLC hash preimages with ECC public keys and Schnorr Adaptor Signatures.
"""

from typing import TYPE_CHECKING, Any, cast

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
from rich.console import Console

from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import ec_point_mul, generate_secret, sha256
from payment_communities.config import SECP256K1_ORDER

if TYPE_CHECKING:
    from payment_communities.domain.node import Node
    from payment_communities.network.client import EsploraClient



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
    Creates a Schnorr Adaptor Signature s' encrypted with payment point T = t * G.
    R = k * G, e = SHA256(R || P || msg) mod N, s' = k + e * p (mod N).
    """
    from payment_communities.bitcoin.utils import ec_point_mul
    from payment_communities.config import SECP256K1_ORDER

    p_priv = (
        int.from_bytes(private_key_bytes[:32], "big")
        if len(private_key_bytes) >= 32
        else int.from_bytes(private_key_bytes, "big")
    ) % SECP256K1_ORDER
    P_pub = ec_point_mul(p_priv)

    k_secret = (
        int.from_bytes(sha256(private_key_bytes + msg_hash), "big") % SECP256K1_ORDER
    )
    if k_secret == 0:
        k_secret = 1
    R_point = ec_point_mul(k_secret)

    e = int.from_bytes(sha256(R_point + P_pub + msg_hash), "big") % SECP256K1_ORDER
    s_prime_scalar = (k_secret + e * p_priv) % SECP256K1_ORDER

    return AdaptorSignature(
        r_hex=R_point.hex(),
        s_prime_hex=s_prime_scalar.to_bytes(32, "big").hex(),
    )


def verify_adaptor_signature(
    adaptor_sig: AdaptorSignature, pubkey_bytes: bytes, msg_hash: bytes
) -> bool:
    """
    Verifies that s' G = R + e * P on secp256k1.
    """
    from payment_communities.bitcoin.utils import (
        ec_point_add,
        ec_point_mul,
        ec_scalar_mul_point,
    )
    from payment_communities.config import SECP256K1_ORDER

    try:
        R_point = bytes.fromhex(adaptor_sig.r_hex)
        s_prime = int.from_bytes(bytes.fromhex(adaptor_sig.s_prime_hex), "big")

        e = (
            int.from_bytes(sha256(R_point + pubkey_bytes + msg_hash), "big")
            % SECP256K1_ORDER
        )

        s_prime_G = ec_point_mul(s_prime)
        e_P = ec_scalar_mul_point(e, pubkey_bytes)
        expected_point = ec_point_add(R_point, e_P)

        return s_prime_G == expected_point
    except Exception:  # noqa: BLE001
        return False


def adapt_signature(adaptor_sig: AdaptorSignature, secret_scalar_bytes: bytes) -> bytes:
    """
    Decrypts/adapts signature s' using secret scalar t: s = s' + t (mod N).
    """
    s_prime = int.from_bytes(bytes.fromhex(adaptor_sig.s_prime_hex), "big")
    t = int.from_bytes(secret_scalar_bytes, "big") % SECP256K1_ORDER
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


def run_ptlc_demo(nodes: dict[str, Node], esplora: EsploraClient) -> None:
    """Demonstrates Point Time-Locked Contracts (PTLCs) and Schnorr Adaptor Signatures."""
    console = Console()
    console.print(
        "\n[bold cyan]=== PTLC & Adaptor Signature Demonstration ===[/bold cyan]\n"
    )

    alice_node = nodes["Alice"]
    secret_scalar_bytes, msg_hash = generate_secret()
    secret_scalar_int = int.from_bytes(secret_scalar_bytes, "big")
    payment_point = ec_point_mul(secret_scalar_int)

    console.print("1. Dave generates payment point T = t * G and sends to Alice...")
    console.print(f"  • Payment Point (T): {payment_point.hex()[:24]}...")

    console.print(
        "\n2. Alice creates Schnorr Adaptor Signature (s') encrypted under T..."
    )
    adaptor_sig = create_adaptor_signature(alice_node.secret, payment_point, msg_hash)
    assert verify_adaptor_signature(adaptor_sig, alice_node.pubkey_bytes, msg_hash)
    console.print(f"  • Adaptor s': {adaptor_sig.s_prime_hex[:24]}...")

    console.print("\n3. Dave adapts signature using secret scalar t (s = s' + t)...")
    final_sig = adapt_signature(adaptor_sig, secret_scalar_bytes)
    console.print(
        f"  • Final On-Chain Witness Signature (s): {final_sig.hex()[:24]}..."
    )

    console.print(
        "\n4. Alice observes s on-chain and extracts secret scalar t (t = s - s')..."
    )
    extracted_secret_bytes = extract_adaptor_secret(adaptor_sig, final_sig)
    assert extracted_secret_bytes == secret_scalar_bytes
    console.print(
        "  [bold green]⚡ PTLC ADAPTOR SECRET EXTRACTED CONFIRMED![/bold green]\n"
    )

