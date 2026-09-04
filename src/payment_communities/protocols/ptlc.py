"""
Point Time-Locked Contracts (PTLCs) & Schnorr Adaptor Signatures engine.
Replaces HTLC hash preimages with ECC public keys and Schnorr Adaptor Signatures.
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

from payment_communities.bitcoin.transaction import TransactionBuilder
from payment_communities.bitcoin.utils import sha256
from payment_communities.config import SECP256K1_ORDER


class AdaptorSignature(BaseModel):
    r_hex: str  # Hex-encoded adaptor nonce point R' = (k + t) * G
    s_prime_hex: str  # Hex-encoded adaptor scalar s' = k + e * p (mod N)
    payment_point_hex: str = ""  # Hex-encoded payment point T = t * G

    @property
    def r_prime(self) -> bytes:
        return bytes.fromhex(self.r_hex)

    @property
    def s_prime(self) -> int:
        return int.from_bytes(bytes.fromhex(self.s_prime_hex), "big")

    @property
    def payment_point(self) -> bytes:
        return bytes.fromhex(self.payment_point_hex) if self.payment_point_hex else b""


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
    private_key: bytes | int, payment_point_bytes: bytes, msg_hash: bytes
) -> AdaptorSignature:
    """
    Creates a Schnorr Adaptor Signature s' encrypted with payment point T = t * G.
    R = k * G, R' = R + T = (k + t) * G, e = SHA256(R' || P || msg) mod N, s' = k + e * p (mod N).
    """
    from payment_communities.bitcoin.utils import ec_point_add, ec_point_mul
    from payment_communities.config import SECP256K1_ORDER

    if isinstance(private_key, int):
        p_priv = private_key % SECP256K1_ORDER
        priv_bytes = p_priv.to_bytes(32, "big")
    else:
        priv_bytes = private_key[:32]
        p_priv = int.from_bytes(priv_bytes, "big") % SECP256K1_ORDER

    P_pub = ec_point_mul(p_priv)

    k_secret = (
        int.from_bytes(sha256(priv_bytes + msg_hash + payment_point_bytes), "big")
        % SECP256K1_ORDER
    )
    if k_secret == 0:
        k_secret = 1
    R_point = ec_point_mul(k_secret)
    R_prime_point = ec_point_add(R_point, payment_point_bytes)

    e = (
        int.from_bytes(sha256(R_prime_point + P_pub + msg_hash), "big")
        % SECP256K1_ORDER
    )
    s_prime_scalar = (k_secret + e * p_priv) % SECP256K1_ORDER

    return AdaptorSignature(
        r_hex=R_prime_point.hex(),
        s_prime_hex=s_prime_scalar.to_bytes(32, "big").hex(),
        payment_point_hex=payment_point_bytes.hex(),
    )


def verify_adaptor_signature(
    adaptor_sig: AdaptorSignature,
    pubkey_bytes: bytes,
    msg_hash: bytes,
    payment_point_bytes: bytes | None = None,
) -> bool:
    """
    Verifies that s' * G = (R' - T) + e * P on secp256k1.
    """
    from payment_communities.bitcoin.utils import (
        ec_point_add,
        ec_point_mul,
        ec_point_sub,
        ec_scalar_mul_point,
    )
    from payment_communities.config import SECP256K1_ORDER

    try:
        T_point = (
            payment_point_bytes
            if payment_point_bytes is not None
            else bytes.fromhex(adaptor_sig.payment_point_hex)
        )
        R_prime_point = bytes.fromhex(adaptor_sig.r_hex)
        s_prime = int.from_bytes(bytes.fromhex(adaptor_sig.s_prime_hex), "big")

        e = (
            int.from_bytes(sha256(R_prime_point + pubkey_bytes + msg_hash), "big")
            % SECP256K1_ORDER
        )

        s_prime_G = ec_point_mul(s_prime)
        R_point = ec_point_sub(R_prime_point, T_point)
        e_P = ec_scalar_mul_point(e, pubkey_bytes)
        expected_point = ec_point_add(R_point, e_P)

        return s_prime_G == expected_point
    except Exception:  # noqa: BLE001
        return False


def verify_schnorr_signature(
    pubkey_bytes: bytes,
    msg_hash: bytes,
    r_point_bytes: bytes,
    final_signature: bytes | int,
) -> bool:
    """
    Verifies standard Schnorr signature (R', s) against public key P and message hash:
    s * G == R' + e * P, where e = SHA256(R' || P || msg).
    """
    from payment_communities.bitcoin.utils import (
        ec_point_add,
        ec_point_mul,
        ec_scalar_mul_point,
    )
    from payment_communities.config import SECP256K1_ORDER

    try:
        if isinstance(final_signature, int):
            s = final_signature % SECP256K1_ORDER
        else:
            s = int.from_bytes(final_signature, "big") % SECP256K1_ORDER

        e = (
            int.from_bytes(sha256(r_point_bytes + pubkey_bytes + msg_hash), "big")
            % SECP256K1_ORDER
        )
        s_G = ec_point_mul(s)
        e_P = ec_scalar_mul_point(e, pubkey_bytes)
        expected = ec_point_add(r_point_bytes, e_P)
        return s_G == expected
    except Exception:  # noqa: BLE001
        return False


def adapt_signature(adaptor_sig: AdaptorSignature, secret_scalar: bytes | int) -> bytes:
    """
    Decrypts/adapts signature s' using secret scalar t: s = s' + t (mod N).
    The resulting (R', s) is a valid standard Schnorr signature on message with public key P.
    """
    s_prime = int.from_bytes(bytes.fromhex(adaptor_sig.s_prime_hex), "big")
    if isinstance(secret_scalar, int):
        t = secret_scalar % SECP256K1_ORDER
    else:
        t = int.from_bytes(secret_scalar[:32], "big") % SECP256K1_ORDER
    s = (s_prime + t) % SECP256K1_ORDER
    return s.to_bytes(32, "big")


def extract_adaptor_secret(
    sig_or_adaptor: AdaptorSignature | bytes | int,
    sig_or_s_prime: bytes | int | None = None,
) -> bytes:
    """
    Extracts payment secret scalar t when final signature s appears on-chain: t = s - s' (mod N).
    Returns 32-byte big-endian secret bytes.
    """
    if isinstance(sig_or_adaptor, AdaptorSignature):
        s_prime = int.from_bytes(bytes.fromhex(sig_or_adaptor.s_prime_hex), "big")
        s = (
            sig_or_s_prime
            if isinstance(sig_or_s_prime, int)
            else int.from_bytes(cast(bytes, sig_or_s_prime)[:32], "big")
        )
    else:
        s = (
            sig_or_adaptor
            if isinstance(sig_or_adaptor, int)
            else int.from_bytes(sig_or_adaptor[:32], "big")
        )
        if isinstance(sig_or_s_prime, int):
            s_prime = sig_or_s_prime
        elif isinstance(sig_or_s_prime, bytes):
            s_prime = int.from_bytes(sig_or_s_prime[:32], "big")
        elif isinstance(sig_or_s_prime, AdaptorSignature):
            s_prime = int.from_bytes(bytes.fromhex(sig_or_s_prime.s_prime_hex), "big")
        else:
            raise TypeError("Invalid parameter types to extract_adaptor_secret")

    t = (s - s_prime) % SECP256K1_ORDER

    return t.to_bytes(32, "big")


def create_ptlc_settlement_transaction(
    funding_txid: str | None = None,
    funding_vout: int = 0,
    claimer_pubkey_bytes: bytes = b"",
    amount_sat: int = 0,
    final_signature_bytes: bytes = b"",
    ptlc_redeem_script: CScript | None = None,
    ptlc_txid: str | None = None,
    ptlc_vout: int = 0,
) -> CMutableTransaction:
    """
    Constructs settlement transaction executing PTLC claim using adapted signature s.
    """
    from payment_communities.bitcoin.contracts import create_p2wpkh_scriptPubKey

    txid = funding_txid or ptlc_txid or ("00" * 32)
    vout = funding_vout if funding_txid is not None else ptlc_vout

    p2wpkh_spk = create_p2wpkh_scriptPubKey(claimer_pubkey_bytes)
    builder = (
        TransactionBuilder().add_input(txid, vout).add_output(amount_sat, p2wpkh_spk)
    )

    if final_signature_bytes and ptlc_redeem_script:
        witness = [final_signature_bytes, b"\x01", bytes(ptlc_redeem_script)]
        builder.add_witness_stack(witness)

    return builder.build()


def create_bip340_adaptor_signature(
    private_key: bytes | int,
    payment_point_bytes: bytes,
    msg_hash: bytes,
) -> AdaptorSignature:
    """
    Creates a BIP 340 Schnorr Adaptor Signature s' encrypted with payment point T = t * G.
    R = k * G, R' = R + T, e = tagged_hash('BIP0340/challenge', r'_x || P_x || msg),
    s' = k + e * p (mod N).
    """
    from payment_communities.bitcoin.taproot import tagged_hash
    from payment_communities.bitcoin.utils import ec_point_add, ec_point_mul
    from payment_communities.config import SECP256K1_ORDER

    if isinstance(private_key, int):
        p_priv = private_key % SECP256K1_ORDER
        priv_bytes = p_priv.to_bytes(32, "big")
    else:
        priv_bytes = private_key[:32]
        p_priv = int.from_bytes(priv_bytes, "big") % SECP256K1_ORDER

    P_pub = ec_point_mul(p_priv)
    P_pub_x = P_pub[1:33]

    k_secret = (
        int.from_bytes(sha256(priv_bytes + msg_hash + payment_point_bytes), "big")
        % SECP256K1_ORDER
    )
    if k_secret == 0:
        k_secret = 1
    R_point = ec_point_mul(k_secret)
    R_prime_point = ec_point_add(R_point, payment_point_bytes)
    r_prime_x = R_prime_point[1:33]

    e = (
        int.from_bytes(
            tagged_hash("BIP0340/challenge", r_prime_x + P_pub_x + msg_hash), "big"
        )
        % SECP256K1_ORDER
    )
    s_prime_scalar = (k_secret + e * p_priv) % SECP256K1_ORDER

    return AdaptorSignature(
        r_hex=R_prime_point.hex(),
        s_prime_hex=s_prime_scalar.to_bytes(32, "big").hex(),
        payment_point_hex=payment_point_bytes.hex(),
    )


def verify_bip340_adaptor_signature(
    adaptor_sig: AdaptorSignature,
    pubkey_bytes: bytes,
    msg_hash: bytes,
    payment_point_bytes: bytes | None = None,
) -> bool:
    """
    Verifies a BIP 340 Schnorr Adaptor Signature:
    s' * G == (R' - T) + e * P, where e = tagged_hash('BIP0340/challenge', r'_x || P_x || msg).
    """
    from payment_communities.bitcoin.taproot import tagged_hash
    from payment_communities.bitcoin.utils import (
        ec_point_add,
        ec_point_mul,
        ec_point_sub,
        ec_scalar_mul_point,
    )
    from payment_communities.config import SECP256K1_ORDER

    try:
        T_point = (
            payment_point_bytes
            if payment_point_bytes is not None
            else bytes.fromhex(adaptor_sig.payment_point_hex)
        )
        R_prime_point = bytes.fromhex(adaptor_sig.r_hex)
        r_prime_x = R_prime_point[1:33]
        P_x = pubkey_bytes[1:33] if len(pubkey_bytes) == 33 else pubkey_bytes[:32]
        s_prime = int.from_bytes(bytes.fromhex(adaptor_sig.s_prime_hex), "big")

        e = (
            int.from_bytes(
                tagged_hash("BIP0340/challenge", r_prime_x + P_x + msg_hash), "big"
            )
            % SECP256K1_ORDER
        )

        s_prime_G = ec_point_mul(s_prime)
        R_point = ec_point_sub(R_prime_point, T_point)
        # Ensure compressed pubkey for point arithmetic
        P_comp = (
            pubkey_bytes
            if len(pubkey_bytes) == 33
            else (b"\x02" + pubkey_bytes if len(pubkey_bytes) == 32 else pubkey_bytes)
        )
        e_P = ec_scalar_mul_point(e, P_comp)
        expected_point = ec_point_add(R_point, e_P)

        return s_prime_G == expected_point
    except Exception:  # noqa: BLE001
        return False


def adapt_bip340_signature(
    adaptor_sig: AdaptorSignature, secret_scalar: bytes | int
) -> bytes:
    """
    Decrypts/adapts a BIP 340 adaptor signature using payment scalar t.
    Returns 64-byte Schnorr signature: r_x (32 bytes) || s (32 bytes).
    """
    from payment_communities.config import SECP256K1_ORDER

    s_prime = int.from_bytes(bytes.fromhex(adaptor_sig.s_prime_hex), "big")
    if isinstance(secret_scalar, int):
        t = secret_scalar % SECP256K1_ORDER
    else:
        t = int.from_bytes(secret_scalar[:32], "big") % SECP256K1_ORDER
    s = (s_prime + t) % SECP256K1_ORDER

    r_prime_x = bytes.fromhex(adaptor_sig.r_hex)[1:33]
    return r_prime_x + s.to_bytes(32, "big")


def create_taproot_ptlc_settlement_transaction(
    funding_txid: str,
    funding_vout: int,
    claimer_pubkey_x: bytes,
    amount_sat: int,
    schnorr_sig_64: bytes = b"",
) -> CMutableTransaction:
    """
    Constructs a Taproot (P2TR) PTLC settlement transaction spending the key-path
    using the adapted 64-byte Schnorr signature.
    """
    from payment_communities.bitcoin.contracts import create_p2tr_scriptPubKey

    p2tr_spk = create_p2tr_scriptPubKey(claimer_pubkey_x)
    builder = (
        TransactionBuilder()
        .add_input(funding_txid, funding_vout)
        .add_output(amount_sat, p2tr_spk)
    )

    if schnorr_sig_64:
        builder.add_witness_stack([schnorr_sig_64])

    return builder.build()
