import hashlib
import secrets

from bitcoin.core import Hash, Hash160, b2x, x
from bitcoin.core.script import CScript
from bitcoin.wallet import (
    CBitcoinSecret,
    P2PKHBitcoinAddress,
    P2WPKHBitcoinAddress,
    P2WSHBitcoinAddress,
)

from payment_communities.config import (
    SECRET_KEY_SIZE_BYTES,
    init_bitcoin_network,
)

init_bitcoin_network()


def generate_secret() -> tuple[bytes, bytes]:
    """
    Generates a 32-byte cryptographic secret (preimage) and its SHA256 hash digest.
    Returns:
        (preimage_bytes, hash_digest_bytes)
    """
    preimage = secrets.token_bytes(SECRET_KEY_SIZE_BYTES)
    hash_digest = hashlib.sha256(preimage).digest()
    return preimage, hash_digest


def sha256(data: bytes) -> bytes:
    """Computes SHA256 digest."""
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Computes double SHA256 digest (Bitcoin standard)."""
    return Hash(data)


def hash160(data: bytes) -> bytes:
    """Computes RIPEMD160(SHA256(data))."""
    return Hash160(data)


def hex_to_bytes(hex_str: str) -> bytes:
    """Converts hex string to bytes."""
    return x(hex_str)


def bytes_to_hex(b: bytes) -> str:
    """Converts bytes to hex string."""
    return b2x(b)


def generate_keypair(wif: str | None = None) -> tuple[CBitcoinSecret, bytes]:
    """
    Generates or loads a Bitcoin private key and derives its compressed public key bytes.
    Returns:
        (CBitcoinSecret, pubkey_bytes)
    """
    if wif:
        secret = CBitcoinSecret(wif)
    else:
        # Generate random 32-byte private key
        raw_key = secrets.token_bytes(SECRET_KEY_SIZE_BYTES)
        secret = CBitcoinSecret.from_secret_bytes(raw_key)

    pubkey_bytes = secret.pub
    return secret, pubkey_bytes


def pubkey_to_p2pkh_address(pubkey_bytes: bytes) -> P2PKHBitcoinAddress:
    """Derives standard Pay-to-PubKey-Hash (P2PKH) on-chain address for a pubkey."""
    return P2PKHBitcoinAddress.from_pubkey(pubkey_bytes)


def pubkey_to_p2wpkh_address(pubkey_bytes: bytes) -> P2WPKHBitcoinAddress:
    """Derives native SegWit Pay-to-Witness-PubKey-Hash (P2WPKH) on-chain address."""
    return P2WPKHBitcoinAddress.from_bytes(0, hash160(pubkey_bytes))


def script_to_p2wsh_address(redeem_script: CScript) -> P2WSHBitcoinAddress:
    """
    Derives a Pay-to-Witness-Script-Hash (P2WSH) address from a redeem script.
    P2WSH scriptPubKey format: 0 <32-byte SHA256(redeemScript)>
    """
    script_hash = sha256(redeem_script)
    return P2WSHBitcoinAddress.from_bytes(0, script_hash)


def sign_sighash(
    secret: CBitcoinSecret, sighash: bytes, sighash_type: int = 1
) -> bytes:
    """
    Generates a DER-encoded ECDSA signature with appended SIGHASH flag byte for Bitcoin witness stack.
    """
    der_sig = secret.sign(sighash)
    return der_sig + bytes([sighash_type])


def verify_ecdsa_signature(
    pubkey_bytes: bytes, sighash: bytes, witness_sig: bytes
) -> bool:
    """
    Verifies a Bitcoin ECDSA witness signature against public key and sighash digest.
    """
    from bitcoin.core.key import CECKey, OpenSSLException

    try:
        der_sig = witness_sig[:-1] if len(witness_sig) > 1 else witness_sig
        key = CECKey()
        key.set_pubkey(pubkey_bytes)
        return key.verify(sighash, der_sig)
    except OpenSSLException, ValueError, TypeError:
        return False


def get_secp256k1_generator_point():
    """Returns the secp256k1 generator point G."""
    from ecdsa import SECP256k1

    return SECP256k1.generator


def ec_point_mul(scalar: int) -> bytes:
    """
    Computes secp256k1 point multiplication: P = scalar * G.
    Returns 33-byte compressed public key bytes.
    """
    from ecdsa import SECP256k1

    from payment_communities.config import SECP256K1_ORDER

    scalar_norm = scalar % SECP256K1_ORDER
    if scalar_norm == 0:
        scalar_norm = 1
    point = scalar_norm * SECP256k1.generator
    return point.to_bytes("compressed")


def ec_point_add(pubkey1_bytes: bytes, pubkey2_bytes: bytes) -> bytes:
    """
    Computes secp256k1 point addition: P_res = P1 + P2.
    Returns 33-byte compressed public key bytes.
    """
    from ecdsa import SECP256k1
    from ecdsa.ellipticcurve import PointJacobi

    p1 = PointJacobi.from_bytes(SECP256k1.curve, pubkey1_bytes)
    p2 = PointJacobi.from_bytes(SECP256k1.curve, pubkey2_bytes)
    res_point = p1 + p2
    return res_point.to_bytes("compressed")


def ec_scalar_mul_point(scalar: int, pubkey_bytes: bytes) -> bytes:
    """
    Computes secp256k1 point multiplication by scalar: P_res = scalar * P.
    Returns 33-byte compressed public key bytes.
    """
    from ecdsa import SECP256k1
    from ecdsa.ellipticcurve import PointJacobi

    from payment_communities.config import SECP256K1_ORDER

    scalar_norm = scalar % SECP256K1_ORDER
    if scalar_norm == 0:
        scalar_norm = 1
    point = PointJacobi.from_bytes(SECP256k1.curve, pubkey_bytes)
    res_point = scalar_norm * point
    return res_point.to_bytes("compressed")
