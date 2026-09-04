"""
BIP 340 Schnorr Signatures and BIP 341 Taproot (SegWit v1) Cryptographic Primitives.

Implements:
- TaggedHash according to BIP 340 specification.
- 32-byte X-only public key extraction and point negation.
- BIP 340 Schnorr signature generation and verification.
- BIP 341 TapTweak output key derivation (Q = P + t*G).
- BIP 350 Bech32m address encoding for native SegWit v1 (bc1p... / tb1p...).
- Taproot Script Tree (taptree) leaf hashing and control block structure.
"""

import hashlib
import secrets

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import PointJacobi

from payment_communities.config import SECP256K1_ORDER

# secp256k1 field prime p = 2^256 - 2^32 - 977
SECP256K1_FIELD_P: int = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
)


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """
    Computes BIP 340 TaggedHash:
    TaggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
    """
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def point_from_x(x: int) -> PointJacobi | None:
    """
    Recovers the elliptic curve point on secp256k1 with x-coordinate x and even y-coordinate.
    y^2 = x^3 + 7 (mod p).
    """
    if x >= SECP256K1_FIELD_P:
        return None
    y_sq = (pow(x, 3, SECP256K1_FIELD_P) + 7) % SECP256K1_FIELD_P
    y = pow(y_sq, (SECP256K1_FIELD_P + 1) // 4, SECP256K1_FIELD_P)
    if pow(y, 2, SECP256K1_FIELD_P) != y_sq:
        return None
    if y % 2 != 0:
        y = SECP256K1_FIELD_P - y
    return PointJacobi(SECP256k1.curve, x, y, 1)


def lift_x(x_bytes: bytes) -> PointJacobi | None:
    """Lifts a 32-byte X-coordinate to a point with an even Y-coordinate (BIP 340 lift_x)."""
    if len(x_bytes) != 32:
        return None
    x_int = int.from_bytes(x_bytes, "big")
    return point_from_x(x_int)


def pubkey_to_x_only(pubkey_bytes: bytes) -> tuple[bytes, bool]:
    """
    Converts 33-byte compressed public key to 32-byte X-only public key.
    Returns:
        (x_only_bytes, is_negated)
    """
    if len(pubkey_bytes) == 32:
        return pubkey_bytes, False
    if len(pubkey_bytes) == 33:
        prefix = pubkey_bytes[0]
        x_only = pubkey_bytes[1:33]
        is_odd = prefix == 0x03
        return x_only, is_odd
    raise ValueError(f"Invalid public key length: {len(pubkey_bytes)}")


def schnorr_sign(
    private_key: bytes | int,
    msg: bytes,
    aux_rand: bytes | None = None,
) -> bytes:
    """
    Generates a 64-byte BIP 340 Schnorr signature: (R.x || s).
    sig = R.x (32 bytes) || s (32 bytes)
    """
    if isinstance(private_key, int):
        d0 = private_key % SECP256K1_ORDER
    else:
        d0 = int.from_bytes(private_key[:32], "big") % SECP256K1_ORDER
    if d0 == 0:
        raise ValueError("Private key cannot be 0")

    P = d0 * SECP256k1.generator
    P_y = int(P.y())
    if P_y % 2 != 0:
        d = SECP256K1_ORDER - d0
    else:
        d = d0

    d_bytes = d.to_bytes(32, "big")
    P_x_bytes = int(P.x()).to_bytes(32, "big")

    rand = aux_rand or secrets.token_bytes(32)
    t = bytes(
        a ^ b for a, b in zip(d_bytes, tagged_hash("BIP0340/aux", rand), strict=False)
    )
    k0 = (
        int.from_bytes(
            tagged_hash("BIP0340/nonce", t + P_x_bytes + msg),
            "big",
        )
        % SECP256K1_ORDER
    )
    if k0 == 0:
        raise RuntimeError("Random nonce k0 was 0, retry.")

    R = k0 * SECP256k1.generator
    R_y = int(R.y())
    if R_y % 2 != 0:
        k = SECP256K1_ORDER - k0
    else:
        k = k0

    R_x_bytes = int(R.x()).to_bytes(32, "big")
    e = (
        int.from_bytes(
            tagged_hash("BIP0340/challenge", R_x_bytes + P_x_bytes + msg),
            "big",
        )
        % SECP256K1_ORDER
    )

    s = (k + e * d) % SECP256K1_ORDER
    return R_x_bytes + s.to_bytes(32, "big")


def schnorr_verify(
    x_only_pubkey: bytes,
    msg: bytes,
    sig: bytes,
) -> bool:
    """
    Verifies a 64-byte BIP 340 Schnorr signature against 32-byte X-only public key.
    Verification formula: s*G == R + e*P.
    """
    if len(x_only_pubkey) == 33:
        x_only_pubkey = x_only_pubkey[1:33]
    if len(sig) != 64 or len(x_only_pubkey) != 32:
        return False

    r_x_bytes = sig[:32]

    s_bytes = sig[32:]
    r_x = int.from_bytes(r_x_bytes, "big")
    s = int.from_bytes(s_bytes, "big")

    if r_x >= SECP256K1_FIELD_P or s >= SECP256K1_ORDER:
        return False

    P = lift_x(x_only_pubkey)
    if P is None:
        return False

    e = (
        int.from_bytes(
            tagged_hash("BIP0340/challenge", r_x_bytes + x_only_pubkey + msg),
            "big",
        )
        % SECP256K1_ORDER
    )

    # R = s*G - e*P
    sG = s * SECP256k1.generator
    eP = e * P
    R = sG + (-eP)

    from ecdsa.ellipticcurve import INFINITY

    if R == INFINITY:
        return False

    if int(R.y()) % 2 != 0:
        return False

    return int(R.x()) == r_x


def taproot_tweak_pubkey(
    internal_pubkey_bytes: bytes,
    merkle_root: bytes | None = None,
) -> tuple[bytes, int]:
    """
    BIP 341 TapTweak key aggregation:
    t = TaggedHash("TapTweak", internal_pubkey || merkle_root)
    Q = P + t*G
    Returns:
        (output_pubkey_x_only_32_bytes, parity_bit_0_or_1)
    """
    x_only, _ = pubkey_to_x_only(internal_pubkey_bytes)
    P = lift_x(x_only)
    if P is None:
        raise ValueError("Invalid internal public key for Taproot tweak")

    h_payload = x_only + (merkle_root if merkle_root is not None else b"")
    t_scalar = (
        int.from_bytes(tagged_hash("TapTweak", h_payload), "big") % SECP256K1_ORDER
    )

    Q = P + (t_scalar * SECP256k1.generator)
    Q_x = int(Q.x()).to_bytes(32, "big")
    parity = 1 if int(Q.y()) % 2 != 0 else 0
    return Q_x, parity


def taproot_tweak_seckey(
    internal_seckey_bytes: bytes,
    merkle_root: bytes | None = None,
) -> bytes:
    """
    Derives tweaked private key corresponding to the Taproot output key:
    q = p + t (mod N) (negating p first if internal public key has odd Y).
    """
    d0 = int.from_bytes(internal_seckey_bytes[:32], "big") % SECP256K1_ORDER
    P = d0 * SECP256k1.generator
    if int(P.y()) % 2 != 0:
        d = SECP256K1_ORDER - d0
    else:
        d = d0

    P_x = int(P.x()).to_bytes(32, "big")
    h_payload = P_x + (merkle_root if merkle_root is not None else b"")
    t_scalar = (
        int.from_bytes(tagged_hash("TapTweak", h_payload), "big") % SECP256K1_ORDER
    )

    q = (d + t_scalar) % SECP256K1_ORDER
    return q.to_bytes(32, "big")


def tapleaf_hash(script_bytes: bytes, leaf_version: int = 0xC0) -> bytes:
    """Computes BIP 341 TapLeaf hash: TaggedHash("TapLeaf", leaf_version || compact_size(script) || script)."""
    script_len = len(script_bytes)
    if script_len < 253:
        len_bytes = bytes([script_len])
    elif script_len <= 0xFFFF:
        len_bytes = b"\xfd" + script_len.to_bytes(2, "little")
    else:
        len_bytes = b"\xfe" + script_len.to_bytes(4, "little")

    payload = bytes([leaf_version]) + len_bytes + script_bytes
    return tagged_hash("TapLeaf", payload)


# ==============================================================================
# BECH32M (BIP 350) ADDRESS DERIVATION FOR SEGWIT V1 TAPROOT
# ==============================================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(
    data: bytes | list[int], frombits: int, tobits: int, pad: bool = True
) -> list[int] | None:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode_bech32m(hrp: str, witness_version: int, witness_program: bytes) -> str:
    """Encodes BIP 350 Bech32m address (version 1+ SegWit / Taproot)."""
    five_bit_program = _convertbits(witness_program, 8, 5)
    if five_bit_program is None:
        raise ValueError("Failed to convert witness program to 5-bit array")
    data = [witness_version] + five_bit_program
    polymod = (
        _bech32_polymod(_bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0])
        ^ BECH32M_CONST
    )
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in data + checksum])


def pubkey_to_p2tr_address(output_pubkey_x_only: bytes, hrp: str = "tb") -> str:
    """Derives native Pay-to-Taproot (P2TR) Bech32m address for a 32-byte X-only output key."""
    return encode_bech32m(
        hrp=hrp, witness_version=1, witness_program=output_pubkey_x_only
    )
