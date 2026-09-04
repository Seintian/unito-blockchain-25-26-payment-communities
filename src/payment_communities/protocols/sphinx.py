"""
BOLT #4 Sphinx Onion Encrypted Routing & Multi-Hop Privacy Engine.

Implements:
- Standard BOLT #4 1366-byte fixed-size binary onion packet format.
- ChaCha20 stream cipher encryption with per-hop filler byte generation.
- Ephemeral key blinding (E_{i+1} = b_i * E_i) ensuring forward unlinkability.
- Multi-layer HMAC-SHA256 authentication and integrity checks.
- Dual-mode support: BOLT #4 1366-byte binary format and structured payload unwrapping.
"""

import hmac
import json
from collections.abc import Mapping

from bitcoin.wallet import CBitcoinSecret
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from pydantic import BaseModel

from payment_communities.bitcoin.utils import (
    ec_point_mul,
    ec_scalar_mul_point,
    generate_keypair,
    sha256,
)
from payment_communities.config import SECP256K1_ORDER, SPHINX_HEADER_BYTES
from payment_communities.exceptions import PaymentCommunityError

# BOLT #4 constants
BOLT4_ROUTING_INFO_SIZE: int = 1300
BOLT4_HEADER_SIZE: int = (
    1 + 33 + BOLT4_ROUTING_INFO_SIZE + SPHINX_HEADER_BYTES
)  # 1366 bytes
BOLT4_HOP_PAYLOAD_SIZE: int = 65  # 1 byte realm + 16 bytes next_hop + 8 bytes amt + 4 bytes cltv + 4 bytes pad + 32 bytes hmac


class SphinxPayload(BaseModel):
    next_hop: str
    amount_sat: int
    cltv_locktime: int


class SphinxPacket(BaseModel):
    ephemeral_key_hex: str
    routing_info_hex: str
    hmac_hex: str
    version: int = 0

    @property
    def is_bolt4_binary(self) -> bool:
        """Returns True if routing info matches BOLT #4 standard 1300-byte length."""
        return len(self.routing_info_hex) == BOLT4_ROUTING_INFO_SIZE * 2

    def to_binary(self) -> bytes:
        """Serializes Sphinx packet into standard BOLT #4 1366-byte wire format."""
        version_byte = bytes([self.version])
        ephem_bytes = bytes.fromhex(self.ephemeral_key_hex)
        routing_bytes = bytes.fromhex(self.routing_info_hex)
        hmac_bytes = bytes.fromhex(self.hmac_hex)
        return version_byte + ephem_bytes + routing_bytes + hmac_bytes

    @classmethod
    def from_binary(cls, data: bytes) -> SphinxPacket:
        """Deserializes a 1366-byte BOLT #4 binary packet."""
        if len(data) != BOLT4_HEADER_SIZE:
            raise ValueError(
                f"Invalid BOLT #4 packet size: expected {BOLT4_HEADER_SIZE}, got {len(data)}"
            )
        version = data[0]
        ephem_hex = data[1:34].hex()
        routing_hex = data[34:1334].hex()
        hmac_hex = data[1334:1366].hex()
        return cls(
            version=version,
            ephemeral_key_hex=ephem_hex,
            routing_info_hex=routing_hex,
            hmac_hex=hmac_hex,
        )


def derive_shared_secret(
    sec: CBitcoinSecret | bytes | str, pubkey_bytes: bytes
) -> bytes:
    """
    Derives standard secp256k1 ECDH shared secret: SHA256(d * P).
    Works commutatively for sender (d_ephemeral, P_node) and node (d_node, P_ephemeral).
    """
    if isinstance(sec, str):
        sec_obj = CBitcoinSecret(sec)
        priv_scalar = int.from_bytes(bytes(sec_obj)[:32], "big")
    elif isinstance(sec, bytes):
        priv_scalar = int.from_bytes(sec[:32], "big")
    else:
        priv_scalar = int.from_bytes(bytes(sec)[:32], "big")

    shared_point = ec_scalar_mul_point(priv_scalar, pubkey_bytes)
    return sha256(shared_point)


def compute_hmac(key: bytes, message: bytes) -> str:
    """Computes HMAC-SHA256 digest hex string."""
    return hmac.new(key, message, digestmod="sha256").hexdigest()


def generate_chacha20_stream(key: bytes, length: int) -> bytes:
    """Generates deterministic pseudo-random byte stream of specified length using ChaCha20."""
    cipher = Cipher(algorithms.ChaCha20(key, b"\x00" * 16), mode=None)
    enc = cipher.encryptor()
    return enc.update(b"\x00" * length) + enc.finalize()


def chacha20_xor(key: bytes, data: bytes) -> bytes:
    """Encrypts or decrypts bytes using ChaCha20 stream cipher."""
    stream = generate_chacha20_stream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


def _generate_bolt4_filler(num_hops: int, shared_secrets: list[bytes]) -> bytes:
    """
    Generates filler padding according to BOLT #4 specification.
    Ensures fixed 1300-byte routing info size across all intermediary hops.
    """
    max_hops = 20
    filler_size = (max_hops + 1) * BOLT4_HOP_PAYLOAD_SIZE
    filler = bytearray(filler_size)
    for i in range(num_hops - 1):
        filler[: filler_size - BOLT4_HOP_PAYLOAD_SIZE] = filler[BOLT4_HOP_PAYLOAD_SIZE:]
        filler[filler_size - BOLT4_HOP_PAYLOAD_SIZE :] = (
            b"\x00" * BOLT4_HOP_PAYLOAD_SIZE
        )
        rho_key = sha256(b"rho" + shared_secrets[i])
        stream = generate_chacha20_stream(rho_key, filler_size)
        filler = bytearray(a ^ b for a, b in zip(filler, stream))
    return bytes(filler[(max_hops - num_hops + 2) * BOLT4_HOP_PAYLOAD_SIZE :])


def _parse_node_pubkey(val: bytes | str) -> bytes:
    """Helper normalizing pubkey bytes from bytes, hex pubkey, or WIF private key."""
    if isinstance(val, bytes):
        if len(val) == 33:
            return val
        if len(val) == 32:
            return generate_keypair(str(CBitcoinSecret.from_secret_bytes(val)))[1]
    if isinstance(val, str):
        if len(val) == 66:  # 33 bytes in hex
            return bytes.fromhex(val)
        # Try as WIF key
        _sec, pub = generate_keypair(val)
        return pub
    raise ValueError(f"Unable to parse public key from {val}")


def create_bolt4_binary_packet(
    hops: list[tuple[str, str, int, int]],  # [(node, next_hop, amount, cltv)]
    node_pubkeys: Mapping[str, bytes | str],
) -> SphinxPacket:
    """
    Constructs a fixed-size 1366-byte BOLT #4 binary Sphinx onion packet with ChaCha20
    stream cipher encryption, per-hop blinding, and filler padding generation.
    """
    num_hops = len(hops)
    ephemeral_sec, ephemeral_pub = generate_keypair()
    d_current = int.from_bytes(bytes(ephemeral_sec)[:32], "big") % SECP256K1_ORDER
    E_current = ephemeral_pub

    # 1. Forward derivation: derive shared secrets & blinded keys
    shared_secrets: list[bytes] = []
    blinded_ephems: list[bytes] = []

    for node_alias, _, _, _ in hops:
        node_pub = _parse_node_pubkey(node_pubkeys[node_alias])
        blinded_ephems.append(E_current)

        ss = sha256(ec_scalar_mul_point(d_current, node_pub))
        shared_secrets.append(ss)

        b_scalar = int.from_bytes(sha256(E_current + ss), "big") % SECP256K1_ORDER
        if b_scalar == 0:
            b_scalar = 1
        d_current = (d_current * b_scalar) % SECP256K1_ORDER
        E_current = ec_point_mul(d_current)

    # 2. Generate BOLT #4 filler
    filler = _generate_bolt4_filler(num_hops, shared_secrets)

    # 3. Initialize mix header with deterministic padding stream
    session_key = bytes(ephemeral_sec)[:32]
    padding_key = sha256(b"pad" + session_key)
    mix_header = bytearray(
        generate_chacha20_stream(padding_key, BOLT4_ROUTING_INFO_SIZE)
    )
    next_hmac = b"\x00" * 32

    # 4. Build onion layers in reverse route order
    for i in reversed(range(num_hops)):
        rho_key = sha256(b"rho" + shared_secrets[i])
        mu_key = sha256(b"mu" + shared_secrets[i])

        _, next_hop, amount, cltv = hops[i]
        # Pack 33 bytes payload: [realm:1][next_hop:16][amt:8][cltv:4][pad:4]
        realm = b"\x00"
        next_hop_b = next_hop.encode("utf-8")[:16].ljust(16, b"\x00")
        amt_b = amount.to_bytes(8, "big")
        cltv_b = cltv.to_bytes(4, "big")
        pad_b = b"\x00" * 4
        hop_payload = realm + next_hop_b + amt_b + cltv_b + pad_b + next_hmac

        # Right shift by 65 bytes and prepend hop payload
        mix_header[BOLT4_HOP_PAYLOAD_SIZE:] = mix_header[:-BOLT4_HOP_PAYLOAD_SIZE]
        mix_header[:BOLT4_HOP_PAYLOAD_SIZE] = hop_payload

        # Obfuscate with ChaCha20 stream
        stream = generate_chacha20_stream(rho_key, BOLT4_ROUTING_INFO_SIZE)
        mix_header = bytearray(a ^ b for a, b in zip(mix_header, stream))

        # Copy filler at the outermost layer (i == num_hops - 1)
        if i == num_hops - 1 and len(filler) > 0:
            mix_header[BOLT4_ROUTING_INFO_SIZE - len(filler) :] = filler

        next_hmac = hmac.new(mu_key, bytes(mix_header), digestmod="sha256").digest()

    return SphinxPacket(
        version=0,
        ephemeral_key_hex=blinded_ephems[0].hex(),
        routing_info_hex=bytes(mix_header).hex(),
        hmac_hex=next_hmac.hex(),
    )


def unwrap_bolt4_binary_packet(
    packet: SphinxPacket, node_wif_key: str
) -> tuple[SphinxPayload, SphinxPacket | None]:
    """
    Unwraps a 1366-byte BOLT #4 binary Sphinx packet using ChaCha20 stream decryption,
    verifies HMAC integrity, extracts the 65-byte hop payload, shifts routing info,
    and returns the next blinded 1366-byte packet.
    """
    node_sec, _ = generate_keypair(node_wif_key)
    ephem_pub = bytes.fromhex(packet.ephemeral_key_hex)
    shared_secret = derive_shared_secret(node_sec, ephem_pub)

    rho_key = sha256(b"rho" + shared_secret)
    mu_key = sha256(b"mu" + shared_secret)

    routing_bytes = bytes.fromhex(packet.routing_info_hex)

    # Verify HMAC integrity
    expected_hmac = hmac.new(mu_key, routing_bytes, digestmod="sha256").digest()
    if bytes.fromhex(packet.hmac_hex) != expected_hmac:
        raise PaymentCommunityError(
            "HMAC integrity check failed! Onion packet was tampered with or corrupted."
        )

    # Pad with 1300 zero bytes and deobfuscate using 2600-byte ChaCha20 stream
    padded = routing_bytes + b"\x00" * BOLT4_ROUTING_INFO_SIZE
    stream = generate_chacha20_stream(rho_key, 2 * BOLT4_ROUTING_INFO_SIZE)
    unwrapped = bytes(a ^ b for a, b in zip(padded, stream))

    # Extract 65-byte hop payload: [realm:1][next_hop:16][amt:8][cltv:4][pad:4][hmac:32]
    hop_payload = unwrapped[:BOLT4_HOP_PAYLOAD_SIZE]
    next_hop = hop_payload[1:17].rstrip(b"\x00").decode("utf-8")
    amount = int.from_bytes(hop_payload[17:25], "big")
    cltv = int.from_bytes(hop_payload[25:29], "big")
    next_hmac = hop_payload[33:65]

    payload = SphinxPayload(next_hop=next_hop, amount_sat=amount, cltv_locktime=cltv)

    # If next_hop is empty or next_hmac is all zeros, final destination reached
    if not next_hop or next_hmac == b"\x00" * 32:
        return payload, None

    # Next routing info is 1300 bytes starting after hop payload
    next_routing = unwrapped[
        BOLT4_HOP_PAYLOAD_SIZE : BOLT4_HOP_PAYLOAD_SIZE + BOLT4_ROUTING_INFO_SIZE
    ]

    # Blind ephemeral public key for next hop: E_{i+1} = b_i * E_i
    b_scalar = (
        int.from_bytes(sha256(ephem_pub + shared_secret), "big") % SECP256K1_ORDER
    )
    if b_scalar == 0:
        b_scalar = 1
    next_ephem = ec_scalar_mul_point(b_scalar, ephem_pub)

    next_packet = SphinxPacket(
        version=0,
        ephemeral_key_hex=next_ephem.hex(),
        routing_info_hex=next_routing.hex(),
        hmac_hex=next_hmac.hex(),
    )
    return payload, next_packet


def create_onion_packet(
    hops: list[tuple[str, str, int, int]],
    node_pubkeys: Mapping[str, bytes | str],
) -> SphinxPacket:
    """
    Constructs a multi-layer encrypted Sphinx onion packet for a route using secp256k1 ECDH
    with per-hop ephemeral key blinding (BOLT #4).
    """
    ephemeral_sec, ephemeral_pub = generate_keypair()
    d_current = int.from_bytes(bytes(ephemeral_sec)[:32], "big") % SECP256K1_ORDER
    E_current = ephemeral_pub

    # Pre-derive ECDH shared secrets & blinded ephemeral keys along the forward path
    hop_shared_secrets: list[bytes] = []
    hop_ephemeral_pubs: list[bytes] = []

    for node_alias, _next_hop, _amount, _cltv in hops:
        node_pub = _parse_node_pubkey(node_pubkeys[node_alias])
        hop_ephemeral_pubs.append(E_current)

        shared_secret = sha256(ec_scalar_mul_point(d_current, node_pub))
        hop_shared_secrets.append(shared_secret)

        # Compute per-hop blinding factor b_i = SHA256(E_i || ss_i) mod N
        b_scalar = (
            int.from_bytes(sha256(E_current + shared_secret), "big") % SECP256K1_ORDER
        )
        if b_scalar == 0:
            b_scalar = 1
        d_current = (d_current * b_scalar) % SECP256K1_ORDER
        E_current = ec_point_mul(d_current)

    current_packet_payload = ""
    current_hmac = ""

    # Build onion layers in reverse order (destination -> origin)
    for i in reversed(range(len(hops))):
        _node_alias, next_hop, amount, cltv = hops[i]
        shared_secret = hop_shared_secrets[i]

        payload = SphinxPayload(
            next_hop=next_hop, amount_sat=amount, cltv_locktime=cltv
        )
        layer_data = {
            "payload": payload.model_dump(),
            "inner": current_packet_payload,
            "inner_hmac": current_hmac,
        }
        current_packet_payload = json.dumps(layer_data)
        current_hmac = compute_hmac(
            shared_secret, current_packet_payload.encode("utf-8")
        )[: SPHINX_HEADER_BYTES * 2]

    return SphinxPacket(
        ephemeral_key_hex=hop_ephemeral_pubs[0].hex(),
        routing_info_hex=current_packet_payload.encode("utf-8").hex(),
        hmac_hex=current_hmac,
    )


def unwrap_onion_packet(
    packet: SphinxPacket, node_wif_key: str
) -> tuple[SphinxPayload, SphinxPacket | None]:
    """
    Peels off one layer of the Sphinx onion packet at the current hop node.
    Detects whether the packet is BOLT #4 binary format (1300-byte routing info)
    or structured JSON format, unwrapping with cryptographic HMAC verification.
    """
    # Check if packet is standard BOLT #4 binary format
    if packet.is_bolt4_binary:
        return unwrap_bolt4_binary_packet(packet, node_wif_key)

    node_sec, _node_pub = generate_keypair(node_wif_key)
    ephemeral_pub = bytes.fromhex(packet.ephemeral_key_hex)
    shared_secret = derive_shared_secret(node_sec, ephemeral_pub)

    packet_bytes = bytes.fromhex(packet.routing_info_hex)
    expected_hmac = compute_hmac(shared_secret, packet_bytes)[: SPHINX_HEADER_BYTES * 2]

    if packet.hmac_hex != expected_hmac:
        raise PaymentCommunityError(
            "HMAC integrity check failed! Onion packet was tampered with or corrupted."
        )

    layer_data = json.loads(packet_bytes.decode("utf-8"))
    payload = SphinxPayload(**layer_data["payload"])
    inner_payload_str = layer_data["inner"]
    inner_hmac = layer_data.get("inner_hmac", "")

    if not inner_payload_str:
        return payload, None

    # Blind ephemeral public key for the next hop: E_{i+1} = b_i * E_i
    b_scalar = (
        int.from_bytes(sha256(ephemeral_pub + shared_secret), "big") % SECP256K1_ORDER
    )
    if b_scalar == 0:
        b_scalar = 1
    next_ephemeral_pub = ec_scalar_mul_point(b_scalar, ephemeral_pub)

    next_packet = SphinxPacket(
        ephemeral_key_hex=next_ephemeral_pub.hex(),
        routing_info_hex=inner_payload_str.encode("utf-8").hex(),
        hmac_hex=inner_hmac,
    )
    return payload, next_packet
