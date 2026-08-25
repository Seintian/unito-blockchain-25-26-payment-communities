import hashlib
import secrets
from typing import Tuple, Optional
import bitcoin
from bitcoin.core import b2x, x, Hash160, Hash
from bitcoin.core.script import CScript
from bitcoin.wallet import CBitcoinSecret, P2WSHBitcoinAddress, P2PKHBitcoinAddress

from config import init_bitcoin_network

init_bitcoin_network()

def generate_secret() -> Tuple[bytes, bytes]:
    """
    Generates a 32-byte cryptographic secret (preimage) and its SHA256 hash digest.
    Returns:
        (preimage_bytes, hash_digest_bytes)
    """
    preimage = secrets.token_bytes(32)
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

def generate_keypair(wif: Optional[str] = None) -> Tuple[CBitcoinSecret, bytes]:
    """
    Generates or loads a Bitcoin private key and derives its compressed public key bytes.
    Returns:
        (CBitcoinSecret, pubkey_bytes)
    """
    if wif:
        secret = CBitcoinSecret(wif)
    else:
        # Generate random 32-byte private key
        raw_key = secrets.token_bytes(32)
        secret = CBitcoinSecret.from_secret_bytes(raw_key)
    
    pubkey_bytes = secret.pub
    return secret, pubkey_bytes

def script_to_p2wsh_address(redeem_script: CScript) -> P2WSHBitcoinAddress:
    """
    Derives a Pay-to-Witness-Script-Hash (P2WSH) address from a redeem script.
    P2WSH scriptPubKey format: 0 <32-byte SHA256(redeemScript)>
    """
    script_hash = sha256(redeem_script)
    return P2WSHBitcoinAddress.from_bytes(0, script_hash)
