"""
Node representation for Payment Communities network.
Manages Bitcoin keypairs, channels, invoices, and payment routing.
"""

from typing import Dict, Optional, Tuple
from bitcoin.wallet import CBitcoinSecret

from src.bitcoin_utils import generate_keypair, generate_secret, bytes_to_hex, hex_to_bytes
from src.channel import Channel, ChannelState, HTLCContract

class Node:
    def __init__(self, alias: str, wif_key: Optional[str] = None):
        self.alias = alias
        self.secret, self.pubkey_bytes = generate_keypair(wif_key)
        self.pubkey_hex = bytes_to_hex(self.pubkey_bytes)
        self.channels: Dict[str, Channel] = {}
        self.known_preimages: Dict[str, str] = {}  # payment_hash -> preimage

    def open_channel(self, peer: "Node", capacity_sat: int) -> Channel:
        """Opens an off-chain unidirectional channel with a peer node."""
        channel_id = f"chan_{self.alias}_{peer.alias}"
        channel = Channel(
            channel_id=channel_id,
            sender_alias=self.alias,
            receiver_alias=peer.alias,
            sender_pubkey_hex=self.pubkey_hex,
            receiver_pubkey_hex=peer.pubkey_hex,
            capacity_sat=capacity_sat,
            balance_sender_sat=capacity_sat,
            balance_receiver_sat=0,
            state=ChannelState.OPEN
        )
        self.channels[peer.alias] = channel
        peer.channels[self.alias] = channel
        return channel

    def create_invoice(self) -> Tuple[str, str]:
        """
        Generates secret preimage and payment hash for receiving payments.
        Returns:
            (preimage_hex, payment_hash_hex)
        """
        preimage, payment_hash = generate_secret()
        preimage_hex = bytes_to_hex(preimage)
        hash_hex = bytes_to_hex(payment_hash)
        self.known_preimages[hash_hex] = preimage_hex
        return preimage_hex, hash_hex

    def route_htlc_payment(
        self,
        target_peer_alias: str,
        amount_sat: int,
        payment_hash: str,
        locktime: int,
        htlc_id: str
    ) -> bool:
        """Offers an HTLC to a direct peer node."""
        if target_peer_alias not in self.channels:
            return False
        channel = self.channels[target_peer_alias]
        htlc = HTLCContract(
            htlc_id=htlc_id,
            payment_hash=payment_hash,
            amount_sat=amount_sat,
            locktime=locktime
        )
        return channel.add_htlc(htlc)

    def fulfill_htlc(self, peer_alias: str, htlc_id: str, preimage_hex: str) -> bool:
        """Settles an HTLC on a channel using secret preimage."""
        if peer_alias not in self.channels:
            return False
        channel = self.channels[peer_alias]
        return channel.redeem_htlc(htlc_id, preimage_hex)

    def refund_htlc(self, peer_alias: str, htlc_id: str, current_block_height: int) -> bool:
        """Claims HTLC refund on channel if timelock expired."""
        if peer_alias not in self.channels:
            return False
        channel = self.channels[peer_alias]
        return channel.refund_htlc(htlc_id, current_block_height)
