"""
Node representation for Payment Communities network.
Manages Bitcoin keypairs, channels, invoices, revocation secrets, and payment routing.
"""

from payment_communities.bitcoin.utils import (
    bytes_to_hex,
    generate_keypair,
    generate_secret,
    pubkey_to_p2wpkh_address,
)
from payment_communities.domain.channel import Channel, ChannelState, HTLCContract
from payment_communities.exceptions import ChannelStateError
from payment_communities.protocols.revocation import generate_revocation_secret


class Node:
    """
    Aggregate root representing a Lightning Network node.
    """

    def __init__(self, alias: str, wif_key: str | None = None):
        self.alias = alias
        self.secret, self.pubkey_bytes = generate_keypair(wif_key)
        self.pubkey_hex = bytes_to_hex(self.pubkey_bytes)
        self.address = str(pubkey_to_p2wpkh_address(self.pubkey_bytes))
        self.channels: dict[str, Channel] = {}
        self.known_preimages: dict[str, str] = {}  # payment_hash -> preimage
        self.revocation_secrets: dict[
            str, dict[int, str]
        ] = {}  # peer -> {seq -> secret_hex}

    @property
    def p2wpkh_address(self) -> str:
        """Returns the SegWit P2WPKH address string for the node."""
        return self.address

    def has_channel_with(self, peer_alias: str) -> bool:
        """Returns True if an open or active channel exists with the given peer."""
        return peer_alias in self.channels

    def get_channel_with(self, peer_alias: str) -> Channel:
        """Returns the channel associated with the peer or raises ChannelStateError."""
        if not self.has_channel_with(peer_alias):
            raise ChannelStateError(f"No channel open with peer '{peer_alias}'.")
        return self.channels[peer_alias]

    def open_channel(self, peer: Node, capacity_sat: int) -> Channel:
        """Opens an off-chain micropayment channel with a peer node."""
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
            state=ChannelState.OPEN,
        )
        self.channels[peer.alias] = channel
        peer.channels[self.alias] = channel

        self.revocation_secrets[peer.alias] = {}
        peer.revocation_secrets[self.alias] = {}
        return channel

    def create_invoice(self) -> tuple[str, str]:
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
        htlc_id: str,
    ) -> bool:
        """Offers an HTLC to a direct peer node."""
        channel = self.get_channel_with(target_peer_alias)
        htlc = HTLCContract(
            htlc_id=htlc_id,
            payment_hash=payment_hash,
            amount_sat=amount_sat,
            locktime=locktime,
        )
        success = channel.add_htlc(htlc)
        if success:
            secret_bytes, _ = generate_revocation_secret()
            seq = channel.sequence_number
            self.revocation_secrets[target_peer_alias][seq] = bytes_to_hex(secret_bytes)
        return success

    def fulfill_htlc(self, peer_alias: str, htlc_id: str, preimage_hex: str) -> bool:
        """Settles an HTLC on a channel using secret preimage."""
        channel = self.get_channel_with(peer_alias)
        return channel.redeem_htlc(htlc_id, preimage_hex)

    def refund_htlc(
        self, peer_alias: str, htlc_id: str, current_block_height: int
    ) -> bool:
        """Claims HTLC refund on channel if timelock expired."""
        channel = self.get_channel_with(peer_alias)
        return channel.refund_htlc(htlc_id, current_block_height)
