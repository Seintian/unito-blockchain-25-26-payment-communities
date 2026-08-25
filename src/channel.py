"""
Payment Channel State Machine & HTLC Management module.
Manages off-chain balances, commitment sequence numbers, HTLC contracts, and channel state transitions.
"""

from enum import Enum
from typing import Dict, Optional, List
from pydantic import BaseModel, Field

from bitcoin_utils import sha256, bytes_to_hex, hex_to_bytes
from contracts import create_2of2_multisig_script, create_p2wsh_scriptPubKey

class ChannelState(str, Enum):
    CLOSED = "CLOSED"
    FUNDING = "FUNDING"
    OPEN = "OPEN"
    DISPUTE = "DISPUTE"
    SETTLED = "SETTLED"

class HTLCContract(BaseModel):
    htlc_id: str
    payment_hash: str  # Hex-encoded SHA256 digest
    amount_sat: int
    locktime: int
    preimage: Optional[str] = None  # Hex-encoded secret preimage when redeemed
    settled: bool = False
    refunded: bool = False

class Channel(BaseModel):
    channel_id: str
    sender_alias: str
    receiver_alias: str
    sender_pubkey_hex: str
    receiver_pubkey_hex: str
    capacity_sat: int
    balance_sender_sat: int
    balance_receiver_sat: int
    state: ChannelState = ChannelState.CLOSED
    funding_txid: Optional[str] = None
    funding_vout: Optional[int] = None
    active_htlcs: Dict[str, HTLCContract] = Field(default_factory=dict)
    sequence_number: int = 0

    @property
    def multisig_redeem_script(self):
        """Generates 2-of-2 multisig redeem script for the channel."""
        pk1 = hex_to_bytes(self.sender_pubkey_hex)
        pk2 = hex_to_bytes(self.receiver_pubkey_hex)
        return create_2of2_multisig_script(pk1, pk2)

    def add_htlc(self, htlc: HTLCContract) -> bool:
        """
        Offers an HTLC if sender has sufficient balance.
        Deducts amount from sender balance and locks it in active HTLCs.
        """
        if self.state != ChannelState.OPEN:
            return False
        if self.balance_sender_sat < htlc.amount_sat:
            return False
        
        self.balance_sender_sat -= htlc.amount_sat
        self.active_htlcs[htlc.htlc_id] = htlc
        self.sequence_number += 1
        return True

    def redeem_htlc(self, htlc_id: str, preimage_hex: str) -> bool:
        """
        Redeems an HTLC using the cryptographic secret preimage.
        Validates SHA256(preimage) == payment_hash.
        Reallocates locked HTLC amount to receiver balance.
        """
        if htlc_id not in self.active_htlcs:
            return False
        htlc = self.active_htlcs[htlc_id]
        if htlc.settled or htlc.refunded:
            return False
        
        preimage_bytes = hex_to_bytes(preimage_hex)
        hash_digest = sha256(preimage_bytes)
        if bytes_to_hex(hash_digest) != htlc.payment_hash:
            return False  # Preimage verification failed!

        htlc.preimage = preimage_hex
        htlc.settled = True
        self.balance_receiver_sat += htlc.amount_sat
        del self.active_htlcs[htlc_id]
        self.sequence_number += 1
        return True

    def refund_htlc(self, htlc_id: str, current_block_height: int) -> bool:
        """
        Reclaims HTLC amount back to sender after timelock expiry.
        """
        if htlc_id not in self.active_htlcs:
            return False
        htlc = self.active_htlcs[htlc_id]
        if current_block_height < htlc.locktime:
            return False  # Timelock has not expired yet
        
        htlc.refunded = True
        self.balance_sender_sat += htlc.amount_sat
        del self.active_htlcs[htlc_id]
        self.sequence_number += 1
        return True

    def close_cooperatively(self) -> Dict[str, int]:
        """
        Closes channel cooperatively and returns final balance breakdown.
        """
        self.state = ChannelState.SETTLED
        return {
            self.sender_alias: self.balance_sender_sat,
            self.receiver_alias: self.balance_receiver_sat
        }
