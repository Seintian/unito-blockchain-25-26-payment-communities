"""
Payment Channel State Machine & HTLC Management module.
Manages off-chain balances, commitment sequence numbers, HTLC contracts,
Poon-Dryja revocation state tracking, and state transitions.
"""

from enum import Enum

from pydantic import BaseModel, Field

from payment_communities.bitcoin_utils import bytes_to_hex, hex_to_bytes, sha256
from payment_communities.contracts import create_2of2_multisig_script
from payment_communities.exceptions import (
    ChannelStateError,
    HTLCExpiredError,
    InsufficientBalanceError,
    InvalidPreimageError,
    RevokedStateBroadcastError,
)
from payment_communities.revocation import RevocationStore


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
    preimage: str | None = None  # Hex-encoded secret preimage when redeemed
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
    funding_txid: str | None = None
    funding_vout: int | None = None
    active_htlcs: dict[str, HTLCContract] = Field(default_factory=dict)
    sequence_number: int = 0
    revocation_store: RevocationStore = Field(default_factory=RevocationStore)

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
            raise ChannelStateError(f"Channel {self.channel_id} is not in OPEN state.")
        if self.balance_sender_sat < htlc.amount_sat:
            raise InsufficientBalanceError(
                f"Insufficient balance in channel {self.channel_id}: "
                f"Required {htlc.amount_sat} sat, available {self.balance_sender_sat} sat."
            )

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
            raise ChannelStateError(f"HTLC {htlc_id} not found in active HTLCs.")
        htlc = self.active_htlcs[htlc_id]
        if htlc.settled or htlc.refunded:
            raise ChannelStateError(f"HTLC {htlc_id} is already settled or refunded.")

        preimage_bytes = hex_to_bytes(preimage_hex)
        hash_digest = sha256(preimage_bytes)
        if bytes_to_hex(hash_digest) != htlc.payment_hash:
            raise InvalidPreimageError(
                f"Preimage SHA256 digest mismatch for HTLC {htlc_id}."
            )

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
            raise ChannelStateError(f"HTLC {htlc_id} not found in active HTLCs.")
        htlc = self.active_htlcs[htlc_id]
        if current_block_height < htlc.locktime:
            raise HTLCExpiredError(
                f"Timelock not yet expired for HTLC {htlc_id}: "
                f"Current height {current_block_height} < locktime {htlc.locktime}."
            )

        htlc.refunded = True
        self.balance_sender_sat += htlc.amount_sat
        del self.active_htlcs[htlc_id]
        self.sequence_number += 1
        return True

    def revoke_prior_state(self, commitment_number: int, secret_hex: str) -> None:
        """Registers a revealed secret, revoking the specified prior commitment state."""
        self.revocation_store.register_remote_secret(commitment_number, secret_hex)

    def verify_commitment_not_revoked(self, commitment_number: int) -> None:
        """Raises RevokedStateBroadcastError if the commitment number has been revoked."""
        if self.revocation_store.is_state_revoked(commitment_number):
            raise RevokedStateBroadcastError(
                f"Commitment state #{commitment_number} has been revoked and cannot be broadcast!"
            )

    def close_cooperatively(self) -> dict[str, int]:
        """
        Closes channel cooperatively and returns final balance breakdown.
        """
        self.state = ChannelState.SETTLED
        return {
            self.sender_alias: self.balance_sender_sat,
            self.receiver_alias: self.balance_receiver_sat,
        }
