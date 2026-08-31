"""
Payment Channel State Machine & HTLC Management module.
Manages off-chain balances, commitment sequence numbers, HTLC contracts,
Poon-Dryja revocation state tracking, and state transitions using domain specifications.
"""

from enum import StrEnum

from pydantic import BaseModel, Field

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.utils import hex_to_bytes
from payment_communities.domain.core.predicates import (
    HasSufficientBalance,
    IsChannelOpen,
    IsHTLCActive,
    IsPreimageValid,
    IsTimelockExpired,
)
from payment_communities.exceptions import (
    ChannelStateError,
    HTLCExpiredError,
    InsufficientBalanceError,
    InvalidPreimageError,
    RevokedStateBroadcastError,
)
from payment_communities.protocols.revocation import RevocationStore


class ChannelState(StrEnum):
    CLOSED = "CLOSED"
    FUNDING = "FUNDING"
    OPEN = "OPEN"
    DISPUTE = "DISPUTE"
    SETTLED = "SETTLED"


class HTLCState(StrEnum):
    OFFERED = "OFFERED"
    ACCEPTED = "ACCEPTED"
    SETTLED = "SETTLED"
    REFUNDED = "REFUNDED"
    EXPIRED = "EXPIRED"


class HTLCContract(BaseModel):
    htlc_id: str
    payment_hash: str  # Hex-encoded SHA256 digest
    amount_sat: int
    locktime: int
    offerer_alias: str | None = None  # Alias of node that offered this HTLC
    preimage: str | None = None  # Hex-encoded secret preimage when redeemed
    settled: bool = False
    refunded: bool = False
    state: HTLCState = HTLCState.OFFERED

    def is_active(self) -> bool:
        """Returns True if the HTLC is active (neither settled nor refunded)."""
        return IsHTLCActive().is_satisfied_by(self)

    def is_expired_at(self, block_height: int) -> bool:
        """Returns True if current block height has reached or passed the HTLC locktime."""
        return IsTimelockExpired(block_height).is_satisfied_by(self)

    def is_preimage_valid(self, preimage_hex: str) -> bool:
        """Returns True if SHA256(preimage_hex) matches payment_hash."""
        return IsPreimageValid(preimage_hex).is_satisfied_by(self)


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
        return ScriptFactory.create_multisig_2of2(pk1, pk2)

    def is_open(self) -> bool:
        """Domain predicate checking if channel is open."""
        return IsChannelOpen().is_satisfied_by(self)

    def has_sufficient_sender_balance_for(self, amount_sat: int) -> bool:
        """Domain predicate checking if sender has sufficient balance."""
        return HasSufficientBalance(amount_sat).is_satisfied_by(self)

    def get_balance(self, node_alias: str) -> int:
        """Returns the current available balance for the specified node in this channel."""
        if node_alias == self.sender_alias:
            return self.balance_sender_sat
        if node_alias == self.receiver_alias:
            return self.balance_receiver_sat
        return 0

    def add_htlc(self, htlc: HTLCContract, offerer_alias: str | None = None) -> bool:
        """
        Offers an HTLC on the channel deducting from offerer's balance (bidirectional support).
        """
        if not self.is_open():
            raise ChannelStateError(f"Channel {self.channel_id} is not in OPEN state.")

        offerer = offerer_alias or htlc.offerer_alias or self.sender_alias
        htlc.offerer_alias = offerer

        if offerer == self.sender_alias:
            if not self.has_sufficient_sender_balance_for(htlc.amount_sat):
                raise InsufficientBalanceError(
                    f"Insufficient balance in channel {self.channel_id} for sender {self.sender_alias}: "
                    f"Required {htlc.amount_sat} sat, available {self.balance_sender_sat} sat."
                )
            self.balance_sender_sat -= htlc.amount_sat
        elif offerer == self.receiver_alias:
            if self.balance_receiver_sat < htlc.amount_sat:
                raise InsufficientBalanceError(
                    f"Insufficient balance in channel {self.channel_id} for receiver {self.receiver_alias}: "
                    f"Required {htlc.amount_sat} sat, available {self.balance_receiver_sat} sat."
                )
            self.balance_receiver_sat -= htlc.amount_sat
        else:
            raise ChannelStateError(
                f"Offerer '{offerer}' is neither sender nor receiver of channel {self.channel_id}."
            )

        self.active_htlcs[htlc.htlc_id] = htlc
        self.sequence_number += 1
        return True

    def redeem_htlc(self, htlc_id: str, preimage_hex: str) -> bool:
        """
        Redeems an HTLC using the secret preimage, crediting the recipient counterparty.
        """
        if htlc_id not in self.active_htlcs:
            raise ChannelStateError(f"HTLC {htlc_id} not found in active HTLCs.")
        htlc = self.active_htlcs[htlc_id]
        if not htlc.is_active():
            raise ChannelStateError(f"HTLC {htlc_id} is already settled or refunded.")

        if not htlc.is_preimage_valid(preimage_hex):
            raise InvalidPreimageError(
                f"Preimage SHA256 digest mismatch for HTLC {htlc_id}."
            )

        htlc.preimage = preimage_hex
        htlc.settled = True
        htlc.state = HTLCState.SETTLED

        # Credit the counterparty of the offerer
        offerer = htlc.offerer_alias or self.sender_alias
        if offerer == self.sender_alias:
            self.balance_receiver_sat += htlc.amount_sat
        else:
            self.balance_sender_sat += htlc.amount_sat

        del self.active_htlcs[htlc_id]
        self.sequence_number += 1
        return True

    def refund_htlc(self, htlc_id: str, current_block_height: int) -> bool:
        """
        Reclaims HTLC amount back to the original offerer after timelock expiry.
        """
        if htlc_id not in self.active_htlcs:
            raise ChannelStateError(f"HTLC {htlc_id} not found in active HTLCs.")
        htlc = self.active_htlcs[htlc_id]
        if not htlc.is_expired_at(current_block_height):
            raise HTLCExpiredError(
                f"Timelock not yet expired for HTLC {htlc_id}: "
                f"Current height {current_block_height} < locktime {htlc.locktime}."
            )

        htlc.refunded = True
        htlc.state = HTLCState.REFUNDED

        # Restore funds to original offerer
        offerer = htlc.offerer_alias or self.sender_alias
        if offerer == self.sender_alias:
            self.balance_sender_sat += htlc.amount_sat
        else:
            self.balance_receiver_sat += htlc.amount_sat

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
