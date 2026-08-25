"""
Domain Exception Hierarchy for Payment Communities.
Provides specific, structured exceptions for protocol, contract, state, and cryptographic errors.
"""


class PaymentCommunityError(Exception):
    """Base exception for all Payment Communities errors."""



class InsufficientBalanceError(PaymentCommunityError):
    """Raised when a node or channel has insufficient funds for a transaction or HTLC."""



class HTLCExpiredError(PaymentCommunityError):
    """Raised when attempting an action on an HTLC whose locktime has expired or not yet reached."""



class InvalidPreimageError(PaymentCommunityError):
    """Raised when SHA256(preimage) does not match the payment hash."""



class ChannelStateError(PaymentCommunityError):
    """Raised when performing an invalid operation on a channel's current state."""



class RevokedStateBroadcastError(PaymentCommunityError):
    """Raised when a party attempts to broadcast a revoked prior commitment state."""



class ScriptVerificationError(PaymentCommunityError):
    """Raised when Bitcoin Script witness verification fails under Bitcoin consensus rules."""



class RouteNotFoundError(PaymentCommunityError):
    """Raised when no viable payment path exists between sender and receiver in the network graph."""

