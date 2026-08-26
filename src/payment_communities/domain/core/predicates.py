"""
Specification Pattern & English-ish Domain Predicates Engine.
Allows composing complex business domain rules using fluent boolean operators (&, |, ~).
"""

from abc import ABC, abstractmethod
from typing import Any


class Specification[T](ABC):
    """
    Abstract Specification Base Class for domain validation predicates.
    Supports fluent composition via &, |, and ~ operators.
    """

    @abstractmethod
    def is_satisfied_by(self, candidate: T) -> bool:
        """Evaluates whether the candidate satisfies the specification rule."""

    def __call__(self, candidate: T) -> bool:
        return self.is_satisfied_by(candidate)

    def __and__(self, other: Specification[T]) -> Specification[T]:
        return AndSpecification(self, other)

    def __or__(self, other: Specification[T]) -> Specification[T]:
        return OrSpecification(self, other)

    def __invert__(self) -> Specification[T]:
        return NotSpecification(self)


class AndSpecification[T](Specification[T]):
    """Logical AND composition of two specifications."""

    def __init__(self, left: Specification[T], right: Specification[T]):
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: T) -> bool:
        return self.left.is_satisfied_by(candidate) and self.right.is_satisfied_by(
            candidate
        )


class OrSpecification[T](Specification[T]):
    """Logical OR composition of two specifications."""

    def __init__(self, left: Specification[T], right: Specification[T]):
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: T) -> bool:
        return self.left.is_satisfied_by(candidate) or self.right.is_satisfied_by(
            candidate
        )


class NotSpecification[T](Specification[T]):
    """Logical NOT negation of a specification."""

    def __init__(self, spec: Specification[T]):
        self.spec = spec

    def is_satisfied_by(self, candidate: T) -> bool:
        return not self.spec.is_satisfied_by(candidate)


# ==============================================================================
# CONCRETE DOMAIN SPECIFICATIONS
# ==============================================================================


class IsChannelOpen(Specification[Any]):
    """Predicate evaluating whether a payment channel is in OPEN state."""

    def is_satisfied_by(self, candidate: Any) -> bool:
        from payment_communities.domain.channel import ChannelState

        return getattr(candidate, "state", None) == ChannelState.OPEN


class HasSufficientBalance(Specification[Any]):
    """Predicate evaluating whether a channel sender has sufficient capacity for an amount."""

    def __init__(self, required_amount_sat: int):
        self.required_amount_sat = required_amount_sat

    def is_satisfied_by(self, candidate: Any) -> bool:
        return getattr(candidate, "balance_sender_sat", 0) >= self.required_amount_sat


class IsHTLCActive(Specification[Any]):
    """Predicate evaluating whether an HTLC contract is neither settled nor refunded."""

    def is_satisfied_by(self, candidate: Any) -> bool:
        settled = getattr(candidate, "settled", False)
        refunded = getattr(candidate, "refunded", False)
        return not settled and not refunded


class IsTimelockExpired(Specification[Any]):
    """Predicate evaluating whether the current block height has reached or passed an HTLC locktime."""

    def __init__(self, current_block_height: int):
        self.current_block_height = current_block_height

    def is_satisfied_by(self, candidate: Any) -> bool:
        locktime = getattr(candidate, "locktime", 0)
        return self.current_block_height >= locktime


class IsPreimageValid(Specification[Any]):
    """Predicate evaluating whether SHA256(preimage) matches an HTLC payment hash."""

    def __init__(self, preimage_hex: str):
        self.preimage_hex = preimage_hex

    def is_satisfied_by(self, candidate: Any) -> bool:
        from payment_communities.bitcoin.utils import (
            bytes_to_hex,
            hex_to_bytes,
            sha256,
        )

        try:
            digest = sha256(hex_to_bytes(self.preimage_hex))
            return bytes_to_hex(digest) == getattr(candidate, "payment_hash", "")
        except Exception:  # noqa: BLE001
            return False
