"""
Backward compatibility shim for core.policies module.
"""

from payment_communities.domain.core.policies import (
    CapacityPolicy,
    RoutingPolicy,
)

__all__ = ["CapacityPolicy", "RoutingPolicy"]
