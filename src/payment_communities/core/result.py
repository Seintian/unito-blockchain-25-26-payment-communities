"""
Backward compatibility shim for core.result module.
"""

from payment_communities.domain.core.result import Err, Ok, Result

__all__ = ["Err", "Ok", "Result"]
