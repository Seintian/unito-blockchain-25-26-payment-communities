"""
Backward compatibility shim for core.decorators module.
"""

from payment_communities.domain.core.decorators import (
    handle_domain_errors,
    log_execution,
    retry,
)

__all__ = ["handle_domain_errors", "log_execution", "retry"]
