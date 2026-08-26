"""
Core domain utilities and design pattern implementations.
"""

from payment_communities.domain.core.decorators import (
    handle_domain_errors,
    log_execution,
    retry,
)
from payment_communities.domain.core.policies import (
    FeePolicy,
    LeaseFeePolicy,
    RevocationPolicy,
    RoutingFeePolicy,
    TimelockPolicy,
)
from payment_communities.domain.core.predicates import (
    AndSpecification,
    HasSufficientBalance,
    IsChannelOpen,
    IsHTLCActive,
    IsPreimageValid,
    IsTimelockExpired,
    NotSpecification,
    OrSpecification,
    Specification,
)
from payment_communities.domain.core.result import Err, Ok, Result

__all__ = [
    "AndSpecification",
    "Err",
    "FeePolicy",
    "HasSufficientBalance",
    "IsChannelOpen",
    "IsHTLCActive",
    "IsPreimageValid",
    "IsTimelockExpired",
    "LeaseFeePolicy",
    "NotSpecification",
    "Ok",
    "OrSpecification",
    "Result",
    "RevocationPolicy",
    "RoutingFeePolicy",
    "Specification",
    "TimelockPolicy",
    "handle_domain_errors",
    "log_execution",
    "retry",
]
