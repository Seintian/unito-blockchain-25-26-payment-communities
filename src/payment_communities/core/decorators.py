"""
Software Engineering Decorators for Error Resilience, Logging & Domain Error Wrapping.
Uses Python 3.12+ type parameters [**P, R] and ParamSpec for precise type preservation.
"""

import functools
import time
from collections.abc import Callable

from payment_communities.exceptions import PaymentCommunityError


def retry[**P, R](
    max_attempts: int = 3,
    delay_seconds: float = 0.1,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator that retries a function invocation up to `max_attempts` times
    if an exception matching `exceptions` is raised.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            last_err: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_err = e
                    if attempt < max_attempts:
                        time.sleep(delay_seconds * attempt)
            if last_err:
                raise last_err
            raise RuntimeError("Unreachable retry execution path.")

        return wrapper

    return decorator


def handle_domain_errors[**P, R](
    target_exception_cls: type[PaymentCommunityError],
    error_message: str = "Domain operation failed.",
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator that catches low-level exceptions and wraps them into a structured domain exception.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            try:
                return func(*args, **kwargs)
            except target_exception_cls:
                raise
            except Exception as e:
                raise target_exception_cls(f"{error_message}: {e}") from e

        return wrapper

    return decorator


def log_execution[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    """
    Decorator that tracks execution time of protocol operations.
    """

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        _start = time.perf_counter()
        res = func(*args, **kwargs)
        _duration = time.perf_counter() - _start
        return res

    return wrapper
