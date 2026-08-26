"""
Decorator engine providing resilient execution, retries, logging, and domain exception wrappers.
"""

import functools
import logging
import time
from collections.abc import Callable
from typing import Any

from payment_communities.exceptions import PaymentCommunityError

logger = logging.getLogger("payment_communities")


def retry(
    max_attempts: int = 3,
    delay_seconds: float = 0.5,
    backoff_factor: float = 2.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable:
    """
    Decorator executing wrapped function with exponential backoff retry resilience.
    """

    def decorator[T](func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            current_delay = delay_seconds
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt == max_attempts:
                        logger.error(
                            f"Function '{func.__name__}' failed after {max_attempts} attempts: {e}"
                        )
                        raise
                    logger.warning(
                        f"Attempt {attempt}/{max_attempts} for '{func.__name__}' failed: {e}. "
                        f"Retrying in {current_delay:.2f}s..."
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff_factor
            return func(*args, **kwargs)

        return wrapper

    return decorator


def handle_domain_errors(
    func_or_exception: Callable | type[Exception] | None = None,
    message_prefix: str | None = None,
) -> Callable:
    """
    Decorator translating unhandled execution failures into PaymentCommunityError or target_exception.
    Supports usage as `@handle_domain_errors` or `@handle_domain_errors(TargetException, "Operation failed")`.
    """
    if isinstance(func_or_exception, type) and issubclass(func_or_exception, Exception):
        target_exc = func_or_exception
        prefix = message_prefix or "Domain execution error"

        def decorator[T](func: Callable[..., T]) -> Callable[..., T]:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> T:
                try:
                    return func(*args, **kwargs)
                except target_exc:
                    raise
                except Exception as e:
                    raise target_exc(f"{prefix}: {e}") from e

            return wrapper

        return decorator

    if callable(func_or_exception):
        func = func_or_exception

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except PaymentCommunityError:
                raise
            except Exception as e:
                raise PaymentCommunityError(
                    f"Domain execution error in '{func.__name__}': {e}"
                ) from e

        return wrapper

    def default_decorator[T](func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return func(*args, **kwargs)
            except PaymentCommunityError:
                raise
            except Exception as e:
                raise PaymentCommunityError(
                    f"Domain execution error in '{func.__name__}': {e}"
                ) from e

        return wrapper

    return default_decorator


def log_execution[T](func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator logging execution start, completion, and parameters of critical domain methods.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        logger.debug(f"Entering '{func.__name__}' with args={args}, kwargs={kwargs}")
        start_time = time.perf_counter()
        res = func(*args, **kwargs)
        elapsed = time.perf_counter() - start_time
        logger.debug(f"Exited '{func.__name__}' in {elapsed:.4f}s")
        return res

    return wrapper
