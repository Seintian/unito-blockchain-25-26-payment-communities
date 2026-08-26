"""
Result Monad implementation for functional error handling.
Replaces exceptions with explicit Ok(value) and Err(error) types.
"""

from collections.abc import Callable
from typing import Any, Generic, TypeVar

T = TypeVar("T")
U = TypeVar("U")
E = TypeVar("E", bound=Exception)
F = TypeVar("F", bound=Exception)


class Result(Generic[T, E]):  # noqa: UP046
    """Abstract base type representing either success (Ok) or failure (Err)."""

    def is_ok(self) -> bool:
        return isinstance(self, Ok)

    def is_err(self) -> bool:
        return isinstance(self, Err)

    def unwrap(self) -> T:
        if isinstance(self, Ok):
            return self.value
        if isinstance(self, Err):
            raise self.error
        raise RuntimeError("Invalid Result state.")

    def unwrap_or(self, default: U) -> T | U:
        if isinstance(self, Ok):
            return self.value
        return default

    def map(self, fn: Callable[[T], U]) -> Result[U, E]:
        if isinstance(self, Ok):
            return Ok(fn(self.value))
        if isinstance(self, Err):
            return Err(self.error)
        raise RuntimeError("Invalid Result state.")

    def and_then(self, fn: Callable[[T], Result[U, F]]) -> Result[U, Any]:
        if isinstance(self, Ok):
            return fn(self.value)
        if isinstance(self, Err):
            return Err(self.error)
        raise RuntimeError("Invalid Result state.")


class Ok(Result[T, Any], Generic[T]):  # noqa: UP046
    """Represents successful computation holding a value."""

    def __init__(self, value: T):
        self.value = value

    def __repr__(self) -> str:
        return f"Ok({self.value!r})"


class Err(Result[Any, E], Generic[E]):  # noqa: UP046
    """Represents failed computation holding an error."""

    def __init__(self, error: E):
        self.error = error

    def __repr__(self) -> str:
        return f"Err({self.error!r})"
