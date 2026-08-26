"""
Result Monad Implementation for Functional Error Handling.
Provides Ok[T] and Err[E] immutable generic result wrappers with covariant types.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Never


class Result[T_co, E_co: BaseException]:
    """
    Abstract base class for functional Result[T_co, E_co] types.
    Represents either a success value Ok(T) or a failure Err(E).
    """

    def is_ok(self) -> bool:
        raise NotImplementedError

    def is_err(self) -> bool:
        raise NotImplementedError

    def unwrap(self) -> T_co:
        raise NotImplementedError

    def unwrap_or(self, default: Any) -> Any:
        raise NotImplementedError

    def map[U](self, fn: Callable[[T_co], U]) -> Result[U, E_co]:
        raise NotImplementedError

    def and_then[U, F: BaseException](
        self, fn: Callable[[T_co], Result[U, F]]
    ) -> Result[U, E_co | F]:
        raise NotImplementedError


@dataclass(frozen=True)
class Ok[T_co](Result[T_co, Never]):
    """Represents a successful operation containing value of type T_co."""

    value: T_co
    __match_args__ = ("value",)

    def is_ok(self) -> bool:
        return True

    def is_err(self) -> bool:
        return False

    def unwrap(self) -> T_co:
        return self.value

    def unwrap_or(self, default: Any) -> Any:
        return self.value

    def map[U](self, fn: Callable[[T_co], U]) -> Ok[U]:
        return Ok(fn(self.value))

    def and_then[U, F: BaseException](
        self, fn: Callable[[T_co], Result[U, F]]
    ) -> Result[U, F]:
        return fn(self.value)


@dataclass(frozen=True)
class Err[E_co: BaseException](Result[Never, E_co]):
    """Represents a failed operation containing an error of type E_co."""

    error: E_co
    __match_args__ = ("error",)

    def is_ok(self) -> bool:
        return False

    def is_err(self) -> bool:
        return True

    def unwrap(self) -> Never:
        raise self.error

    def unwrap_or(self, default: Any) -> Any:
        return default

    def map[U](self, fn: Callable[[Never], U]) -> Err[E_co]:
        return Err(self.error)

    def and_then[U, F: BaseException](
        self, fn: Callable[[Never], Result[U, F]]
    ) -> Err[E_co]:
        return Err(self.error)
