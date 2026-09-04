from collections.abc import Sequence
from typing import Any

from bitcoin.core.script import CScript, CScriptWitness

def Hash(data: bytes) -> bytes: ...
def Hash160(data: bytes) -> bytes: ...
def b2x(b: bytes) -> str: ...
def x(hex_str: str) -> bytes: ...
def b2lx(b: bytes) -> str: ...
def lx(hex_str: str) -> bytes: ...


class CTxInWitness:
    scriptWitness: CScriptWitness
    def __init__(self, scriptWitness: CScriptWitness = ...) -> None: ...

class CTxWitness:
    vtxinwit: list[CTxInWitness]
    def __init__(self, vtxinwit: Sequence[CTxInWitness] = ...) -> None: ...

class COutPoint:
    hash: bytes
    n: int
    def __init__(self, hash: bytes = ..., n: int = ...) -> None: ...

class CMutableTxIn:
    prevout: COutPoint
    scriptSig: CScript
    nSequence: int
    def __init__(
        self, prevout: COutPoint = ..., scriptSig: CScript = ..., nSequence: int = ...
    ) -> None: ...

class CMutableTxOut:
    nValue: int
    scriptPubKey: CScript
    def __init__(self, nValue: int = ..., scriptPubKey: CScript = ...) -> None: ...

class CMutableTransaction:
    vin: list[CMutableTxIn]
    vout: list[CMutableTxOut]
    wit: CTxWitness
    nLockTime: int
    nVersion: int
    def __init__(
        self,
        vin: Sequence[CMutableTxIn] = ...,
        vout: Sequence[CMutableTxOut] = ...,
        nLockTime: int = ...,
        nVersion: int = ...,
    ) -> None: ...
    def GetTxid(self) -> bytes: ...
    def serialize(self) -> bytes: ...
    def stream_serialize(self, f: Any) -> None: ...
    @classmethod
    def deserialize(cls, b: bytes) -> CMutableTransaction: ...
    @classmethod
    def stream_deserialize(cls, f: Any) -> CMutableTransaction: ...

class CTransaction:
    vin: list[Any]
    vout: list[Any]
    nLockTime: int
    nVersion: int
    def __init__(
        self,
        vin: Sequence[Any] = ...,
        vout: Sequence[Any] = ...,
        nLockTime: int = ...,
        nVersion: int = ...,
    ) -> None: ...
    def GetTxid(self) -> bytes: ...
    def GetHash(self) -> bytes: ...
    def serialize(self) -> bytes: ...

