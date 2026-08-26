from collections.abc import Sequence
from typing import Any

from bitcoin.core.script import CScriptWitness

def Hash(data: bytes) -> bytes: ...
def Hash160(data: bytes) -> bytes: ...
def b2x(b: bytes) -> str: ...
def x(hex_str: str) -> bytes: ...

class CTxInWitness:
    scriptWitness: CScriptWitness
    def __init__(self, scriptWitness: CScriptWitness = ...) -> None: ...

class CTxWitness:
    vtxinwit: tuple[CTxInWitness, ...]
    def __init__(self, vtxinwit: Sequence[CTxInWitness] = ...) -> None: ...

class COutPoint:
    hash: bytes
    n: int
    def __init__(self, hash: bytes = ..., n: int = ...) -> None: ...

class CMutableTxIn:
    prevout: COutPoint
    scriptSig: Any
    nSequence: int
    def __init__(
        self, prevout: COutPoint = ..., scriptSig: Any = ..., nSequence: int = ...
    ) -> None: ...

class CMutableTxOut:
    nValue: int
    scriptPubKey: Any
    def __init__(self, nValue: int = ..., scriptPubKey: Any = ...) -> None: ...

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
