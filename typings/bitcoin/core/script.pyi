from collections.abc import Iterable, Sequence
from typing import Any, Self

OP_0: int

OP_1: int
OP_2: int
OP_16: int
OP_CHECKMULTISIG: int
OP_CHECKSIG: int
OP_CLTV: int
OP_CHECKLOCKTIMEVERIFY: int
OP_CHECKSEQUENCEVERIFY: int
OP_DROP: int
OP_DUP: int
OP_ELSE: int
OP_ENDIF: int
OP_EQUALVERIFY: int
OP_HASH160: int
OP_IF: int
OP_IFDUP: int
OP_NOTIF: int
OP_SHA256: int

SIGHASH_ALL: int
SIGHASH_NONE: int
SIGHASH_SINGLE: int
SIGHASH_ANYONECANPAY: int

class CScript(bytes):
    def __new__(cls, value: Iterable[bytes | int] | bytes = ...) -> Self: ...
    def __init__(self, value: Iterable[bytes | int] | bytes = ...) -> None: ...

class CScriptWitness:
    stack: list[bytes]
    def __init__(self, stack: Sequence[bytes] = ...) -> None: ...

def SignatureHash(
    script: CScript,
    txTo: Any,
    inIdx: int,
    hashtype: int,
    amount: int = ...,
) -> bytes: ...
