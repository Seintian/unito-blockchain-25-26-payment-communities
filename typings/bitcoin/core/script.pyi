from collections.abc import Sequence
from typing import Any

OP_0: int
OP_2: int
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
OP_SHA256: int

class CScript(bytes):
    def __init__(self, value: Any = ...) -> None: ...

class CScriptWitness:
    stack: list[bytes]
    def __init__(self, stack: Sequence[bytes] = ...) -> None: ...
