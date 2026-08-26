from collections.abc import Sequence
from typing import Any

from bitcoin.core import CMutableTransaction
from bitcoin.core.script import CScript

SCRIPT_VERIFY_P2SH: int
SCRIPT_VERIFY_DERSIG: int
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: int
SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: int
SCRIPT_VERIFY_WITNESS: int
SCRIPT_VERIFY_NULLFAIL: int
SCRIPT_VERIFY_WITNESS_PUBKEYTYPE: int
SCRIPT_VERIFY_CLEANSTACK: int

class EvalScriptError(Exception): ...

def VerifyScript(
    scriptSig: CScript,
    scriptPubKey: CScript,
    txTo: CMutableTransaction,
    nIn: int,
    flags: Sequence[int] | int = ...,
    amount: int = ...,
    witness: Any = ...,
) -> None: ...
