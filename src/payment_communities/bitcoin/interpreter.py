"""
Centralized Bitcoin SegWit Consensus Script Interpretation & Verification Engine.
Implements the Specification and Interpreter Patterns for BIP 141 (SegWit) and BIP 143
(Transaction Signature Verification for Version 0 Witness Program).
"""

from abc import ABC, abstractmethod
from typing import Any

import bitcoin.core.key
from bitcoin.core import CMutableTransaction
from bitcoin.core.script import (
    OP_0,
    OP_1,
    OP_2DROP,
    OP_16,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_HASH256,
    OP_IF,
    OP_IFDUP,
    OP_NOTIF,
    OP_RIPEMD160,
    OP_SHA256,
    SIGVERSION_WITNESS_V0,
    CScript,
    CScriptOp,
    SignatureHash,
)

from payment_communities.bitcoin.contracts import ScriptFactory
from payment_communities.bitcoin.utils import hash160, hash256, ripemd160, sha256
from payment_communities.exceptions import ScriptVerificationError


def cast_to_bool(val: bytes | int | bool) -> bool:
    """
    Evaluates a stack element as a Bitcoin consensus boolean.
    Empty byte strings and negative zero (0x80) evaluate to False.
    """
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, bytes):
        if not val:
            return False
        for b in val[:-1]:
            if b != 0:
                return True
        return val[-1] not in (0, 0x80)
    return bool(val)


class ScriptInterpreter:
    """
    Stack machine interpreter executing BIP 143 SegWit V0 witness scripts.
    Implements the Interpreter Pattern for Bitcoin Assembly opcodes.
    """

    def __init__(
        self,
        witness_script: CScript,
        tx: CMutableTransaction,
        input_index: int,
        amount_sat: int,
        initial_stack: list[bytes] | None = None,
    ) -> None:
        self.witness_script = witness_script
        self.tx = tx
        self.input_index = input_index
        self.amount_sat = amount_sat
        self.eval_stack: list[bytes] = list(initial_stack or [])
        self.exec_stack: list[bool] = []
        self.ops = list(witness_script)
        self.pc = 0

    def is_executing(self) -> bool:
        """Returns True if the current execution branch is active (all parent IF branches are True)."""
        return all(self.exec_stack)

    def execute(self) -> bool:
        """
        Executes the parsed opcode sequence.
        Raises ScriptVerificationError upon any constraint or validation failure.
        Returns True if execution completes with a truthy top-of-stack.
        """
        while self.pc < len(self.ops):
            op = self.ops[self.pc]
            self.pc += 1

            if self._handle_control_flow(op):
                continue

            if not self.is_executing():
                continue

            self._dispatch_opcode(op)

        if len(self.exec_stack) > 0:
            raise ScriptVerificationError("Unbalanced OP_IF / OP_ENDIF control block")

        if len(self.eval_stack) == 0 or not cast_to_bool(self.eval_stack[-1]):
            raise ScriptVerificationError(
                f"Script evaluation ended with non-truthy top of stack: {self.eval_stack}"
            )

        return True

    def _handle_control_flow(self, op: Any) -> bool:
        """Handles conditional branching opcodes (OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF)."""
        if not isinstance(op, CScriptOp):
            return False

        if op in (OP_IF, OP_NOTIF):
            if not self.is_executing():
                self.exec_stack.append(False)
            else:
                if len(self.eval_stack) < 1:
                    raise ScriptVerificationError("OP_IF/OP_NOTIF on empty stack")
                condition = cast_to_bool(self.eval_stack.pop())
                if op == OP_NOTIF:
                    condition = not condition
                self.exec_stack.append(condition)
            return True

        if op == OP_ELSE:
            if len(self.exec_stack) == 0:
                raise ScriptVerificationError("OP_ELSE encountered without prior OP_IF")
            self.exec_stack[-1] = not self.exec_stack[-1]
            return True

        if op == OP_ENDIF:
            if len(self.exec_stack) == 0:
                raise ScriptVerificationError(
                    "OP_ENDIF encountered without prior OP_IF"
                )
            self.exec_stack.pop()
            return True

        return False

    def _dispatch_opcode(self, op: Any) -> None:
        """Executes push, arithmetic, hash, timelock, or cryptographic verification opcodes."""
        if isinstance(op, bytes):
            self.eval_stack.append(op)
            return

        if isinstance(op, CScriptOp):
            if op == OP_0:
                self.eval_stack.append(b"")
            elif OP_1 <= op <= OP_16:
                self.eval_stack.append(bytes([op - 80]))
            elif op == OP_DROP:
                self._op_drop()
            elif op == OP_2DROP:
                self._op_2drop()
            elif op == OP_DUP:
                self._op_dup()
            elif op == OP_IFDUP:
                self._op_ifdup()
            elif op in (OP_EQUAL, OP_EQUALVERIFY):
                self._op_equal(verify=op == OP_EQUALVERIFY)
            elif op == OP_SHA256:
                self._op_hash(sha256)
            elif op == OP_HASH160:
                self._op_hash(hash160)
            elif op == OP_HASH256:
                self._op_hash(hash256)
            elif op == OP_RIPEMD160:
                self._op_hash(ripemd160)
            elif op == OP_CHECKLOCKTIMEVERIFY:
                self._op_cltv()
            elif op == OP_CHECKSEQUENCEVERIFY:
                self._op_csv()
            elif op in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                self._op_checksig(verify=op == OP_CHECKSIGVERIFY)
            elif op in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                self._op_checkmultisig(verify=op == OP_CHECKMULTISIGVERIFY)
            return

        if isinstance(op, int):
            self.eval_stack.append(
                op.to_bytes(4, "little", signed=True) if op != 0 else b""
            )

    def _op_drop(self) -> None:
        if len(self.eval_stack) < 1:
            raise ScriptVerificationError("OP_DROP on empty stack")
        self.eval_stack.pop()

    def _op_2drop(self) -> None:
        if len(self.eval_stack) < 2:
            raise ScriptVerificationError("OP_2DROP requires at least 2 items")
        self.eval_stack.pop()
        self.eval_stack.pop()

    def _op_dup(self) -> None:
        if len(self.eval_stack) < 1:
            raise ScriptVerificationError("OP_DUP on empty stack")
        self.eval_stack.append(self.eval_stack[-1])

    def _op_ifdup(self) -> None:
        if len(self.eval_stack) < 1:
            raise ScriptVerificationError("OP_IFDUP on empty stack")
        if cast_to_bool(self.eval_stack[-1]):
            self.eval_stack.append(self.eval_stack[-1])

    def _op_equal(self, verify: bool) -> None:
        if len(self.eval_stack) < 2:
            raise ScriptVerificationError("OP_EQUAL requires at least 2 items")
        a = self.eval_stack.pop()
        b = self.eval_stack.pop()
        matched = a == b
        if verify:
            if not matched:
                raise ScriptVerificationError("OP_EQUALVERIFY constraint failed")
        else:
            self.eval_stack.append(b"\x01" if matched else b"")

    def _op_hash(self, hash_func: Any) -> None:
        if len(self.eval_stack) < 1:
            raise ScriptVerificationError("Hash operation on empty stack")
        val = self.eval_stack.pop()
        self.eval_stack.append(hash_func(val))

    def _op_cltv(self) -> None:
        if len(self.eval_stack) < 1:
            raise ScriptVerificationError("OP_CHECKLOCKTIMEVERIFY on empty stack")
        n_lock = int.from_bytes(self.eval_stack[-1], "little", signed=True)
        if self.tx.vin[self.input_index].nSequence == 0xFFFFFFFF:
            raise ScriptVerificationError("CLTV requires input nSequence < 0xffffffff")
        if self.tx.nLockTime < n_lock:
            raise ScriptVerificationError(
                f"CLTV locktime requirement failed: {self.tx.nLockTime} < {n_lock}"
            )

    def _op_csv(self) -> None:
        if len(self.eval_stack) < 1:
            raise ScriptVerificationError("OP_CHECKSEQUENCEVERIFY on empty stack")
        n_seq = int.from_bytes(self.eval_stack[-1], "little", signed=True)
        in_seq = self.tx.vin[self.input_index].nSequence
        if in_seq == 0xFFFFFFFF or (in_seq & (1 << 31)) != 0:
            raise ScriptVerificationError("CSV requires sequence relative lock enabled")
        if (in_seq & 0x0000FFFF) < n_seq:
            raise ScriptVerificationError(
                f"CSV relative lock requirement failed: {in_seq & 0x0000FFFF} < {n_seq}"
            )

    def _op_checksig(self, verify: bool) -> None:
        if len(self.eval_stack) < 2:
            raise ScriptVerificationError("OP_CHECKSIG requires at least 2 items")
        pubkey = self.eval_stack.pop()
        sig = self.eval_stack.pop()

        if not sig:
            valid = False
        else:
            hashtype = sig[-1]
            sighash = SignatureHash(
                self.witness_script,
                self.tx,
                self.input_index,
                hashtype,
                amount=self.amount_sat,
                sigversion=SIGVERSION_WITNESS_V0,
            )
            key = bitcoin.core.key.CECKey()
            key.set_pubkey(pubkey)
            valid = key.verify(sighash, sig[:-1])

        if verify:
            if not valid:
                raise ScriptVerificationError("OP_CHECKSIGVERIFY failed")
        else:
            self.eval_stack.append(b"\x01" if valid else b"")

    def _op_checkmultisig(self, verify: bool) -> None:
        if len(self.eval_stack) < 1:
            raise ScriptVerificationError("OP_CHECKMULTISIG on empty stack")
        n_keys_raw = self.eval_stack.pop()
        n_keys = int.from_bytes(n_keys_raw, "little", signed=True) if n_keys_raw else 0
        keys = [self.eval_stack.pop() for _ in range(n_keys)]

        n_sigs_raw = self.eval_stack.pop()
        n_sigs = int.from_bytes(n_sigs_raw, "little", signed=True) if n_sigs_raw else 0
        sigs = [self.eval_stack.pop() for _ in range(n_sigs)]

        # Pop dummy element (BIP 147 / off-by-one checkmultisig dummy)
        if len(self.eval_stack) > 0:
            self.eval_stack.pop()

        sig_idx = 0
        key_idx = 0
        success = True

        while sig_idx < len(sigs):
            if key_idx >= len(keys):
                success = False
                break
            sig = sigs[sig_idx]
            pubkey = keys[key_idx]
            hashtype = sig[-1]
            sighash = SignatureHash(
                self.witness_script,
                self.tx,
                self.input_index,
                hashtype,
                amount=self.amount_sat,
                sigversion=SIGVERSION_WITNESS_V0,
            )
            key = bitcoin.core.key.CECKey()
            key.set_pubkey(pubkey)
            if key.verify(sighash, sig[:-1]):
                sig_idx += 1
            key_idx += 1

        valid_ms = success and (sig_idx == len(sigs))
        if verify:
            if not valid_ms:
                raise ScriptVerificationError("OP_CHECKMULTISIGVERIFY failed")
        else:
            self.eval_stack.append(b"\x01" if valid_ms else b"")


class WitnessProgram(ABC):
    """
    Abstract Base Class for SegWit Witness Programs (BIP 141).
    Encapsulates program classification, parsing, and execution using the Specification Pattern.
    """

    def __init__(self, version: int, program: bytes) -> None:
        self.version = version
        self.program = program

    @abstractmethod
    def verify(
        self,
        tx: CMutableTransaction,
        input_index: int,
        witness_stack: list[bytes],
        amount_sat: int,
    ) -> bool:
        """Verifies the witness stack against the witness program."""

    @classmethod
    def from_script_pub_key(cls, script_pub_key: CScript) -> WitnessProgram:
        """
        Parses and classifies a scriptPubKey into its typed SegWit WitnessProgram.
        Raises ScriptVerificationError if the scriptPubKey is not a supported SegWit pattern.
        """
        raw_ops = list(script_pub_key)
        if len(raw_ops) != 2:
            raise ScriptVerificationError(
                f"Unsupported scriptPubKey pattern: {script_pub_key}"
            )

        version_op, program_bytes = raw_ops[0], raw_ops[1]
        if not isinstance(program_bytes, (bytes, bytearray)):
            raise ScriptVerificationError(
                f"Invalid witness program payload in scriptPubKey: {program_bytes}"
            )

        # Version 0 check
        if version_op == 0 or version_op == OP_0:
            if len(program_bytes) == 20:
                return WitnessV0KeyHashProgram(version=0, program=bytes(program_bytes))
            if len(program_bytes) == 32:
                return WitnessV0ScriptHashProgram(
                    version=0, program=bytes(program_bytes)
                )

        raise ScriptVerificationError(
            f"Unsupported witness program version {version_op} with length {len(program_bytes)}"
        )


class WitnessV0KeyHashProgram(WitnessProgram):
    """
    BIP 141 / BIP 143 P2WPKH Witness Program:
    scriptPubKey: OP_0 <20-byte key hash>
    Witness Stack: <signature> <pubkey>
    """

    def verify(
        self,
        tx: CMutableTransaction,
        input_index: int,
        witness_stack: list[bytes],
        amount_sat: int,
    ) -> bool:
        if len(witness_stack) != 2:
            raise ScriptVerificationError(
                f"P2WPKH witness stack must have exactly 2 elements (sig, pubkey), got {len(witness_stack)}"
            )

        sig, pubkey = witness_stack[0], witness_stack[1]
        if hash160(pubkey) != self.program:
            raise ScriptVerificationError(
                "P2WPKH public key hash160 mismatch with scriptPubKey program"
            )

        script_code = ScriptFactory.create_p2wpkh_scriptCode(pubkey)
        hashtype = sig[-1] if len(sig) > 0 else 1
        sighash = SignatureHash(
            script_code,
            tx,
            input_index,
            hashtype,
            amount=amount_sat,
            sigversion=SIGVERSION_WITNESS_V0,
        )

        key = bitcoin.core.key.CECKey()
        key.set_pubkey(pubkey)
        if not key.verify(sighash, sig[:-1]):
            raise ScriptVerificationError("P2WPKH ECDSA signature verification failed")

        return True


class WitnessV0ScriptHashProgram(WitnessProgram):
    """
    BIP 141 / BIP 143 P2WSH Witness Program:
    scriptPubKey: OP_0 <32-byte script hash>
    Witness Stack: <stack_items...> <witnessScript>
    """

    def verify(
        self,
        tx: CMutableTransaction,
        input_index: int,
        witness_stack: list[bytes],
        amount_sat: int,
    ) -> bool:
        if len(witness_stack) < 1:
            raise ScriptVerificationError("P2WSH witness stack cannot be empty")

        witness_script_bytes = witness_stack[-1]
        if sha256(witness_script_bytes) != self.program:
            raise ScriptVerificationError(
                "P2WSH witnessScript SHA256 mismatch with scriptPubKey program"
            )

        witness_script = CScript(witness_script_bytes)
        interpreter = ScriptInterpreter(
            witness_script=witness_script,
            tx=tx,
            input_index=input_index,
            amount_sat=amount_sat,
            initial_stack=witness_stack[:-1],
        )
        return interpreter.execute()
