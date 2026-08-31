"""
Unit tests for Core Design Patterns, Functional Primitives, Specifications, Policies & Decorators.
"""

import pytest

from payment_communities.domain.core import (
    Err,
    FeePolicy,
    HasSufficientBalance,
    IsChannelOpen,
    IsHTLCActive,
    IsTimelockExpired,
    LeaseFeePolicy,
    Ok,
    Result,
    RoutingFeePolicy,
    handle_domain_errors,
    retry,
)
from payment_communities.exceptions import ChannelStateError


def test_result_monad_ok():
    res: Result[int, ValueError] = Ok(42)
    assert res.is_ok() is True
    assert res.is_err() is False
    assert res.unwrap() == 42
    assert res.unwrap_or(0) == 42
    assert res.map(lambda x: x * 2).unwrap() == 84
    assert res.and_then(lambda x: Ok(str(x))).unwrap() == "42"


def test_result_monad_err():
    err_inst = ValueError("boom")
    res: Result[int, ValueError] = Err(err_inst)
    assert res.is_ok() is False
    assert res.is_err() is True
    assert res.unwrap_or(100) == 100
    with pytest.raises(ValueError, match="boom"):
        res.unwrap()


def test_specification_pattern_composition():
    class MockChannel:
        def __init__(self, state_str, sender_sat):
            from payment_communities.domain.channel import ChannelState

            self.state = ChannelState(state_str)
            self.balance_sender_sat = sender_sat

    chan_open = MockChannel("OPEN", 50_000)
    chan_closed = MockChannel("CLOSED", 50_000)
    chan_broke = MockChannel("OPEN", 1_000)

    spec = IsChannelOpen() & HasSufficientBalance(10_000)

    assert spec.is_satisfied_by(chan_open) is True
    assert spec.is_satisfied_by(chan_closed) is False
    assert spec.is_satisfied_by(chan_broke) is False

    or_spec = IsChannelOpen() | HasSufficientBalance(100_000)
    assert or_spec.is_satisfied_by(chan_closed) is False

    not_spec = ~IsChannelOpen()
    assert not_spec.is_satisfied_by(chan_closed) is True
    assert not_spec.is_satisfied_by(chan_open) is False


def test_htlc_predicates():
    class MockHTLC:
        def __init__(self, settled, refunded, locktime, payment_hash):
            self.settled = settled
            self.refunded = refunded
            self.locktime = locktime
            self.payment_hash = payment_hash

    htlc = MockHTLC(settled=False, refunded=False, locktime=100, payment_hash="")
    assert IsHTLCActive().is_satisfied_by(htlc) is True
    assert IsTimelockExpired(105).is_satisfied_by(htlc) is True
    assert IsTimelockExpired(95).is_satisfied_by(htlc) is False


def test_polymorphic_fee_policies():
    policies: list[FeePolicy] = [
        RoutingFeePolicy(base_fee_sat=1, fee_rate_ppm=1000),
        LeaseFeePolicy(base_fee_sat=500, fee_rate_ppm=2000),
    ]

    calculated_fees = [p.calculate_fee(amount_sat=10_000) for p in policies]
    assert calculated_fees == [11, 520]


def test_decorators():
    attempts = 0

    @retry(max_attempts=3, delay_seconds=0.01, exceptions=(ValueError,))
    def flaky_fn():
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise ValueError("transient failure")
        return "success"

    assert flaky_fn() == "success"
    assert attempts == 2

    @handle_domain_errors(ChannelStateError, "Operation failed")
    def bad_fn():
        raise KeyError("missing key")

    with pytest.raises(ChannelStateError, match="Operation failed: 'missing key'"):
        bad_fn()


def test_demo_controller_pattern():
    from payment_communities.cli.demos import DemoCommand, DemoController, controller

    ctrl = DemoController()
    demos = ctrl.list_demos()
    assert len(demos) == 8

    demo_names = [d.name for d in demos]
    expected_names = [
        "simulate",
        "breach",
        "watchtower",
        "eltoo",
        "sphinx",
        "ptlc",
        "anchors",
        "swaps",
    ]
    for name in expected_names:
        assert name in demo_names

    # Test custom command registration and dispatching
    executed = []
    ctrl.register("custom", "Custom Test Demo", lambda x: executed.append(x))

    cmd = ctrl.get_demo("custom")
    assert isinstance(cmd, DemoCommand)
    assert cmd.name == "custom"
    assert cmd.description == "Custom Test Demo"

    ctrl.run("custom", "hello_world")
    assert executed == ["hello_world"]

    with pytest.raises(KeyError, match="Demo 'non_existent' is not registered"):
        ctrl.run("non_existent")

    # Global controller singleton check
    assert isinstance(controller, DemoController)
