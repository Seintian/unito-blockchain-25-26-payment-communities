"""
Protocol Demonstrations Package.

Exports the DemoController, DemoCommand, singleton controller, and all demo runners.
"""

from payment_communities.cli.demos.anchors import run_anchors_demo
from payment_communities.cli.demos.breach import run_breach_demo
from payment_communities.cli.demos.controller import (
    DemoCommand,
    DemoController,
    controller,
)
from payment_communities.cli.demos.eltoo import run_eltoo_demo
from payment_communities.cli.demos.ptlc import run_ptlc_demo
from payment_communities.cli.demos.routing import run_simulate_demo
from payment_communities.cli.demos.sphinx import run_sphinx_demo
from payment_communities.cli.demos.swaps import run_swaps_demo
from payment_communities.cli.demos.watchtower import run_watchtower_demo

__all__ = [
    "DemoCommand",
    "DemoController",
    "controller",
    "run_anchors_demo",
    "run_breach_demo",
    "run_eltoo_demo",
    "run_ptlc_demo",
    "run_simulate_demo",
    "run_sphinx_demo",
    "run_swaps_demo",
    "run_watchtower_demo",
]
