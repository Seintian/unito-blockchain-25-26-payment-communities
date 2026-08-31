"""
Protocol Demonstrations Controller & Registry Engine.

Implements Controller, Command, and Registry design patterns to dynamically
register, discover, and dispatch interactive payment protocol demonstrations.
"""

from collections.abc import Callable
from typing import Any

from payment_communities.cli.demos.anchors import run_anchors_demo
from payment_communities.cli.demos.breach import run_breach_demo
from payment_communities.cli.demos.eltoo import run_eltoo_demo
from payment_communities.cli.demos.ptlc import run_ptlc_demo
from payment_communities.cli.demos.routing import run_simulate_demo
from payment_communities.cli.demos.sphinx import run_sphinx_demo
from payment_communities.cli.demos.swaps import run_swaps_demo
from payment_communities.cli.demos.watchtower import run_watchtower_demo


class DemoCommand:
    """Encapsulates a registered protocol demonstration command (Command Pattern)."""

    def __init__(self, name: str, description: str, handler: Callable[..., Any]):
        self.name = name
        self.description = description
        self.handler = handler

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        """Executes the encapsulated demo handler."""
        return self.handler(*args, **kwargs)


class DemoController:
    """
    Central Controller & Registry for payment community protocol demonstrations
    (Controller, Facade, & Registry Patterns).
    Provides dispatching, discovery, and execution management for all protocol demos.
    """

    def __init__(self) -> None:
        self._demos: dict[str, DemoCommand] = {}
        self._register_default_demos()

    def register(
        self, name: str, description: str, handler: Callable[..., Any]
    ) -> None:
        """Registers a demonstration command in the controller registry."""
        self._demos[name] = DemoCommand(name, description, handler)

    def _register_default_demos(self) -> None:
        """Registers default core protocol demonstrations."""
        self.register(
            "simulate",
            "Multi-Hop Micropayment Routing & Pathfinding Simulation",
            run_simulate_demo,
        )
        self.register(
            "breach",
            "Poon-Dryja Revocation & Breach Remedy Penalty",
            run_breach_demo,
        )
        self.register(
            "watchtower",
            "Watchtower Encrypted Hint Registration & Autonomous Breach Sweep",
            run_watchtower_demo,
        )
        self.register(
            "eltoo",
            "Eltoo (LN-Symmetric) Floating Sequence State Update Protocol",
            run_eltoo_demo,
        )
        self.register(
            "sphinx",
            "Sphinx Multi-Layer ECDH Onion Encrypted Routing Protocol",
            run_sphinx_demo,
        )
        self.register(
            "ptlc",
            "PTLC & Schnorr Adaptor Signature Execution Protocol",
            run_ptlc_demo,
        )
        self.register(
            "anchors",
            "Anchor Outputs (330 sat) & CPFP Fee Bumping Engine",
            run_anchors_demo,
        )
        self.register(
            "swaps",
            "Atomic Submarine Swaps & BOLT #7 Liquidity Advertisements",
            run_swaps_demo,
        )

    def run(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Executes a registered demo by name."""
        if name not in self._demos:
            raise KeyError(f"Demo '{name}' is not registered in DemoController.")
        return self._demos[name].execute(*args, **kwargs)

    def get_demo(self, name: str) -> DemoCommand:
        """Returns the registered DemoCommand instance by name."""
        if name not in self._demos:
            raise KeyError(f"Demo '{name}' is not registered in DemoController.")
        return self._demos[name]

    def list_demos(self) -> list[DemoCommand]:
        """Returns list of all registered demo commands."""
        return list(self._demos.values())


# Global Controller Singleton Instance
controller = DemoController()
