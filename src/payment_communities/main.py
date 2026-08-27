"""
Payment Communities - Main Entry Point.
Delegates to payment_communities.cli.app.
"""

from payment_communities.cli.app import (
    anchors_demo,
    app,
    breach_demo,
    eltoo_demo,
    funds,
    info,
    main,
    ptlc_demo,
    simulate,
    sphinx_demo,
    status,
    swaps_demo,
    watchtower_demo,
)

__all__ = [
    "anchors_demo",
    "app",
    "breach_demo",
    "eltoo_demo",
    "funds",
    "info",
    "main",
    "ptlc_demo",
    "simulate",
    "sphinx_demo",
    "status",
    "swaps_demo",
    "watchtower_demo",
]

if __name__ == "__main__":
    main()
