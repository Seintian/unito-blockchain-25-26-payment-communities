"""
Payment Communities - Typer CLI Application Engine.
"""

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from payment_communities.cli.demos import (
    run_anchors_demo,
    run_breach_demo,
    run_eltoo_demo,
    run_ptlc_demo,
    run_simulate_demo,
    run_sphinx_demo,
    run_swaps_demo,
    run_watchtower_demo,
)
from payment_communities.config import MIN_CHANNEL_CAPACITY_SAT, settings
from payment_communities.domain.node import Node
from payment_communities.exceptions import NetworkError
from payment_communities.network.client import EsploraClient
from payment_communities.storage.engine import StorageEngine

app = typer.Typer(
    name="Payment Communities",
    help="Bitcoin Micropayment Channels Simulation CLI (Alice -> Bob -> Dave)",
    add_completion=True,
)
console = Console()
storage = StorageEngine()

# Persistent node registry for network simulation
nodes = {
    "Alice": Node("Alice", wif_key=settings.alice_key or None),
    "Bob": Node("Bob", wif_key=settings.bob_key or None),
    "Dave": Node("Dave", wif_key=settings.dave_key or None),
}

esplora = EsploraClient()


def _sync_nodes_with_storage():
    """Loads persistent channels into nodes dictionary."""
    state = storage.load_state()
    for channel in state.channels.values():
        if channel.sender_alias in nodes and channel.receiver_alias in nodes:
            sender = nodes[channel.sender_alias]
            receiver = nodes[channel.receiver_alias]
            sender.channels[receiver.alias] = channel
            receiver.channels[sender.alias] = channel


def _save_nodes_to_storage():
    """Saves current channel states into storage."""
    all_channels = {}
    for node in nodes.values():
        for ch in node.channels.values():
            all_channels[ch.channel_id] = ch
    storage.save_state(all_channels, {})


def _get_node_offchain_balance(node: Node) -> int:
    """Calculates node's total off-chain balance across all open payment channels."""
    total = 0
    for channel in node.channels.values():
        if channel.sender_alias == node.alias:
            total += channel.balance_sender_sat
        elif channel.receiver_alias == node.alias:
            total += channel.balance_receiver_sat
    return total


@app.command()
def info():
    """Displays project setup, network parameter settings, node keys, and on-chain addresses."""
    _sync_nodes_with_storage()
    try:
        current_height = esplora.get_block_height()
        tip_hash = esplora.get_tip_hash()
        fee_rate = esplora.get_recommended_fee_rate(target_blocks=1)
        network_status = f"[green]Online[/green] (Height: {current_height:,}, Fee: {fee_rate} sat/vB)"
    except (NetworkError, httpx.HTTPError, ValueError) as e:
        tip_hash = "Unavailable"
        network_status = f"[yellow]Degraded ({e})[/yellow]"

    # Query live on-chain & off-chain balances
    balance_lines = []
    for alias, node in nodes.items():
        try:
            confirmed, unconfirmed = esplora.get_address_balance(node.address)
            bal_str = f"{confirmed:,} sat"
            if unconfirmed:
                bal_str += f" ({unconfirmed:+,} mempool)"
        except NetworkError, httpx.HTTPError, ValueError:
            confirmed = 0
            bal_str = "N/A"

        l2_bal = _get_node_offchain_balance(node)
        balance_lines.append(
            f"  • {alias:5}: {node.address}\n"
            f"           [dim]PubKey: {node.pubkey_hex[:24]}... | L1 On-Chain: {bal_str} | L2 Off-Chain: {l2_bal:,} sat[/dim]"
        )

    node_info_str = "\n".join(balance_lines)

    console.print(
        Panel.fit(
            "[bold cyan]Payment Communities - Bitcoin Micropayment Channels[/bold cyan]\n"
            f"[green]Network:[/green] {settings.network}\n"
            f"[green]Esplora API:[/green] {settings.esplora_api_url}\n"
            f"[green]Network Status:[/green] {network_status}\n"
            f"[green]Tip Block Hash:[/green] {tip_hash[:32]}...\n"
            f"[green]Signet Faucet:[/green] {settings.signet_faucet_url}\n"
            f"[green]Storage File:[/green] {storage.file_path}\n\n"
            "[yellow]Live Node Addresses, Public Keys & Portfolio Balances:[/yellow]\n"
            f"{node_info_str}",
            title="Project Configuration & Live Network Status",
        )
    )


@app.command()
def funds():
    """Queries and displays live on-chain UTXOs, off-chain L2 channel balances, and total node liquidity."""
    _sync_nodes_with_storage()
    console.print(
        "\n[bold cyan]=== Unified Liquidity & Node Portfolio Matrix ===[/bold cyan]\n"
    )

    # 1. On-Chain L1 Balances Table
    l1_table = Table(
        title=f"Layer 1 On-Chain Balances ({settings.network.capitalize()})"
    )
    l1_table.add_column("Node", style="magenta")
    l1_table.add_column("Address", style="cyan")
    l1_table.add_column("Confirmed (sat)", justify="right")
    l1_table.add_column("Mempool (sat)", justify="right")
    l1_table.add_column("UTXO Count", justify="center")

    total_confirmed = 0
    total_mempool = 0
    node_onchain = {}

    for alias, node in nodes.items():
        try:
            confirmed, unconfirmed = esplora.get_address_balance(node.address)
            utxos = esplora.get_address_utxos(node.address)
            l1_table.add_row(
                alias,
                node.address,
                f"{confirmed:,}",
                f"{unconfirmed:+,}" if unconfirmed != 0 else "0",
                str(len(utxos)),
            )
            total_confirmed += confirmed
            total_mempool += unconfirmed
            node_onchain[alias] = confirmed
        except (NetworkError, httpx.HTTPError, ValueError) as e:
            l1_table.add_row(alias, node.address, "Error", str(e), "0")
            node_onchain[alias] = 0

    console.print(l1_table)

    # 2. Unified Net Liquidity Breakdown (L1 On-Chain + L2 Off-Chain)
    portfolio_table = Table(
        title="Unified Net Node Portfolio Breakdown (L1 On-Chain + L2 Off-Chain)"
    )
    portfolio_table.add_column("Node", style="magenta")
    portfolio_table.add_column("L1 On-Chain (sat)", justify="right", style="cyan")
    portfolio_table.add_column("L2 Off-Chain (sat)", justify="right", style="green")
    portfolio_table.add_column(
        "Total Net Liquidity (sat)", justify="right", style="bold yellow"
    )

    total_offchain_sum = 0
    for alias, node in nodes.items():
        l1_bal = node_onchain.get(alias, 0)
        l2_bal = _get_node_offchain_balance(node)
        total_offchain_sum += l2_bal
        portfolio_table.add_row(
            alias,
            f"{l1_bal:,}",
            f"{l2_bal:,}",
            f"{l1_bal + l2_bal:,}",
        )

    console.print()
    console.print(portfolio_table)
    console.print(
        f"\n[green]Total Network Liquidity:[/green] On-Chain: [cyan]{total_confirmed:,} sat[/cyan] | Off-Chain: [green]{total_offchain_sum:,} sat[/green] | Net Portfolio: [bold yellow]{total_confirmed + total_offchain_sum:,} sat[/bold yellow]"
    )

    if total_confirmed == 0:
        console.print(
            f"\n[yellow]💡 Tip: Need testnet/signet satoshis? Request free coins from the faucet:[/yellow]\n"
            f"   [cyan]{settings.signet_faucet_url}[/cyan]\n"
            f"   Send funds to Alice: [bold]{nodes['Alice'].address}[/bold]\n"
            f"   Send funds to Bob:   [bold]{nodes['Bob'].address}[/bold]\n"
        )


@app.command()
def status():
    """Displays active channels, balances, and pending HTLC contracts."""
    _sync_nodes_with_storage()
    table = Table(title="Off-Chain Payment Channels Matrix (L2)")
    table.add_column("Channel ID", style="cyan")
    table.add_column("Sender", style="magenta")
    table.add_column("Receiver", style="green")
    table.add_column("Capacity (sat)", justify="right")
    table.add_column("Sender Bal (sat)", justify="right")
    table.add_column("Receiver Bal (sat)", justify="right")
    table.add_column("Funding TXID / Mode", style="dim")
    table.add_column("State", style="bold yellow")
    table.add_column("Active HTLCs", justify="center")

    processed_channels = set()

    for node in nodes.values():
        for channel in node.channels.values():
            if channel.channel_id in processed_channels:
                continue
            processed_channels.add(channel.channel_id)
            txid_disp = (
                f"{channel.funding_txid[:16]}..."
                if channel.funding_txid
                else "Off-Chain Simulated"
            )
            table.add_row(
                channel.channel_id,
                channel.sender_alias,
                channel.receiver_alias,
                f"{channel.capacity_sat:,}",
                f"{channel.balance_sender_sat:,}",
                f"{channel.balance_receiver_sat:,}",
                txid_disp,
                channel.state.value,
                str(len(channel.active_htlcs)),
            )

    if not processed_channels:
        console.print(
            "[yellow]No payment channels currently open. Run `simulate` to see a full demo.[/yellow]"
        )
    else:
        console.print(table)
        console.print(
            "\n[dim]💡 Off-chain channel balances represent L2 Lightning Network liquidity. Run `funds` for the complete unified On-Chain (L1) + Off-Chain (L2) portfolio breakdown.[/dim]\n"
        )


@app.command()
def fund_channel(
    funder: str = typer.Option(
        "Alice", "--funder", "-f", help="Funder node alias (Alice, Bob, Dave)"
    ),
    counterparty: str = typer.Option(
        "Bob", "--counterparty", "-c", help="Counterparty node alias"
    ),
    capacity: int = typer.Option(
        MIN_CHANNEL_CAPACITY_SAT,
        "--capacity",
        "-s",
        help="Channel capacity in satoshis",
    ),
):
    """
    Opens and funds a real micropayment channel on-chain using live testnet/signet UTXOs.
    """
    if funder not in nodes or counterparty not in nodes:
        console.print(
            f"[bold red]Error: Invalid node alias. Choose from: {list(nodes.keys())}[/bold red]"
        )
        raise typer.Exit(1)

    funder_node = nodes[funder]
    cp_node = nodes[counterparty]

    console.print(
        f"\n[cyan]Attempting to fund on-chain channel {funder} -> {counterparty} ({capacity:,} sat)...[/cyan]"
    )
    try:
        txid, vout, _redeem_script = esplora.fund_channel_on_chain(
            funder_secret=funder_node.secret,
            counterparty_pubkey=cp_node.pubkey_bytes,
            capacity_sat=capacity,
        )
        channel = funder_node.open_channel(cp_node, capacity_sat=capacity)
        channel.funding_txid = txid
        channel.funding_vout = vout
        _save_nodes_to_storage()

        console.print(
            f"[bold green]✓ Channel Funded & Broadcast Live to {settings.network.capitalize()}![/bold green]"
        )
        console.print(f"  • Funding TXID: [cyan]{txid}[/cyan]")
        console.print(
            f"  • View on explorer: [link={settings.esplora_api_url.replace('/api', '')}/tx/{txid}]{txid}[/link]\n"
        )
    except NetworkError as e:
        console.print(f"[bold red]Failed to fund channel on-chain:[/bold red] {e}")


@app.command()
def simulate():
    """Runs an automated multi-hop payment routing simulation with pathfinding and persistence."""
    run_simulate_demo(nodes, esplora, status, _save_nodes_to_storage)


@app.command()
def breach_demo():
    """Demonstrates Poon-Dryja State Revocation and Breach Remedy Justice Sweep Penalty."""
    run_breach_demo(nodes, esplora)


@app.command()
def watchtower_demo():
    """Demonstrates privacy-preserving Watchtower hint registration and autonomous L1 breach sweep."""
    run_watchtower_demo(nodes, esplora)


@app.command()
def eltoo_demo():
    """Demonstrates Eltoo (LN-Symmetric) state update protocol without penalty revocation secrets."""
    run_eltoo_demo(nodes, esplora)


@app.command()
def sphinx_demo():
    """Demonstrates Sphinx multi-layer onion encryption across intermediate routing nodes."""
    run_sphinx_demo(nodes, esplora)


@app.command()
def ptlc_demo():
    """Demonstrates Point Time-Locked Contracts (PTLCs) and Schnorr Adaptor Signatures."""
    run_ptlc_demo(nodes, esplora)


@app.command()
def anchors_demo():
    """Demonstrates BOLT #3 330 sat Anchor Outputs and CPFP Child Fee Bumping."""
    run_anchors_demo(nodes, esplora)


@app.command()
def swaps_demo():
    """Demonstrates Atomic Submarine Swaps (L1 <-> L2) and BOLT #7 Liquidity Advertisements."""
    run_swaps_demo(nodes, esplora)


def main():
    app()


if __name__ == "__main__":
    main()
