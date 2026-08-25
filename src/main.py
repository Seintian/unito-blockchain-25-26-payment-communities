"""
Payment Communities - Main CLI Starting Point
Simulates unidirectional off-chain micropayment channels on Bitcoin Testnet/Signet/Regtest.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import settings
from network import EsploraClient
from node import Node

app = typer.Typer(
    name="Payment Communities",
    help="Bitcoin Micropayment Channels Simulation CLI (Alice -> Bob -> Dave)",
    add_completion=False
)
console = Console()

# Persistent node instances
nodes = {
    "Alice": Node("Alice", wif_key=settings.alice_key or None),
    "Bob": Node("Bob", wif_key=settings.bob_key or None),
    "Dave": Node("Dave", wif_key=settings.dave_key or None)
}

esplora = EsploraClient()

@app.command()
def info():
    """Displays project setup, network parameter settings, node keys, and on-chain addresses."""
    height = esplora.get_block_height()
    console.print(Panel.fit(
        "[bold cyan]Payment Communities - Bitcoin Micropayment Channels[/bold cyan]\n"
        f"[green]Network:[/green] {settings.network}\n"
        f"[green]Esplora API:[/green] {settings.esplora_api_url}\n"
        f"[green]Current Block Height:[/green] {height}\n\n"
        "[yellow]Node Addresses & Public Keys:[/yellow]\n"
        f"  • Alice: {nodes['Alice'].address} ({nodes['Alice'].pubkey_hex[:16]}...)\n"
        f"  • Bob:   {nodes['Bob'].address} ({nodes['Bob'].pubkey_hex[:16]}...)\n"
        f"  • Dave:  {nodes['Dave'].address} ({nodes['Dave'].pubkey_hex[:16]}...)",
        title="Project Configuration"
    ))

@app.command()
def status():
    """Displays active channels, balances, and pending HTLC contracts."""
    table = Table(title="Payment Channels Status Matrix")
    table.add_column("Channel ID", style="cyan")
    table.add_column("Sender", style="magenta")
    table.add_column("Receiver", style="green")
    table.add_column("Capacity (sat)", justify="right")
    table.add_column("Sender Bal (sat)", justify="right")
    table.add_column("Receiver Bal (sat)", justify="right")
    table.add_column("State", style="bold yellow")
    table.add_column("Active HTLCs", justify="center")

    processed_channels = set()

    for node in nodes.values():
        for channel in node.channels.values():
            if channel.channel_id in processed_channels:
                continue
            processed_channels.add(channel.channel_id)
            table.add_row(
                channel.channel_id,
                channel.sender_alias,
                channel.receiver_alias,
                f"{channel.capacity_sat:,}",
                f"{channel.balance_sender_sat:,}",
                f"{channel.balance_receiver_sat:,}",
                channel.state.value,
                str(len(channel.active_htlcs))
            )

    if not processed_channels:
        console.print("[yellow]No payment channels currently open. Run `simulate` to see a full demo.[/yellow]")
    else:
        console.print(table)

@app.command()
def simulate():
    """Runs an automated multi-hop payment routing simulation (Alice -> Bob -> Dave)."""
    console.print("\n[bold green]=== Starting Multi-Hop Micropayment Simulation ===[/bold green]\n")
    
    alice = nodes["Alice"]
    bob = nodes["Bob"]
    dave = nodes["Dave"]

    # 1. Open Channels
    console.print("[cyan]Step 1:[/cyan] Opening channel Alice -> Bob (100,000 sat capacity)...")
    alice.open_channel(bob, 100_000)

    console.print("[cyan]Step 2:[/cyan] Opening channel Bob -> Dave (100,000 sat capacity)...")
    bob.open_channel(dave, 100_000)

    # 2. Dave creates invoice
    console.print("\n[cyan]Step 3:[/cyan] Dave generates invoice (Preimage & Payment Hash)...")
    preimage_hex, hash_hex = dave.create_invoice()
    console.print(f"  [dim]Preimage (R):[/dim] {preimage_hex[:24]}...")
    console.print(f"  [dim]Payment Hash (H):[/dim] {hash_hex[:24]}...")

    # 3. Alice routes HTLC to Bob
    amount = 25_000
    block_height = esplora.get_block_height()
    locktime_ab = block_height + 144  # T1
    locktime_bd = block_height + 100  # T2 (Staggered: T1 > T2)

    console.print(f"\n[cyan]Step 4:[/cyan] Alice locks {amount:,} sat HTLC to Bob (Locktime T1 = {locktime_ab})...")
    ok1 = alice.route_htlc_payment("Bob", amount, hash_hex, locktime_ab, "htlc_ab_1")
    if ok1:
        console.print("  [bold green]✓ HTLC Alice -> Bob offered successfully[/bold green]")

    # 4. Bob forwards HTLC to Dave
    console.print(f"\n[cyan]Step 5:[/cyan] Bob forwards {amount:,} sat HTLC to Dave (Locktime T2 = {locktime_bd})...")
    ok2 = bob.route_htlc_payment("Dave", amount, hash_hex, locktime_bd, "htlc_bd_1")
    if ok2:
        console.print("  [bold green]✓ HTLC Bob -> Dave offered successfully[/bold green]")

    # 5. Dave claims payment from Bob with Preimage
    console.print("\n[cyan]Step 6:[/cyan] Dave fulfills HTLC with Bob using Preimage...")
    dave_claim = bob.fulfill_htlc("Dave", "htlc_bd_1", preimage_hex)
    if dave_claim:
        console.print("  [bold green]✓ Dave claimed 25,000 sat from Bob![/bold green]")

    # 6. Bob claims payment from Alice with revealed Preimage
    console.print("\n[cyan]Step 7:[/cyan] Bob fulfills HTLC with Alice using revealed Preimage...")
    bob_claim = alice.fulfill_htlc("Bob", "htlc_ab_1", preimage_hex)
    if bob_claim:
        console.print("  [bold green]✓ Bob claimed 25,000 sat from Alice![/bold green]")

    console.print("\n[bold green]=== Multi-Hop Payment Complete! Final Balances: ===[/bold green]\n")
    status()

def main():
    app()

if __name__ == "__main__":
    main()
