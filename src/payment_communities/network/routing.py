"""
Network Graph Topology, Fee Policy & Routing Strategy Engine.
Computes multi-hop payment routes based on channel capacities, directional liquidity,
routing fees (base_fee + fee_rate_ppm), and staggered timelocks using the Strategy pattern.
"""

from typing import Any
from abc import ABC, abstractmethod
from heapq import heappop, heappush

from pydantic import BaseModel, ConfigDict, Field

from payment_communities.config import (
    DEFAULT_CLTV_DELTA_BLOCKS,
    DEFAULT_ROUTING_BASE_FEE_SAT,
    DEFAULT_ROUTING_FEE_RATE_PPM,
)
from payment_communities.domain.channel import Channel
from payment_communities.domain.core.policies import RoutingFeePolicy
from payment_communities.exceptions import RouteNotFoundError


def calculate_routing_fee(
    amount_sat: int,
    base_fee_sat: int = DEFAULT_ROUTING_BASE_FEE_SAT,
    fee_rate_ppm: int = DEFAULT_ROUTING_FEE_RATE_PPM,
) -> int:
    """Calculates routing fee delegating to RoutingFeePolicy."""
    policy = RoutingFeePolicy(base_fee_sat=base_fee_sat, fee_rate_ppm=fee_rate_ppm)
    return policy.calculate_fee(amount_sat)


class RouteHop(BaseModel):
    sender_alias: str
    receiver_alias: str
    amount_sat: int
    fee_sat: int
    locktime: int


class PaymentRoute(BaseModel):
    hops: list[RouteHop]
    total_amount_sat: int
    total_fee_sat: int

    @property
    def path(self) -> list[str]:
        if not self.hops:
            return []
        nodes = [self.hops[0].sender_alias]
        for hop in self.hops:
            nodes.append(hop.receiver_alias)
        return nodes


class RoutingStrategy(ABC):
    """Abstract Strategy interface for multi-hop route finding."""

    @abstractmethod
    def find_route(
        self,
        graph: NetworkGraph,
        source: str,
        target: str,
        amount_sat: int,
        base_locktime: int = 100,
        cltv_delta_per_hop: int = DEFAULT_CLTV_DELTA_BLOCKS,
        base_fee_sat: int = DEFAULT_ROUTING_BASE_FEE_SAT,
        fee_rate_ppm: int = DEFAULT_ROUTING_FEE_RATE_PPM,
    ) -> PaymentRoute:
        pass


class DijkstraRoutingStrategy(RoutingStrategy):
    """Concrete Dijkstra Pathfinding Strategy based on directional channel capacity."""

    def find_route(
        self,
        graph: NetworkGraph,
        source: str,
        target: str,
        amount_sat: int,
        base_locktime: int = 100,
        cltv_delta_per_hop: int = DEFAULT_CLTV_DELTA_BLOCKS,
        base_fee_sat: int = DEFAULT_ROUTING_BASE_FEE_SAT,
        fee_rate_ppm: int = DEFAULT_ROUTING_FEE_RATE_PPM,
    ) -> PaymentRoute:
        if source not in graph.adj or target not in graph.adj:
            raise RouteNotFoundError(
                f"Source '{source}' or target '{target}' not present in network graph."
            )

        queue: list[tuple[int, str, list[str]]] = [(0, source, [source])]
        visited: set[str] = set()

        while queue:
            cost, current, path = heappop(queue)

            if current == target:
                hops = []
                current_amount = amount_sat
                current_locktime = base_locktime
                total_fee = 0

                for i in range(len(path) - 2, -1, -1):
                    u = path[i]
                    v = path[i + 1]

                    fee = 0
                    if v != target:
                        fee = calculate_routing_fee(
                            current_amount, base_fee_sat, fee_rate_ppm
                        )
                        total_fee += fee

                    hop_amount = current_amount + fee
                    hops.insert(
                        0,
                        RouteHop(
                            sender_alias=u,
                            receiver_alias=v,
                            amount_sat=hop_amount,
                            fee_sat=fee,
                            locktime=current_locktime,
                        ),
                    )
                    current_amount = hop_amount
                    current_locktime += cltv_delta_per_hop

                return PaymentRoute(
                    hops=hops,
                    total_amount_sat=current_amount,
                    total_fee_sat=total_fee,
                )

            if current in visited:
                continue
            visited.add(current)

            for neighbor in graph.adj.get(current, {}):
                if neighbor not in visited:
                    cap = graph.get_capacity(current, neighbor)
                    if cap >= amount_sat:
                        heappush(queue, (cost + 1, neighbor, path + [neighbor]))

        raise RouteNotFoundError(
            f"No viable path found from '{source}' to '{target}' for amount {amount_sat} sat."
        )


class NetworkGraph(BaseModel):
    """Network topology graph of active nodes and channels."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    adj: dict[str, dict[str, Channel]] = Field(default_factory=dict)
    strategy: RoutingStrategy = Field(
        default_factory=DijkstraRoutingStrategy, exclude=True
    )

    def add_channel(self, channel: Channel) -> None:
        """Registers a payment channel in the graph (supporting bidirectional routing)."""
        if channel.sender_alias not in self.adj:
            self.adj[channel.sender_alias] = {}
        if channel.receiver_alias not in self.adj:
            self.adj[channel.receiver_alias] = {}

        self.adj[channel.sender_alias][channel.receiver_alias] = channel
        self.adj[channel.receiver_alias][channel.sender_alias] = channel

    def get_capacity(self, u: str, v: str) -> int:
        """Returns available balance in directional channel from u -> v."""
        if u not in self.adj or v not in self.adj[u]:
            return 0
        chan = self.adj[u][v]
        if chan.sender_alias == u:
            return chan.balance_sender_sat
        return chan.balance_receiver_sat

    def find_path(
        self,
        source: str,
        target: str,
        amount_sat: int,
        base_locktime: int = 100,
        cltv_delta_per_hop: int = DEFAULT_CLTV_DELTA_BLOCKS,
        base_fee_sat: int = DEFAULT_ROUTING_BASE_FEE_SAT,
        fee_rate_ppm: int = DEFAULT_ROUTING_FEE_RATE_PPM,
    ) -> PaymentRoute:
        """Finds path delegating to configured RoutingStrategy."""
        return self.strategy.find_route(
            graph=self,
            source=source,
            target=target,
            amount_sat=amount_sat,
            base_locktime=base_locktime,
            cltv_delta_per_hop=cltv_delta_per_hop,
            base_fee_sat=base_fee_sat,
            fee_rate_ppm=fee_rate_ppm,
        )


def run_simulate_demo(
    nodes: dict[str, Any],
    esplora: Any,
    status_fn: Any,
    save_fn: Any,
) -> None:
    """Runs an automated multi-hop payment routing simulation with pathfinding and persistence."""
    from bitcoin.core.script import SIGHASH_ALL, SIGVERSION_WITNESS_V0, SignatureHash
    from rich.console import Console

    from payment_communities.bitcoin.contracts import ScriptFactory
    from payment_communities.bitcoin.transaction import (
        TransactionBuilder,
        create_commitment_transaction,
        create_cooperative_close_transaction,
        create_funding_transaction,
        sign_commitment_transaction,
    )
    from payment_communities.bitcoin.utils import sign_sighash
    from payment_communities.config import (
        DEFAULT_HTLC_LOCKTIME_T1_DELTA,
        DEFAULT_HTLC_LOCKTIME_T2_DELTA,
        DEFAULT_SIMULATION_CAPACITY_SAT,
        DEFAULT_SIMULATION_PAYMENT_SAT,
    )

    console = Console()
    console.print(
        "\n[bold green]=== Starting Multi-Hop Micropayment Simulation ===[/bold green]\n"
    )

    alice_node = nodes["Alice"]
    bob_node = nodes["Bob"]
    dave_node = nodes["Dave"]

    # 1. Fetch live network parameters and UTXOs
    alice_txid, alice_vout = esplora.get_utxo_for_node(
        alice_node.pubkey_bytes, alice_node.p2wpkh_address
    )
    bob_txid, bob_vout = esplora.get_utxo_for_node(
        bob_node.pubkey_bytes, bob_node.p2wpkh_address
    )

    console.print(
        f"[cyan]Step 1:[/cyan] Opening channel Alice -> Bob ({DEFAULT_SIMULATION_CAPACITY_SAT:,} sat capacity)..."
    )
    ch_ab = alice_node.open_channel(
        bob_node, capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT
    )
    funding_tx_ab, multisig_script_ab = create_funding_transaction(
        funder_utxo_txid=alice_txid,
        funder_utxo_vout=alice_vout,
        funder_pubkey_bytes=alice_node.pubkey_bytes,
        counterparty_pubkey_bytes=bob_node.pubkey_bytes,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
    )
    ch_ab.funding_txid = funding_tx_ab.GetTxid().hex()
    ch_ab.funding_vout = 0
    console.print(
        f"  [dim]Funding TXID (Alice->Bob):[/dim] {(ch_ab.funding_txid or '')[:24]}..."
    )

    console.print(
        f"[cyan]Step 2:[/cyan] Opening channel Bob -> Dave ({DEFAULT_SIMULATION_CAPACITY_SAT:,} sat capacity)..."
    )
    ch_bd = bob_node.open_channel(
        dave_node, capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT
    )
    funding_tx_bd, _multisig_script_bd = create_funding_transaction(
        funder_utxo_txid=bob_txid,
        funder_utxo_vout=bob_vout,
        funder_pubkey_bytes=bob_node.pubkey_bytes,
        counterparty_pubkey_bytes=dave_node.pubkey_bytes,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
    )
    ch_bd.funding_txid = funding_tx_bd.GetTxid().hex()
    ch_bd.funding_vout = 0
    console.print(
        f"  [dim]Funding TXID (Bob->Dave):[/dim] {(ch_bd.funding_txid or '')[:24]}..."
    )

    # 2. Dijkstra Pathfinding
    graph = NetworkGraph()
    graph.add_channel(ch_ab)
    graph.add_channel(ch_bd)
    route = graph.find_path("Alice", "Dave", amount_sat=DEFAULT_SIMULATION_PAYMENT_SAT)

    console.print(
        f"\n[cyan]Pathfinding Route Found:[/cyan] {' -> '.join(route.path)} "
        f"(Total Sat: {route.total_amount_sat:,}, Total Routing Fee: {route.total_fee_sat:,} sat)"
    )

    # 3. Dave creates invoice (preimage R & hash H)
    console.print(
        "\n[cyan]Step 3:[/cyan] Dave generates invoice (Preimage & Payment Hash)..."
    )
    preimage_hex, hash_hex = dave_node.create_invoice()
    console.print(f"  [dim]Preimage (R):[/dim] {preimage_hex[:24]}...")
    console.print(f"  [dim]Payment Hash (H):[/dim] {hash_hex[:24]}...")

    # 4. Alice routes HTLC to Bob using live block height
    payment_amount_sat = DEFAULT_SIMULATION_PAYMENT_SAT
    current_block_height = esplora.get_block_height()
    locktime_alice_to_bob = current_block_height + DEFAULT_HTLC_LOCKTIME_T1_DELTA
    locktime_bob_to_dave = current_block_height + DEFAULT_HTLC_LOCKTIME_T2_DELTA

    console.print(
        f"\n[cyan]Step 4:[/cyan] Alice locks {payment_amount_sat:,} sat HTLC to Bob..."
    )
    alice_node.route_htlc_payment(
        target_peer_alias="Bob",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_alice_to_bob,
        htlc_id="htlc_ab_1",
    )

    htlc_script_ab = ScriptFactory.create_htlc(
        alice_node.pubkey_bytes,
        bob_node.pubkey_bytes,
        bytes.fromhex(hash_hex),
        locktime_alice_to_bob,
    )
    alice_balance_sat = DEFAULT_SIMULATION_CAPACITY_SAT - payment_amount_sat
    commit_tx_ab = create_commitment_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        sender_balance_sat=alice_balance_sat,
        receiver_balance_sat=0,
        htlc_outputs=[(payment_amount_sat, htlc_script_ab)],
    )
    sign_commitment_transaction(
        tx=commit_tx_ab,
        input_index=0,
        redeem_script=multisig_script_ab,
        capacity_sat=DEFAULT_SIMULATION_CAPACITY_SAT,
        sec1=alice_node.secret,
        sec2=bob_node.secret,
    )
    console.print(
        "  [bold green]✓ HTLC Alice -> Bob offered & Signed Commitment TX built[/bold green]"
    )

    # 5. Bob forwards HTLC to Dave
    console.print(
        f"\n[cyan]Step 5:[/cyan] Bob forwards {payment_amount_sat:,} sat HTLC to Dave..."
    )
    bob_node.route_htlc_payment(
        target_peer_alias="Dave",
        amount_sat=payment_amount_sat,
        payment_hash=hash_hex,
        locktime=locktime_bob_to_dave,
        htlc_id="htlc_bd_1",
    )
    console.print("  [bold green]✓ HTLC Bob -> Dave offered successfully[/bold green]")

    # 6. Preimage Fulfillment across the route
    console.print(
        "\n[cyan]Step 6:[/cyan] Dave fulfills HTLC with Bob using secret Preimage..."
    )
    bob_node.fulfill_htlc("Dave", "htlc_bd_1", preimage_hex)
    console.print(
        f"  [bold green]✓ Dave claimed {payment_amount_sat:,} sat from Bob![/bold green]"
    )

    console.print(
        "\n[cyan]Step 7:[/cyan] Bob fulfills HTLC with Alice using revealed Preimage..."
    )
    alice_node.fulfill_htlc("Bob", "htlc_ab_1", preimage_hex)
    console.print(
        f"  [bold green]✓ Bob claimed {payment_amount_sat:,} sat from Alice![/bold green]"
    )

    # 7. Real Cooperative Close Settlement Transaction Generation & Signing
    close_tx_ab = create_cooperative_close_transaction(
        funding_txid=ch_ab.funding_txid or "",
        funding_vout=0,
        sender_pubkey_bytes=alice_node.pubkey_bytes,
        receiver_pubkey_bytes=bob_node.pubkey_bytes,
        final_sender_sat=alice_balance_sat,
        final_receiver_sat=payment_amount_sat,
    )
    sighash_close = SignatureHash(
        multisig_script_ab,
        close_tx_ab,
        0,
        SIGHASH_ALL,
        amount=DEFAULT_SIMULATION_CAPACITY_SAT,
        sigversion=SIGVERSION_WITNESS_V0,
    )
    sig1_close = sign_sighash(alice_node.secret, sighash_close)
    sig2_close = sign_sighash(bob_node.secret, sighash_close)
    witness_close = ScriptFactory.witness_multisig_2of2(
        sig1_close, sig2_close, multisig_script_ab
    )

    signed_close_tx_ab = (
        TransactionBuilder()
        .add_input(ch_ab.funding_txid or "", 0)
        .add_p2wsh_output(alice_balance_sat, alice_node.pubkey_bytes)
        .add_p2wsh_output(payment_amount_sat, bob_node.pubkey_bytes)
        .add_witness_stack(witness_close)
        .build()
    )

    console.print(
        f"\n[dim]Signed Cooperative Settlement TXID:[/dim] {signed_close_tx_ab.GetTxid().hex()[:24]}..."
    )

    save_fn()
    console.print(
        "\n[bold green]=== Multi-Hop Payment Complete & State Persisted! ===[/bold green]\n"
    )
    status_fn()
