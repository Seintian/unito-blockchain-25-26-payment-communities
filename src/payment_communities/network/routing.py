"""
Network Graph Topology, Fee Policy & Routing Strategy Engine.
Computes multi-hop payment routes based on channel capacities, directional liquidity,
routing fees (base_fee + fee_rate_ppm), and staggered timelocks using the Strategy pattern.
"""

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
                path_valid = True

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
                    if graph.get_capacity(u, v) < hop_amount:
                        path_valid = False
                        break

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

                if path_valid:
                    return PaymentRoute(
                        hops=hops,
                        total_amount_sat=current_amount,
                        total_fee_sat=total_fee,
                    )
                # If path lacks cumulative fee capacity, continue search for alternate paths
                continue

            if current in visited:
                continue
            visited.add(current)

            for neighbor in graph.adj.get(current, {}):
                if neighbor not in path:  # avoid cycles
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
