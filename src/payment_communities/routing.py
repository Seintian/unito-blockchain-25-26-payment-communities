"""
Network Graph Topology, Fee Policy & Dijkstra Pathfinding Engine.
Computes multi-hop payment routes based on channel capacities, directional liquidity,
routing fees (base_fee + fee_rate_ppm), and staggered timelocks.
"""

from heapq import heappop, heappush

from pydantic import BaseModel, Field

from payment_communities.channel import Channel
from payment_communities.exceptions import RouteNotFoundError


def calculate_routing_fee(
    amount_sat: int, base_fee_sat: int = 1, fee_rate_ppm: int = 1000
) -> int:
    """
    Calculates routing fee for a given amount:
    fee = base_fee + floor(amount * fee_rate_ppm / 1,000,000)
    """
    proportional_fee = (amount_sat * fee_rate_ppm) // 1_000_000
    return base_fee_sat + proportional_fee


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


class NetworkGraph(BaseModel):
    """Network topology graph of active nodes and channels."""

    adj: dict[str, dict[str, Channel]] = Field(default_factory=dict)

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
        cltv_delta_per_hop: int = 40,
        base_fee_sat: int = 1,
        fee_rate_ppm: int = 1000,
    ) -> PaymentRoute:
        """
        Finds optimal payment route from source to target using Dijkstra pathfinding.
        Raises:
            RouteNotFoundError: If no path with sufficient channel liquidity exists.
        """
        if source not in self.adj or target not in self.adj:
            raise RouteNotFoundError(
                f"Source '{source}' or target '{target}' not present in network graph."
            )

        # Dijkstra queue: (cost, current_node, path_history)
        queue: list[tuple[int, str, list[str]]] = [(0, source, [source])]
        visited: set[str] = set()

        while queue:
            cost, current, path = heappop(queue)

            if current == target:
                # Construct route hops with fee and timelock staggering
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

            for neighbor in self.adj.get(current, {}):
                if neighbor not in visited:
                    cap = self.get_capacity(current, neighbor)
                    if cap >= amount_sat:
                        heappush(queue, (cost + 1, neighbor, path + [neighbor]))

        raise RouteNotFoundError(
            f"No viable path found from '{source}' to '{target}' for amount {amount_sat} sat."
        )
