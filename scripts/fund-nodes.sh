#!/usr/bin/env bash
set -e

RPC_USER="bitcoin"
RPC_PASS="bitcoin"
RPC_PORT="18443"
RPC_HOST="${BITCOIND_HOST:-localhost}"
AMOUNT_BTC="${1:-1.0}"

echo "Funding Alice, Bob, and Dave with $AMOUNT_BTC BTC each..."

# Get addresses from python CLI
ALICE_ADDR=$(uv run python -c "from payment_communities.domain.node import Node; from payment_communities.config import settings; print(Node('Alice', settings.alice_key or None).address)")
BOB_ADDR=$(uv run python -c "from payment_communities.domain.node import Node; from payment_communities.config import settings; print(Node('Bob', settings.bob_key or None).address)")
DAVE_ADDR=$(uv run python -c "from payment_communities.domain.node import Node; from payment_communities.config import settings; print(Node('Dave', settings.dave_key or None).address)")

echo "Alice Address: $ALICE_ADDR"
echo "Bob Address:   $BOB_ADDR"
echo "Dave Address:  $DAVE_ADDR"

for ADDR in "$ALICE_ADDR" "$BOB_ADDR" "$DAVE_ADDR"; do
  echo "Sending $AMOUNT_BTC BTC to $ADDR..."
  curl -s --user $RPC_USER:$RPC_PASS \
    --data-binary "{\"jsonrpc\": \"1.0\", \"id\":\"send\", \"method\": \"sendtoaddress\", \"params\": [\"$ADDR\", $AMOUNT_BTC]}" \
    -H 'content-type: text/plain;' \
    http://"$RPC_HOST":$RPC_PORT/wallet/miner_wallet
  echo ""
done

# Mine 1 block to confirm funding transactions
./scripts/mine-blocks.sh 1
echo "All nodes successfully funded and confirmed!"
