#!/usr/bin/env bash
set -e

BLOCKS=${1:-1}
RPC_USER="bitcoin"
RPC_PASS="bitcoin"
RPC_PORT="18443"
RPC_HOST="${BITCOIND_HOST:-localhost}"

echo "Mining $BLOCKS block(s) in Bitcoin Regtest on $RPC_HOST..."

ADDR=$(curl -s --user $RPC_USER:$RPC_PASS \
  --data-binary '{"jsonrpc": "1.0", "id":"addr", "method": "getnewaddress", "params": []}' \
  -H 'content-type: text/plain;' \
  http://"$RPC_HOST":$RPC_PORT/wallet/miner_wallet | grep -o '"result":"[^"]*' | cut -d'"' -f4)

curl -s --user $RPC_USER:$RPC_PASS \
  --data-binary "{\"jsonrpc\": \"1.0\", \"id\":\"mine\", \"method\": \"generatetoaddress\", \"params\": [$BLOCKS, \"$ADDR\"]}" \
  -H 'content-type: text/plain;' \
  http://"$RPC_HOST":$RPC_PORT/wallet/miner_wallet | jq .

echo "Done! Mined $BLOCKS block(s)."
