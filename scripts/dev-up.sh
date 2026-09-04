#!/usr/bin/env bash
set -e

echo "=== Starting Payment Communities Docker Regtest Environment ==="

docker compose down -v
docker compose build
docker compose up -d

echo "Waiting for Bitcoin Core Regtest RPC to become healthy..."
docker compose exec -T bitcoind-regtest bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin -rpcwait getblockchaininfo > /dev/null

echo "Waiting 12 seconds for miner to mature initial 101 blocks..."
sleep 12

echo "Funding node wallets on Regtest..."
./scripts/fund-nodes.sh 2.0

echo "Docker environment ready for experimentation!"
echo "Run live simulations with:"
echo "  docker compose exec alice-node payment-communities status"
echo "  docker compose exec alice-node payment-communities simulate --live"
