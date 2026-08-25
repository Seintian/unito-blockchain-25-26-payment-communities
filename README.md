# Payment Communities - Bitcoin Micropayment Channels

#### Exam project for the Blockchain, Distributed and Decentralized Systems course (INF04422).

This project implements a simplified network of unidirectional *off-chain* micropayment channels on Bitcoin Testnet, inspired by the principles of the Lightning Network protocol.

The system allows Alice to send secure micropayments to Dave by routing them through Bob's intermediate node, without requiring a direct channel and ensuring that no intermediary can steal or freeze the funds thanks to cryptographic and temporal constraints.

## Protocol Features

- **Unidirectional Channels**: On-chain channel opening with multisig security collateral.
- **Spending Logic (Bitcoin Script)**: HTLCs (Hashed Time-Locked Contracts) that lock the redemption of funds to the knowledge of a cryptographic secret (`OP_SHA256`) or the expiration of a predefined block height/timestamp (`OP_CHECKLOCKTIMEVERIFY`).
- **Dispute Resolution**: Unilateral channel closure or automatic refund triggered upon timeout.
- **Client Interface**: CLI or automated scripts to simulate interaction between nodes (Alice, Bob, Dave).

## Project Structure

- `/contracts/`: Definition of scriptSig and scriptPubKey templates in Bitcoin assembly format.
- `/src/`: Python modules and scripts for address generation, channel funding, signature generation, and on-chain broadcasting of open, update, and close transactions.
- `/tests/`: Test suite simulating payment routing, multi-hop updates, and dispute scenarios.
- `/docs/`: Detailed documentation of the transaction flow and channel state diagrams.

## Prerequisites and Setup

- Python (v3.10+).
- [uv](https://docs.astral.sh/uv/) package and project manager.
- Access to a Bitcoin Testnet/Signet node or via external APIs (e.g., Blockstream, Blockcypher).
- Testnet private keys and addresses funded by a public faucet.

## Installation

```bash
# Clone the repository
git clone git@github.com:Seintian/unito-blockchain-25-26-payment-communities
cd payment-communities

# Create a virtual environment and sync dependencies using uv
uv sync

# Environment variables configuration
cp .env.example .env
# Fill in your testnet private keys in the .env file
```

## Running the Simulation

```bash
# Run the node simulation script
uv run python -m src.main
```

## Running Tests

```bash
# Launch the payment channel simulation
uv run pytest
```

