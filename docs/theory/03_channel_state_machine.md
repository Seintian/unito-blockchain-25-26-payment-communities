# 03. Channel State Machine & HTLC Contract Resolution

## 1. Formal Channel State Machine

Lightning channels maintain strict state synchronization across asynchronous peer sockets using a non-blocking, two-phase update protocol defined in BOLT #2.

```mermaid
stateDiagram-v2
    [*] --> OPENING : Fund Initiated
    OPENING --> OPEN : Funding TX Confirmed & channel_ready

    state OPEN {
        [*] --> Idle
        Idle --> Updating : update_add_htlc
        Updating --> Signed : commitment_signed
        Signed --> Acknowledged : revoke_and_ack
        Acknowledged --> Idle : State Advanced (N to N+1)
    }

    OPEN --> CLOSING : Mutual Close / Unilateral Close
    OPEN --> BREACHED : Cheater broadcasts revoked state

    BREACHED --> CLOSED : Justice Penalty Sweep claims 100% funds
    CLOSING --> CLOSED : All CSV / CLTV outputs settled on L1
    CLOSED --> [*]
```

---

## 2. Two-Phase Commitment Synchronization

To advance channel state from $N$ to $N+1$ (e.g. to add or settle an HTLC), parties must execute a synchronized 4-message exchange:

```mermaid
sequenceDiagram
    autonumber
    participant Alice
    participant Bob

    Note over Alice,Bob: State N active (balances synchronized)
    Alice->>Bob: 1. update_add_htlc (amount=5,000 sat, hash=H, cltv=144)
    Note over Bob: Staged in pending HTLC table
    Alice->>Bob: 2. commitment_signed (Alice's signature on Bob's State N+1)
    Note over Bob: Validates signature against State N+1<br/>Saves State N+1 commitment
    Bob->>Alice: 3. revoke_and_ack (Reveals Revocation Secret for Bob's State N)
    Note over Alice: Alice now holds Bob's State N revocation secret!<br/>Bob can never broadcast State N again.
    Bob->>Alice: 4. commitment_signed (Bob's signature on Alice's State N+1)
    Alice->>Bob: 5. revoke_and_ack (Reveals Revocation Secret for Alice's State N)
    Note over Alice,Bob: State N+1 is now final and irreversible!
```

---

## 3. Hash Time-Locked Contracts (HTLCs)

HTLCs enable trustless multi-hop payment routing across chains of intermediaries without trusting any node along the path.

An HTLC enforces two mutual conditions:

1. **Preimage Success**: If the receiver presents the 32-byte secret preimage $R$ such that $\text{SHA256}(R) == H$, the receiver claims the funds.
2. **Timeout Refund**: If the expiration block height (CLTV) passes without the preimage being revealed, the sender reclaims the funds.

### The BOLT #3 2nd-Stage HTLC Vulnerability & Solution

In a unilateral force-close scenario, an on-chain race condition exists between the preimage claim and the timeout refund.

If Alice force-closes, she broadcasts her commitment transaction. If Bob has an offered HTLC with Alice:

- If Bob spent directly from Alice's commitment transaction output using the preimage, and Alice's commitment transaction is on-chain:
- A malicious Alice could wait for Bob's preimage to be broadcast, and immediately attempt to spend the refund if CLTV has elapsed!
- Even worse, if Bob publishes the revoked state, Alice must have time to execute a justice remedy on the HTLC output!

To solve this, **BOLT #3 introduces 2nd-stage HTLC Transactions** (`HTLC-Success` and `HTLC-Timeout`):

- The commitment transaction's HTLC output can only be spent by the 2nd-stage transaction.
- The output of the 2nd-stage transaction is **itself encumbered by `to_self_delay` (CSV)**!
- This guarantees that even if a party claims an HTLC on-chain, their counterparty has an undisputed window to submit a justice penalty transaction if the state was revoked!

```mermaid
graph TD
    CommitmentTX["Commitment Transaction (L1)"]
    HTLCOutput["HTLC Output: 5,000 sat (P2WSH)"]
    
    CommitmentTX --> HTLCOutput
    
    subgraph SecondStage ["BOLT #3 2nd-Stage Resolution"]
        HTLC_Success["<b>HTLC-Success Transaction</b><br/>Spends with Preimage R<br/>nLockTime = 0"]
        HTLC_Timeout["<b>HTLC-Timeout Transaction</b><br/>Spends with Expiration CLTV<br/>nLockTime = Expiry"]
    end
    
    HTLCOutput -->|Fulfill Path| HTLC_Success
    HTLCOutput -->|Timeout Path| HTLC_Timeout

    RevocableOutput["<b>Revocable Output</b><br/>Encumbered by to_self_delay CSV<br/>Counterparty can sweep with Revocation Key!"]
    
    HTLC_Success --> RevocableOutput
    HTLC_Timeout --> RevocableOutput
```
