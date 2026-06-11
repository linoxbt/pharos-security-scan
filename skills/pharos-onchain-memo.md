---
name: pharos-onchain-memo
description: >
  Writes a tamper-evident audit record to the Pharos chain (atlantic-testnet or
  mainnet). Pair it with pharos-security-scan so an Agent leaves a permanent,
  verifiable on-chain trail of every security verdict it acted on before moving
  user funds. The record is carried in the calldata of a 0-value transaction —
  no dedicated contract to deploy. Invoke whenever an Agent needs to log a
  decision, verdict, or event on Pharos as proof.
author: linoxbt
license: MIT
pharos_networks:
  - atlantic-testnet
  - mainnet
tags:
  - audit
  - logging
  - pharos
  - agent-safety
  - on-chain
  - reusable
inputs:
  address:
    type: string
    required: true
    description: The address the record is about (the scanned subject, 0x...).
  verdict:
    type: string
    required: true
    enum: [SAFE, CAUTION, DANGER, CRITICAL]
    description: The verdict being recorded.
  risk_score:
    type: number
    required: false
    description: Optional 0–100 score to embed in the record.
  summary:
    type: string
    required: false
    description: Optional human summary to embed.
  network:
    type: string
    required: false
    enum: [atlantic-testnet, mainnet]
    default: atlantic-testnet
    description: Pharos network to write to.
  to:
    type: string
    required: false
    description: Recipient of the memo tx. Defaults to the sender's own address.
outputs:
  sent:
    type: boolean
    description: true if broadcast, false for a dry run (no key configured).
  tx_hash:
    type: string
    description: Transaction hash (when sent).
  explorer_url:
    type: string
    description: Pharosscan link to the memo transaction (when sent).
  content_hash:
    type: string
    description: keccak256 fingerprint of the record's calldata.
  data_hex:
    type: string
    description: The exact calldata carried by the memo transaction.
---

# pharos-onchain-memo

## Overview

`pharos-onchain-memo` turns an Agent decision into a permanent on-chain record.
It encodes a compact JSON record into the `data` field of a 0-value transaction
and broadcasts it to Pharos — so there is nothing to deploy and the record is
retrievable forever from the transaction itself.

Its primary use is as the **audit layer** for [`pharos-security-scan`](./pharos-security-scan.md):
before an Agent acts on a `CRITICAL` / `DANGER` verdict (or proceeds on `SAFE`),
it writes the verdict on-chain, creating proof of *why* it did what it did.

## Composition with pharos-security-scan

```ts
import { pharosSecurityScan, pharosOnchainMemo } from 'pharos-security-scan';

const scan = await pharosSecurityScan({ address, chain_id: '1672', scan_type: 'auto' });

// Leave an on-chain audit trail of the verdict before acting on it.
await pharosOnchainMemo({
  address,
  verdict: scan.data!.verdict,
  risk_score: scan.data!.risk_score.total,
  summary: scan.data!.summary,
  network: 'mainnet',
});

if (scan.data!.verdict === 'CRITICAL' || scan.data!.verdict === 'DANGER') {
  // abort — but the reason is now provable on-chain
}
```

## Networks

Configuration mirrors the Pharos Skill Engine `assets/networks.json`:

| Network          | chainId | RPC                                   | Native | Explorer                       |
|------------------|---------|---------------------------------------|--------|--------------------------------|
| atlantic-testnet | 688689  | https://atlantic.dplabs-internal.com  | PHRS   | https://atlantic.pharosscan.xyz |
| mainnet          | 1672    | https://rpc.pharos.xyz                | PROS   | https://www.pharosscan.xyz      |

Default network is `atlantic-testnet`, matching the Engine default.

## Dry run vs broadcast

- **No private key** → DRY RUN: returns the exact `data_hex`, target `chainId`, and
  `content_hash` without sending anything. Safe to run with no funds; ideal for
  previews and tests.
- **`PHAROS_PRIVATE_KEY` (or `PRIVATE_KEY`) set** → broadcasts the memo tx and
  returns `tx_hash` + `explorer_url`.

## Environment Variables

```bash
PHAROS_PRIVATE_KEY=0x...   # required only to broadcast (else dry run)
# PRIVATE_KEY=0x...        # also accepted, matching the Pharos Skill Engine
```

> ⚠️ Never commit a private key. Use an env var and a throwaway funded key on testnet.

## CLI

```bash
# Dry run (no key) — prints the calldata an Agent would broadcast
npx ts-node src/memo.ts '{"address":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","verdict":"CRITICAL","risk_score":100,"network":"atlantic-testnet"}'
```

## Example Output (dry run)

```json
{
  "success": true,
  "data": {
    "sent": false,
    "network": "atlantic-testnet",
    "chainId": 688689,
    "to": "0x0000000000000000000000000000000000000000",
    "payload": "{\"std\":\"pharos-security-scan\",\"ver\":\"1\",\"subject\":\"0x098B...2f96\",\"verdict\":\"CRITICAL\",\"ts\":1700000000,\"score\":100}",
    "data_hex": "0x7b22...",
    "content_hash": "0x…64 hex…",
    "note": "DRY RUN — no private key. Set PHAROS_PRIVATE_KEY (or pass privateKey) to broadcast."
  }
}
```
