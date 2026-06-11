---
name: pharos-onchain-memo
description: >
  Writes a tamper-evident audit record to the Pharos chain (atlantic-testnet or
  mainnet). Invoke whenever an Agent needs to log a decision, verdict, scan
  result, or event on Pharos as permanent proof — for example before moving user
  funds, after a security scan, or to record any on-chain attestation. The record
  is carried in the calldata of a 0-value transaction, so there is no contract to
  deploy. Pairs with pharos-security-scan to create an on-chain trail of every
  security verdict an Agent acted on.
version: 1.0.0
license: MIT
requires:
  anyBins:
    - node
---

# Pharos On-chain Memo

Turns an Agent decision into a permanent, verifiable on-chain record. The memo is
encoded into the `data` field of a 0-value transaction and broadcast to Pharos —
nothing to deploy, and the record is retrievable forever from the transaction.

## Prerequisites

- **Node.js** (≥ 18). Install once: `npm install -g pharos-security-scan` (ships
  the `pharos-onchain-memo` binary), or run via `npx` (below).
- To **broadcast** (not just preview), set a funded key:
  `export PHAROS_PRIVATE_KEY=0x...` (or `PRIVATE_KEY`, matching the Skill Engine).

## Usage

```bash
# Dry run (no key) — prints the exact calldata + content hash, sends nothing
npx pharos-onchain-memo '{"address":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","verdict":"CRITICAL","risk_score":100,"network":"mainnet"}'

# Broadcast — set PHAROS_PRIVATE_KEY first, then run the same command
```

The Agent reads `data.sent`, `data.tx_hash`, and `data.explorer_url` from the JSON.

## Networks

Mirrors the Pharos Skill Engine `assets/networks.json`:

| Network          | chainId | RPC                                  | Native | Explorer                        |
|------------------|---------|--------------------------------------|--------|---------------------------------|
| atlantic-testnet | 688689  | https://atlantic.dplabs-internal.com | PHRS   | https://atlantic.pharosscan.xyz |
| mainnet          | 1672    | https://rpc.pharos.xyz               | PROS   | https://www.pharosscan.xyz      |

Default network is `atlantic-testnet`.

## Inputs

| Field        | Required | Notes                                                        |
|--------------|----------|--------------------------------------------------------------|
| `address`    | yes      | Subject the record is about (0x + 40 hex).                   |
| `verdict`    | yes      | `SAFE` / `CAUTION` / `DANGER` / `CRITICAL`.                  |
| `risk_score` | no       | 0–100 score to embed.                                        |
| `summary`    | no       | Human summary to embed.                                      |
| `network`    | no       | `atlantic-testnet` (default) or `mainnet`.                   |
| `to`         | no       | Memo recipient; defaults to the sender's own address.        |

## Composition with pharos-security-scan

Scan first, then write the verdict on-chain before acting:

```bash
V=$(npx pharos-security-scan '{"address":"0xTARGET","chain_id":"1672","scan_type":"auto"}')
# extract verdict from $V, then:
npx pharos-onchain-memo '{"address":"0xTARGET","verdict":"CRITICAL","network":"mainnet"}'
```

## Security

- **Never** expose a private key in logs, chat, or version control. Use
  `PHAROS_PRIVATE_KEY` and a throwaway funded key on testnet.
- Mainnet writes spend real `PROS` gas — confirm the network before broadcasting.
- Without a key the skill is a safe **dry run** (no transaction is sent).

## Error Handling

| Scenario | Signature | Handling |
|----------|-----------|----------|
| Invalid subject/recipient | `Invalid … address` | Check 0x + 40 hex chars |
| RPC unreachable | `Could not reach Pharos … RPC` | Retry; verify network |
| No gas | `Insufficient … balance` | Fund the sender on the target network |
