---
name: pharos-security-scan
description: >
  REQUIRED before any Pharos Agent interacts with an unknown token, contract, or
  wallet. Runs multi-layer security analysis on any EVM address via the GoPlus
  Security API and returns a machine-readable verdict (SAFE / CAUTION / DANGER /
  CRITICAL) with a 0–100 risk score, plain-English summary, and a concrete action
  recommendation. Invoke whenever an Agent is about to send funds to, swap with,
  approve, or otherwise trust an address on Pharos (chainId 1672 / 688688) or any
  GoPlus-supported chain — especially before using the Pharos Skill Engine's
  send-transaction, contract-write, or approval capabilities. Pairs with
  pharos-onchain-memo to write the verdict on-chain as an audit trail.
version: 1.0.0
license: MIT
requires:
  anyBins:
    - node
---

# Pharos Security Scan

A guard skill for Pharos Agents. Before an Agent trusts an unknown address, it
calls `pharos-security-scan`, reads a single `verdict`, and decides whether to
proceed, reduce size, or abort — no custom parsing of security feeds required.

Security data is provided by **GoPlus Security**, which supports **Pharos Mainnet
(1672)** and **Pharos Testnet (688688)** natively, plus 40+ other chains.

## Prerequisites

- **Node.js** (≥ 18). Run `node --version` to confirm.
- Install dependencies once: `npm install`
- Optional `GOPLUS_API_KEY` / `GOPLUS_API_SECRET` for higher rate limits (works
  without them at standard limits).

## Capability Index

| User Need | Capability | How |
|-----------|------------|-----|
| Is this token safe to buy/swap? | Token honeypot/tax/ownership scan | `scan_type: "token"` |
| Is this wallet/contract malicious? | Threat-intel scan (sanctions, phishing, theft…) | `scan_type: "wallet"` |
| Is this NFT collection risky? | NFT contract scan | `scan_type: "nft"` |
| I don't know the address type | Auto-detect (token-first, falls back to wallet) | `scan_type: "auto"` |
| Also check risky approvals | Wallet approvals enumeration | `scan_type: "wallet", include_approvals: true` |

## Usage

The Agent runs the CLI and reads the JSON result. Once published to npm, no clone
is needed — `npx` fetches and runs it:

```bash
# Scan (auto-detects token vs wallet)
npx pharos-security-scan '{"address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","chain_id":"1672","scan_type":"auto"}'

# Write the verdict on-chain (dry run unless PHAROS_PRIVATE_KEY is set)
npx pharos-onchain-memo '{"address":"0x...","verdict":"CRITICAL","risk_score":100,"network":"mainnet"}'
```

```bash
# From a clone (no npm needed): npx ts-node src/index.ts '<json>'
# As a library: const { pharosSecurityScan } = require('pharos-security-scan')
```

The Agent branches on `result.data.verdict`:

```ts
switch (result.data.verdict) {
  case 'CRITICAL':
  case 'DANGER':   return abort(result.data.summary);          // do not interact
  case 'CAUTION':  return proceedReduced(result.data.summary); // reduced size + notify
  default:         return proceed();                           // SAFE
}
```

## Verdict System

| Verdict  | Score  | Agent Action                                      |
|----------|--------|---------------------------------------------------|
| SAFE     | 0–20   | Proceed                                           |
| CAUTION  | 21–50  | Reduced size + notify user                        |
| DANGER   | 51–80  | Halt, escalate to user                            |
| CRITICAL | 81–100 | Abort, emergency exit, log on-chain               |

## Composition

Combine with [`pharos-onchain-memo`](skills/pharos-onchain-memo.md) to write the
verdict to Pharos before acting — a provable audit trail of every Agent decision.

See `skills/pharos-security-scan.md` for the full input/output schema, scan
coverage, and example outputs.

## Network Configuration

Pharos network details (RPC, chainId, explorer) are in `assets/networks.json`,
mirroring the Pharos Skill Engine.

## Error Handling

| Scenario | Signature | Handling |
|----------|-----------|----------|
| Invalid address | `Invalid EVM address` | Check 0x + 40 hex chars |
| Unsupported scan type | `Invalid scan_type` | Use token / wallet / nft / auto |
| GoPlus unreachable / rate-limited | `Scan failed: GoPlus API error <code>` | Retry; add API key for higher limits |
| No token data for address | flag: "No token security data" | Address may be a wallet — use `auto` |

## Security

This skill is **read-only** for scanning (no keys, no writes). Only the paired
`pharos-onchain-memo` skill performs writes, and only when a private key is
explicitly configured.
