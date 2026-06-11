---
name: pharos-security-scan
description: >
  This is the Pharos Skill that performs multi-layer security analysis on any EVM
  address using GoPlus Security APIs. Returns a structured risk report with a
  machine-readable verdict (SAFE / CAUTION / DANGER / CRITICAL) and a plain-English
  summary any agent can relay to a user or use for autonomous decision-making.
author: linoxbt
license: MIT
pharos_chain_id: "688688"
tags:
  - security
  - defi
  - risk
  - goplus
  - agent-safety
  - pharos
  - reusable
inputs:
  address:
    type: string
    required: true
    description: EVM wallet or contract address to scan (0x...)
  chain_id:
    type: string
    required: true
    description: Chain ID to scan on. Use "1" for Ethereum, "56" for BSC, or Pharos chain ID.
  scan_type:
    type: string
    required: true
    enum: [token, wallet, nft, auto]
    description: Type of scan. Use "auto" to let the Skill detect based on address type.
  include_approvals:
    type: boolean
    required: false
    default: false
    description: For wallet scans — also check risky token approvals.
outputs:
  verdict:
    type: string
    enum: [SAFE, CAUTION, DANGER, CRITICAL]
  risk_score:
    type: object
    description: Numerical score (0–100) with breakdown by category
  summary:
    type: string
    description: Plain English security summary for user-facing display
  action_recommendation:
    type: string
    description: What the calling Agent should do next based on verdict
  flags:
    type: array
    description: List of specific risk flags detected
  raw:
    type: object
    description: Raw GoPlus API response data for advanced agent use
---

# pharos-security-scan

## Overview

Before any Pharos Agent interacts with an unknown token, contract, or wallet address,
it should call this Skill. `pharos-security-scan` queries the GoPlus Security API —
the industry standard for Web3 security data — and returns a structured verdict any
agent can act on immediately without custom parsing logic.

## How Agents Use This Skill

### Step 1 — Trigger

Any agent that needs to interact with an unknown address calls:

```ts
pharos-security-scan({
  address: "0xTARGET_ADDRESS",
  chain_id: "CHAIN_ID",
  scan_type: "auto"
})
```

### Step 2 — Read Verdict

```ts
if (result.data.verdict === 'CRITICAL' || result.data.verdict === 'DANGER') {
  // ABORT — do not interact
  // Execute emergency exit if position exists
  // Alert user with result.data.summary
} else if (result.data.verdict === 'CAUTION') {
  // Notify user — proceed with reduced size
} else {
  // SAFE — proceed with transaction
}
```

### Step 3 — Log

Combine with `pharos-onchain-memo` Skill to write the scan verdict on-chain as
an audit trail before any significant transaction.

## Verdict Definitions

| Verdict  | Risk Score | Meaning                                           |
|----------|------------|---------------------------------------------------|
| SAFE     | 0–20       | No significant red flags detected                 |
| CAUTION  | 21–50      | Minor concerns — review before interacting        |
| DANGER   | 51–80      | Serious flags — do not interact without review    |
| CRITICAL | 81–100     | Honeypot or malicious — abort all interaction     |

## Scan Coverage

- Honeypot detection
- Mint/inflation functions
- Ownership reclaim risk
- Buy/sell tax analysis
- Unverified source code
- External call patterns
- Slippage manipulation
- Malicious address database (cybercrime, phishing, money laundering, darkweb)
- Token approval risk (wallet scan mode)

## Installation

```bash
npx skills add https://github.com/linoxbt/pharos-security-scan
```

Or install manually:

```bash
npm install pharos-security-scan
```

## Environment Variables

```bash
GOPLUS_API_KEY=your_key_here        # Optional — higher rate limits with auth
GOPLUS_API_SECRET=your_secret_here  # Optional
```

The Skill works without API credentials for standard rate limits (suitable for
development and moderate agent usage).

## Example Output

```json
{
  "success": true,
  "data": {
    "address": "0xabc...123",
    "chain_id": "1",
    "scan_type": "token",
    "verdict": "CRITICAL",
    "risk_score": {
      "total": 90,
      "breakdown": {
        "honeypot": 40,
        "ownership_risk": 25,
        "tax_risk": 20,
        "source_risk": 5,
        "holder_concentration": 0,
        "malicious_flags": 0
      }
    },
    "summary": "Address 0xabc...1 is flagged as CRITICAL risk. Do not interact. Likely malicious or honeypot.",
    "action_recommendation": "ABORT interaction. Trigger emergency exit if user has existing position. Log incident on-chain.",
    "flags": [
      "🚨 HONEYPOT DETECTED — cannot sell token",
      "⚠️ Owner can reclaim renounced ownership",
      "🚨 High sell tax: 99.0%"
    ]
  }
}
```

## Composability

This Skill is designed to be called by:

- **SentinelGuard Agent** — as the detection layer for real-time wallet monitoring
- **RWA Yield Scout Agent** — to verify vault contracts before rebalancing
- **PROS Paymaster Agent** — to validate destination contracts before gasless relay
- Any agent interacting with user funds on Pharos

## Data Source

All security data is provided by [GoPlus Security](https://gopluslabs.io/security-api) —
the industry's leading Web3 security intelligence platform, covering 1M+ tokens across
30+ chains. GoPlus is an official sponsor of the Pharos Skill-to-Agent Dual Cascade
Hackathon.
