# pharos-security-scan

> Multi-layer EVM address security scanning for Pharos Agents — powered by GoPlus Security.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Pharos](https://img.shields.io/badge/Pharos-Skill-7C3AED.svg)](https://pharos.xyz)

## What is this

Autonomous agents cannot safely interact with unknown tokens, contracts, or wallets.
A single interaction with a honeypot, a malicious approval, or a sanctioned address
can drain user funds in one transaction. Agents need a fast, standardized way to ask
"is this address safe?" and get an answer they can branch on — without writing custom
parsing logic for every security feed.

`pharos-security-scan` is that layer. It queries the [GoPlus Security](https://gopluslabs.io/security-api)
API across multiple risk dimensions, normalizes the results into a single 0–100 risk
score, and returns a machine-readable verdict — `SAFE`, `CAUTION`, `DANGER`, or
`CRITICAL` — alongside a plain-English summary and a concrete `action_recommendation`.
Any Pharos Agent can call it as a guard before touching user funds.

## This repo ships two composable Pharos Skills

| Skill | What it does |
|-------|--------------|
| **pharos-security-scan** | Read-only risk scan of any EVM address → `SAFE`/`CAUTION`/`DANGER`/`CRITICAL` verdict |
| **pharos-onchain-memo** | Writes a verdict/decision to Pharos as a tamper-evident on-chain audit record |

Both follow the **Pharos Skill Engine** format (`SKILL.md` frontmatter + `assets/networks.json`),
and GoPlus supports **Pharos Mainnet (`1672`)** and **Pharos Testnet (`688688`)** natively — so
the scanner works on Pharos addresses, not just Ethereum/BSC.

## Dashboard UI

A premium web dashboard ships in the repo — paste an address, pick a network
(Pharos Mainnet / Testnet and more), and get a live verdict with an animated risk
gauge, per-category breakdown, severity-coded flags, and a one-click on-chain
audit-memo preview.

![Pharos Security Scan — result view](docs/screenshot-critical.png)

```bash
git clone https://github.com/linoxbt/pharos-security-scan.git
cd pharos-security-scan && npm install
npm run ui     # → http://localhost:4317
```

Scans are shareable via deep link: `/?address=0x…&chain=1672&type=wallet&run=1`.
The UI is a local/demo convenience and is **not** part of the published npm package.

## Installation

### As a Skill (recommended) — works today

```bash
npx skills add https://github.com/linoxbt/pharos-security-scan
```

This installs the skill to `~/.agents/skills/pharos-security-scan` for every agent
you select (Claude Code, Codex, Cursor, Cline, Gemini CLI, and more). You can also
manually place `skills/pharos-security-scan.md` (and `skills/pharos-onchain-memo.md`)
under your agent's skills directory (e.g. `~/.claude/skills/`).

### As a library / to run the CLI and demo

The package is not published to npm yet — clone and install from source:

```bash
git clone https://github.com/linoxbt/pharos-security-scan.git
cd pharos-security-scan
npm install          # installs deps incl. ts-node used by the CLI/demo
npm run build        # optional: emit dist/
```

> Note: `npm install pharos-security-scan` will 404 until it's published to npm.

## Demo

> Run these **from inside the cloned repo** (`cd pharos-security-scan`), after `npm install`.

```bash
npm run demo          # live 4-scene walkthrough: SAFE → CRITICAL → on Pharos → on-chain memo
```

Record it with Loom / OBS / QuickTime for a submission video. A pre-recorded
terminal session is also committed at [`examples/demo.cast`](examples/demo.cast)
(asciinema v2). To play or share it, install asciinema first:

```bash
sudo apt install asciinema            # or: snap install asciinema
asciinema play  examples/demo.cast    # local playback
asciinema upload examples/demo.cast   # -> shareable asciinema.org link for the submission
# regenerate from live output: npm run demo:cast
```

## Quick Start

> Installed from npm (once published) or via `npm link`, import by package name as
> below. Running from a clone, import the source instead: `from './src'`.

```ts
import { pharosSecurityScan } from 'pharos-security-scan';

const result = await pharosSecurityScan({
  address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  chain_id: '1',
  scan_type: 'auto',
});

if (result.success) {
  console.log(result.data.verdict);                // "SAFE"
  console.log(result.data.risk_score.total);       // 0
  console.log(result.data.action_recommendation);  // "Safe to proceed..."
}
```

Example output:

```json
{
  "success": true,
  "data": {
    "address": "0xabc...123",
    "chain_id": "1",
    "scan_type": "token",
    "verdict": "CRITICAL",
    "risk_score": { "total": 90, "breakdown": { "honeypot": 40, "ownership_risk": 25, "tax_risk": 20, "source_risk": 5, "holder_concentration": 0, "malicious_flags": 0 } },
    "summary": "Address 0xabc...123 is flagged as CRITICAL risk. Do not interact. Likely malicious or honeypot.",
    "action_recommendation": "ABORT interaction. Trigger emergency exit if user has existing position. Log incident on-chain.",
    "flags": ["🚨 HONEYPOT DETECTED — cannot sell token", "⚠️ Owner can reclaim renounced ownership", "🚨 High sell tax: 99.0%"]
  }
}
```

## Verdict System

| Verdict  | Score  | Meaning                                      | Recommended Agent Action                          |
|----------|--------|----------------------------------------------|---------------------------------------------------|
| SAFE     | 0–20   | No significant red flags detected            | Proceed with the intended transaction             |
| CAUTION  | 21–50  | Minor concerns — review before interacting   | Proceed with reduced size + explicit user notice  |
| DANGER   | 51–80  | Serious flags — review required              | Halt and escalate to user for manual review       |
| CRITICAL | 81–100 | Honeypot or malicious — abort                | Abort, trigger emergency exit, log on-chain       |

## Scan Coverage

- Honeypot detection (cannot sell / cannot buy / paused transfers)
- Mint / inflation functions
- Ownership reclaim & hidden-owner risk
- Self-destruct and proxy/upgradeability
- Buy / sell tax analysis
- Slippage & tax modifiability
- Unverified (non-open-source) code
- External call patterns
- Holder concentration
- Malicious address database — cybercrime, phishing, money laundering, sanctions, darkweb
- Token approval risk (wallet scan mode)

## API Reference

```ts
function pharosSecurityScan(input: ScanInput): Promise<ScanResult>;

interface ScanInput {
  address: string;            // EVM address (0x...) — required
  chain_id: string;           // "1" Ethereum, "56" BSC, "688688" Pharos — required
  scan_type: 'token' | 'wallet' | 'nft' | 'auto'; // required
  include_approvals?: boolean;// wallet scans only — default false
}

interface ScanResult {
  success: boolean;
  error?: string;             // present when success === false
  data?: {
    address: string;
    chain_id: string;
    scan_type: 'token' | 'wallet' | 'nft';
    verdict: 'SAFE' | 'CAUTION' | 'DANGER' | 'CRITICAL';
    risk_score: { total: number; breakdown: Record<string, number> };
    summary: string;
    action_recommendation: string;
    flags: string[];
    raw: Record<string, unknown>;
  };
}
```

**Input fields**

- `address` — the EVM address to scan. Validated against `0x[0-9a-fA-F]{40}`.
- `chain_id` — GoPlus-supported chain ID as a string.
- `scan_type` — `token`, `wallet`, `nft`, or `auto` (token-first, falls back to wallet).
- `include_approvals` — when scanning a wallet, also enumerate token approvals.

**Output fields**

- `verdict` — branch on this. Stable enum.
- `risk_score.total` — 0–100, clamped. `breakdown` shows per-category contribution.
- `summary` — user-facing one-liner.
- `action_recommendation` — what the agent should do next.
- `flags` — specific human-readable findings.
- `raw` — the underlying GoPlus payload for advanced use.

## Agent Integration Guide

Compose this Skill as a guard in front of any value-moving action:

```ts
// Guard pattern — call before interacting with an unknown address
async function safeInteract(agent, address, chainId) {
  const scan = await pharosSecurityScan({ address, chain_id: chainId, scan_type: 'auto' });

  if (!scan.success || scan.data.verdict === 'CRITICAL' || scan.data.verdict === 'DANGER') {
    await pharosOnchainMemo({ event: 'SCAN_BLOCKED', verdict: scan.data?.verdict, address }); // audit trail
    return agent.abort(scan.data?.summary ?? scan.error);
  }

  if (scan.data.verdict === 'CAUTION') {
    agent.reduceSize(0.5);
    agent.notifyUser(scan.data.summary);
  }

  return agent.proceed();
}
```

Designed to be called by **SentinelGuard**, **RWA Yield Scout**, **PROS Paymaster**,
and any agent interacting with user funds on Pharos.

## Environment Variables

| Variable             | Default                                       | Description                              |
|----------------------|-----------------------------------------------|------------------------------------------|
| `GOPLUS_API_KEY`     | _(unset)_                                     | Optional — raises GoPlus rate limits     |
| `GOPLUS_API_SECRET`  | _(unset)_                                     | Optional — paired with the API key       |
| `PHAROS_TESTNET_RPC` | `https://testnet.pharosnetwork.xyz/rpc`       | For future on-chain Skill extensions     |
| `PHAROS_CHAIN_ID`    | `688688`                                      | Pharos chain ID                          |

The Skill works without credentials at standard rate limits — suitable for development
and moderate agent usage.

## GoPlus Data Source

All security data is provided by [GoPlus Security](https://gopluslabs.io/security-api),
the industry's leading Web3 security intelligence platform, covering 1M+ tokens across
30+ chains. See the [GoPlus API docs](https://docs.gopluslabs.io/reference/api-overview).
GoPlus is an official sponsor of the Pharos Skill-to-Agent Dual Cascade Hackathon.

## Roadmap

- **v1.1**
  - ✅ On-chain audit trail via the `pharos-onchain-memo` skill (shipped in v1.0)
  - [CertiK](https://www.certik.com/) Skynet integration as a second risk source (also a hackathon sponsor)
  - Real-time streaming alerts for monitored addresses
  - A deployed Pharos memo-registry contract (indexed, queryable verdict history)

## License

MIT
