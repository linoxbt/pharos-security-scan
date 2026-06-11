#!/usr/bin/env bash
#
# pharos-security-scan — live demo
#
# A 4-scene walkthrough you can run in any terminal (and record with Loom / OBS /
# QuickTime / asciinema). Shows SAFE -> CRITICAL contrast, a live scan ON Pharos,
# and the on-chain audit-memo composition.
#
# Usage:  bash examples/demo.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

RUN="npx --no-install ts-node"
PAUSE="${DEMO_PAUSE:-2}"   # seconds between scenes; set DEMO_PAUSE=0 to go fast

banner() { printf '\n\033[1;35m%s\033[0m\n' "────────────────────────────────────────────────────────"; printf '\033[1;35m▶ %s\033[0m\n' "$1"; }
say()    { printf '\033[0;36m%s\033[0m\n' "$1"; }
cmd()    { printf '\033[1;32m$ %s\033[0m\n' "$1"; }

# Pretty-print just the fields that matter for a demo.
summarize() {
  python3 -c "
import sys,json
d=json.load(sys.stdin).get('data') or {}
print('  verdict : %s   (score %s)' % (d.get('verdict'), (d.get('risk_score') or {}).get('total')))
if d.get('summary'): print('  summary : %s' % d['summary'])
if d.get('action_recommendation'): print('  action  : %s' % d['action_recommendation'])
for f in d.get('flags',[]): print('  flag    : %s' % f)
"
}

clear || true
say "pharos-security-scan — security guard for Pharos Agents"
say "Before an Agent trusts an address, it asks: is this SAFE?"
sleep "$PAUSE"

banner "Scene 1 — SAFE: USDC on Ethereum"
say "A legitimate token returns SAFE; the Agent proceeds."
cmd "ts-node src/index.ts '{\"address\":\"0xA0b8...eB48\",\"chain_id\":\"1\",\"scan_type\":\"token\"}'"
$RUN src/index.ts '{"address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","chain_id":"1","scan_type":"token"}' | summarize
sleep "$PAUSE"

banner "Scene 2 — CRITICAL: a sanctioned / theft-linked wallet"
say "GoPlus threat intel flags it. Verdict CRITICAL -> the Agent ABORTS."
cmd "ts-node src/index.ts '{\"address\":\"0x098B...2f96\",\"chain_id\":\"1\",\"scan_type\":\"wallet\"}'"
$RUN src/index.ts '{"address":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","chain_id":"1","scan_type":"wallet"}' | summarize
sleep "$PAUSE"

banner "Scene 3 — Works natively ON Pharos (chain_id 1672)"
say "GoPlus indexes Pharos Mainnet, so the same scan runs on Pharos addresses."
cmd "ts-node src/index.ts '{\"address\":\"0x098B...2f96\",\"chain_id\":\"1672\",\"scan_type\":\"wallet\"}'"
$RUN src/index.ts '{"address":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","chain_id":"1672","scan_type":"wallet"}' | summarize
sleep "$PAUSE"

banner "Scene 4 — On-chain audit trail (pharos-onchain-memo)"
say "Before acting, the Agent writes the verdict to Pharos (dry run shown)."
cmd "ts-node src/memo.ts '{\"address\":\"0x098B...2f96\",\"verdict\":\"CRITICAL\",\"risk_score\":100,\"network\":\"mainnet\"}'"
$RUN src/memo.ts '{"address":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","verdict":"CRITICAL","risk_score":100,"network":"mainnet"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; print('  network      :', d['network'], '(chainId %s)'%d['chainId']); print('  content_hash :', d['content_hash']); print('  note         :', d['note'])"
sleep "$PAUSE"

banner "Done"
say "One verdict. Any Agent can branch on it. Audit trail on Pharos."
