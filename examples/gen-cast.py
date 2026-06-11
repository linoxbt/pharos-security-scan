#!/usr/bin/env python3
"""
Generate an asciinema v2 .cast recording of the pharos-security-scan demo.

We don't depend on the `asciinema` binary: we run the real CLI commands, capture
their output, and emit the documented asciinema v2 format (a JSON header line
followed by [time, "o", data] event lines). The result plays on asciinema.org,
in the asciinema player, and embeds in the README.

Usage:  python3 examples/gen-cast.py > examples/demo.cast
"""
import json
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ANSI helpers
MAGENTA = "\x1b[1;35m"
CYAN = "\x1b[0;36m"
GREEN = "\x1b[1;32m"
RESET = "\x1b[0m"
RED = "\x1b[1;31m"
YELLOW = "\x1b[1;33m"

WIDTH, HEIGHT = 100, 34

events = []
clock = 0.0


def emit(text, dt=0.04):
    """Append an output event `dt` seconds after the previous one."""
    global clock
    clock += dt
    events.append([round(clock, 3), "o", text])


def type_line(text, prompt="$ "):
    """Simulate a human typing a command, char by char."""
    emit(GREEN + prompt + RESET, 0.3)
    for ch in text:
        emit(GREEN + ch + RESET, 0.012)
    emit("\r\n", 0.25)


def line(text, dt=0.06):
    emit(text + "\r\n", dt)


def run_json(args):
    out = subprocess.run(
        ["npx", "--no-install", "ts-node"] + args,
        cwd=ROOT, capture_output=True, text=True,
    )
    try:
        return json.loads(out.stdout).get("data", {})
    except Exception:
        sys.stderr.write(out.stdout + out.stderr)
        return {}


def verdict_color(v):
    return {"SAFE": GREEN, "CAUTION": YELLOW, "DANGER": RED, "CRITICAL": RED}.get(v, RESET)


def scene_scan(title, note, args, blurb_cmd):
    line("")
    line(MAGENTA + "────────────────────────────────────────────────────────" + RESET, 0.2)
    line(MAGENTA + "▶ " + title + RESET, 0.2)
    line(CYAN + note + RESET, 0.4)
    type_line(blurb_cmd)
    d = run_json(args)
    v = d.get("verdict", "?")
    score = (d.get("risk_score") or {}).get("total")
    line("  verdict : %s%s%s   (score %s)" % (verdict_color(v), v, RESET, score), 0.5)
    if d.get("summary"):
        line("  summary : " + d["summary"])
    if d.get("action_recommendation"):
        line("  action  : " + d["action_recommendation"])
    for f in d.get("flags", []):
        line("  flag    : " + f, 0.12)


def scene_memo(args, blurb_cmd):
    line("")
    line(MAGENTA + "────────────────────────────────────────────────────────" + RESET, 0.2)
    line(MAGENTA + "▶ Scene 4 — On-chain audit trail (pharos-onchain-memo)" + RESET, 0.2)
    line(CYAN + "Before acting, the Agent writes the verdict to Pharos (dry run)." + RESET, 0.4)
    type_line(blurb_cmd)
    d = run_json(args)
    line("  network      : %s (chainId %s)" % (d.get("network"), d.get("chainId")), 0.4)
    line("  content_hash : " + str(d.get("content_hash")))
    line("  data_hex     : " + (str(d.get("data_hex"))[:58] + "…"))
    line("  note         : " + str(d.get("note")))


# ── Title ──
line(CYAN + "pharos-security-scan — security guard for Pharos Agents" + RESET, 0.5)
line(CYAN + "Before an Agent trusts an address, it asks: is this SAFE?" + RESET, 0.6)

scene_scan(
    "Scene 1 — SAFE: USDC on Ethereum",
    "A legitimate token returns SAFE; the Agent proceeds.",
    ["src/index.ts", '{"address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","chain_id":"1","scan_type":"token"}'],
    "ts-node src/index.ts '{\"address\":\"0xA0b8…eB48\",\"chain_id\":\"1\",\"scan_type\":\"token\"}'",
)

scene_scan(
    "Scene 2 — CRITICAL: a sanctioned / theft-linked wallet",
    "GoPlus threat intel flags it. Verdict CRITICAL → the Agent ABORTS.",
    ["src/index.ts", '{"address":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","chain_id":"1","scan_type":"wallet"}'],
    "ts-node src/index.ts '{\"address\":\"0x098B…2f96\",\"chain_id\":\"1\",\"scan_type\":\"wallet\"}'",
)

scene_scan(
    "Scene 3 — Works natively ON Pharos (chain_id 1672)",
    "GoPlus indexes Pharos Mainnet, so the same scan runs on Pharos.",
    ["src/index.ts", '{"address":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","chain_id":"1672","scan_type":"wallet"}'],
    "ts-node src/index.ts '{\"address\":\"0x098B…2f96\",\"chain_id\":\"1672\",\"scan_type\":\"wallet\"}'",
)

scene_memo(
    ["src/memo.ts", '{"address":"0x098B716B8Aaf21512996dC57EB0615e2383E2f96","verdict":"CRITICAL","risk_score":100,"network":"mainnet"}'],
    "ts-node src/memo.ts '{\"address\":\"0x098B…2f96\",\"verdict\":\"CRITICAL\",\"network\":\"mainnet\"}'",
)

line("")
line(MAGENTA + "▶ One verdict. Any Agent can branch on it. Audit trail on Pharos." + RESET, 0.3)
line("")

header = {
    "version": 2,
    "width": WIDTH,
    "height": HEIGHT,
    "timestamp": 1781000000,
    "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
    "title": "pharos-security-scan demo",
}

out = [json.dumps(header)]
for ev in events:
    out.append(json.dumps(ev, ensure_ascii=False))
sys.stdout.write("\n".join(out) + "\n")
