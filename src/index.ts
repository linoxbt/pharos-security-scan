#!/usr/bin/env node
/**
 * pharos-security-scan
 *
 * A reusable Pharos Skill that performs multi-layer security analysis on any
 * EVM address using the GoPlus Security API and returns a structured,
 * machine-readable verdict (SAFE / CAUTION / DANGER / CRITICAL) plus a
 * plain-English summary any agent can relay or act on.
 *
 * Entry point: `pharosSecurityScan(input)`.
 */

import axios, { AxiosInstance } from 'axios';
import { createHash } from 'crypto';
import * as dotenv from 'dotenv';

import {
  ScanInput,
  ScanResult,
  ScanData,
  ScanType,
  Verdict,
  RiskBreakdown,
  RiskScore,
} from './types';

dotenv.config();

const GOPLUS_BASE = 'https://api.gopluslabs.io/api';
const REQUEST_TIMEOUT_MS = 20_000;

/** Per-category caps so a single dimension can't dominate the 0–100 scale. */
const CATEGORY_CAPS: RiskBreakdown = {
  honeypot: 40,
  ownership_risk: 25,
  tax_risk: 20,
  source_risk: 10,
  holder_concentration: 10,
  // Threat-intel hits are high-confidence and are the only signal in a wallet
  // scan, so this dimension is allowed to dominate the full 0–100 range.
  malicious_flags: 100,
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** GoPlus encodes booleans as the strings "1" / "0". */
function isFlag(v: unknown): boolean {
  return v === '1' || v === 1 || v === true;
}

/** Parse GoPlus tax/percent strings ("0.99") into a percentage number (99). */
function toPercent(v: unknown): number {
  const n = parseFloat(String(v ?? ''));
  if (!isFinite(n)) return 0;
  return n * 100;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

function isHexAddress(addr: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(addr);
}

function verdictFromScore(total: number): Verdict {
  if (total >= 81) return 'CRITICAL';
  if (total >= 51) return 'DANGER';
  if (total >= 21) return 'CAUTION';
  return 'SAFE';
}

// ---------------------------------------------------------------------------
// GoPlus client (optional auth for higher rate limits)
// ---------------------------------------------------------------------------

let cachedAccessToken: { token: string; expires: number } | null = null;

async function getAccessToken(http: AxiosInstance): Promise<string | null> {
  const key = process.env.GOPLUS_API_KEY;
  const secret = process.env.GOPLUS_API_SECRET;
  if (!key || !secret) return null;

  // Reuse a still-valid token to avoid signing on every call.
  const now = Math.floor(Date.now() / 1000);
  if (cachedAccessToken && cachedAccessToken.expires - 60 > now) {
    return cachedAccessToken.token;
  }

  // sign = sha1(app_key + time + app_secret)
  const time = now;
  const sign = createHash('sha1').update(`${key}${time}${secret}`).digest('hex');

  try {
    const res = await http.post(`${GOPLUS_BASE}/v1/token`, {
      app_key: key,
      time,
      sign,
    });
    const token = res.data?.result?.access_token as string | undefined;
    const expiresAt = res.data?.result?.expires_in as number | undefined;
    if (token) {
      cachedAccessToken = {
        token,
        expires: expiresAt ?? now + 3600,
      };
      return token;
    }
  } catch {
    // Auth is best-effort: fall back to unauthenticated (standard) rate limits.
  }
  return null;
}

function makeClient(): AxiosInstance {
  return axios.create({
    timeout: REQUEST_TIMEOUT_MS,
    headers: { Accept: 'application/json' },
  });
}

async function authHeaders(http: AxiosInstance): Promise<Record<string, string>> {
  const token = await getAccessToken(http);
  return token ? { Authorization: token } : {};
}

// ---------------------------------------------------------------------------
// Scorers — each returns its category contribution and pushes human flags
// ---------------------------------------------------------------------------

function scoreToken(
  data: Record<string, any>,
  breakdown: RiskBreakdown,
  flags: string[],
): void {
  // --- Honeypot / tradeability ---
  if (isFlag(data.is_honeypot)) {
    breakdown.honeypot += 40;
    flags.push('🚨 HONEYPOT DETECTED — cannot sell token');
  }
  if (isFlag(data.cannot_sell_all)) {
    breakdown.honeypot += 30;
    flags.push('🚨 Holders cannot sell their full balance');
  }
  if (isFlag(data.cannot_buy)) {
    breakdown.honeypot += 15;
    flags.push('⚠️ Token cannot be bought (trading restricted)');
  }
  if (isFlag(data.transfer_pausable)) {
    breakdown.honeypot += 10;
    flags.push('⚠️ Transfers can be paused by owner');
  }
  if (isFlag(data.trading_cooldown)) {
    breakdown.honeypot += 5;
    flags.push('⚠️ Trading cooldown enforced');
  }

  // --- Ownership / control ---
  if (isFlag(data.can_take_back_ownership)) {
    breakdown.ownership_risk += 25;
    flags.push('⚠️ Owner can reclaim renounced ownership');
  }
  if (isFlag(data.hidden_owner)) {
    breakdown.ownership_risk += 20;
    flags.push('⚠️ Hidden owner detected');
  }
  if (isFlag(data.owner_change_balance)) {
    breakdown.ownership_risk += 20;
    flags.push('🚨 Owner can arbitrarily change balances');
  }
  if (isFlag(data.selfdestruct)) {
    breakdown.ownership_risk += 15;
    flags.push('🚨 Contract can self-destruct');
  }
  if (isFlag(data.is_mintable)) {
    breakdown.ownership_risk += 10;
    flags.push('⚠️ Token supply is mintable');
  }
  if (isFlag(data.is_proxy)) {
    breakdown.ownership_risk += 5;
    flags.push('ℹ️ Contract is a proxy (upgradeable logic)');
  }

  // --- Taxes / slippage ---
  const sellTax = toPercent(data.sell_tax);
  const buyTax = toPercent(data.buy_tax);
  if (sellTax >= 50) {
    breakdown.tax_risk += 20;
    flags.push(`🚨 High sell tax: ${sellTax.toFixed(1)}%`);
  } else if (sellTax >= 10) {
    breakdown.tax_risk += 10;
    flags.push(`⚠️ Elevated sell tax: ${sellTax.toFixed(1)}%`);
  }
  if (buyTax >= 50) {
    breakdown.tax_risk += 15;
    flags.push(`🚨 High buy tax: ${buyTax.toFixed(1)}%`);
  } else if (buyTax >= 10) {
    breakdown.tax_risk += 7;
    flags.push(`⚠️ Elevated buy tax: ${buyTax.toFixed(1)}%`);
  }
  if (isFlag(data.slippage_modifiable)) {
    breakdown.tax_risk += 5;
    flags.push('⚠️ Tax/slippage is modifiable by owner');
  }

  // --- Source code ---
  if (data.is_open_source !== undefined && !isFlag(data.is_open_source)) {
    breakdown.source_risk += 10;
    flags.push('⚠️ Source code is not verified / open');
  }
  if (isFlag(data.external_call)) {
    breakdown.source_risk += 3;
    flags.push('ℹ️ Contract makes external calls');
  }

  // --- Holder concentration ---
  const ownerPercent = toPercent(data.owner_percent) / 100; // already a fraction in API
  const creatorPercent = toPercent(data.creator_percent) / 100;
  const topHolder = Math.max(ownerPercent, creatorPercent);
  if (topHolder >= 50) {
    breakdown.holder_concentration += 10;
    flags.push(`⚠️ High holder concentration: ${topHolder.toFixed(1)}% held by owner/creator`);
  } else if (topHolder >= 20) {
    breakdown.holder_concentration += 5;
    flags.push(`ℹ️ Notable holder concentration: ${topHolder.toFixed(1)}%`);
  }

  // --- Reputation flags surfaced by token endpoint ---
  if (isFlag(data.is_blacklisted)) {
    breakdown.malicious_flags += 20;
    flags.push('🚨 Token has a blacklist function');
  }
}

const ADDRESS_RISK_FIELDS: Array<{ key: string; weight: number; label: string }> = [
  // High-confidence threat-intel designations — a single hit is CRITICAL.
  { key: 'cybercrime', weight: 85, label: '🚨 Linked to cybercrime' },
  { key: 'money_laundering', weight: 85, label: '🚨 Linked to money laundering' },
  { key: 'financial_crime', weight: 85, label: '🚨 Linked to financial crime' },
  { key: 'phishing_activities', weight: 85, label: '🚨 Linked to phishing activity' },
  { key: 'stealing_attack', weight: 85, label: '🚨 Linked to theft / stealing attacks' },
  { key: 'sanctioned', weight: 85, label: '🚨 Address is sanctioned' },
  // Serious associations — DANGER on a single hit.
  { key: 'darkweb_transactions', weight: 60, label: '🚨 Darkweb transaction history' },
  { key: 'blackmail_activities', weight: 60, label: '🚨 Linked to blackmail activity' },
  { key: 'honeypot_related_address', weight: 40, label: '⚠️ Associated with honeypot contracts' },
  { key: 'fake_kyc', weight: 30, label: '⚠️ Fake KYC association' },
  { key: 'malicious_mining_activities', weight: 20, label: '⚠️ Malicious mining activity' },
  { key: 'mixer', weight: 20, label: '⚠️ Funds routed through a mixer' },
  { key: 'gas_abuse', weight: 15, label: '⚠️ Gas abuse detected' },
  { key: 'blacklist_doubt', weight: 15, label: '⚠️ Appears on blacklist watchlists' },
];

function scoreAddress(
  data: Record<string, any>,
  breakdown: RiskBreakdown,
  flags: string[],
): void {
  for (const { key, weight, label } of ADDRESS_RISK_FIELDS) {
    if (isFlag(data[key])) {
      breakdown.malicious_flags += weight;
      flags.push(label);
    }
  }
  const created = parseInt(String(data.number_of_malicious_contracts_created ?? '0'), 10);
  if (created > 0) {
    breakdown.malicious_flags += Math.min(30, created * 10);
    flags.push(`🚨 Created ${created} known malicious contract(s)`);
  }
}

// ---------------------------------------------------------------------------
// Network fetchers
// ---------------------------------------------------------------------------

async function fetchTokenSecurity(
  http: AxiosInstance,
  chainId: string,
  address: string,
): Promise<Record<string, any> | null> {
  const headers = await authHeaders(http);
  const url = `${GOPLUS_BASE}/v1/token_security/${chainId}`;
  const res = await http.get(url, {
    params: { contract_addresses: address },
    headers,
  });
  const result = res.data?.result ?? {};
  const entry = result[address.toLowerCase()] ?? result[address];
  return entry && Object.keys(entry).length > 0 ? entry : null;
}

async function fetchAddressSecurity(
  http: AxiosInstance,
  chainId: string,
  address: string,
): Promise<Record<string, any>> {
  const headers = await authHeaders(http);
  const url = `${GOPLUS_BASE}/v1/address_security/${address}`;
  const res = await http.get(url, {
    params: { chain_id: chainId },
    headers,
  });
  return res.data?.result ?? {};
}

async function fetchNftSecurity(
  http: AxiosInstance,
  chainId: string,
  address: string,
): Promise<Record<string, any> | null> {
  const headers = await authHeaders(http);
  const url = `${GOPLUS_BASE}/v1/nft_security/${chainId}`;
  const res = await http.get(url, {
    params: { contract_addresses: address },
    headers,
  });
  const result = res.data?.result ?? {};
  const entry = result[address.toLowerCase()] ?? result[address] ?? result;
  return entry && Object.keys(entry).length > 0 ? entry : null;
}

async function fetchApprovals(
  http: AxiosInstance,
  chainId: string,
  address: string,
): Promise<Record<string, any> | null> {
  const headers = await authHeaders(http);
  const url = `${GOPLUS_BASE}/v2/token_approval_security/${chainId}`;
  try {
    const res = await http.get(url, {
      params: { addresses: address },
      headers,
    });
    return res.data?.result ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Summary / recommendation
// ---------------------------------------------------------------------------

function shortAddr(addr: string): string {
  return `${addr.slice(0, 6)}...${addr.slice(-3)}`;
}

function buildSummary(addr: string, verdict: Verdict, flagCount: number): string {
  const a = shortAddr(addr);
  switch (verdict) {
    case 'CRITICAL':
      return `Address ${a} is flagged as CRITICAL risk. Do not interact. Likely malicious or honeypot.`;
    case 'DANGER':
      return `Address ${a} is flagged as DANGER (${flagCount} serious issue(s)). Do not interact without manual review.`;
    case 'CAUTION':
      return `Address ${a} shows CAUTION-level concerns (${flagCount} flag(s)). Review before interacting and consider reducing size.`;
    default:
      return `Address ${a} appears SAFE — no significant red flags detected.`;
  }
}

function buildRecommendation(verdict: Verdict): string {
  switch (verdict) {
    case 'CRITICAL':
      return 'ABORT interaction. Trigger emergency exit if user has existing position. Log incident on-chain.';
    case 'DANGER':
      return 'Do NOT proceed automatically. Halt and escalate to user for manual review.';
    case 'CAUTION':
      return 'Proceed only with reduced position size and explicit user awareness of the flags.';
    default:
      return 'Safe to proceed with the intended transaction.';
  }
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

export async function pharosSecurityScan(input: ScanInput): Promise<ScanResult> {
  const { address, chain_id, scan_type, include_approvals } = input ?? ({} as ScanInput);

  // --- Validate ---
  if (!address || !isHexAddress(address)) {
    return { success: false, error: `Invalid EVM address: ${address ?? '(missing)'}` };
  }
  if (!chain_id) {
    return { success: false, error: 'chain_id is required' };
  }
  const allowed: ScanType[] = ['token', 'wallet', 'nft', 'auto'];
  if (!scan_type || !allowed.includes(scan_type)) {
    return { success: false, error: `Invalid scan_type: ${scan_type ?? '(missing)'}` };
  }

  const http = makeClient();
  const breakdown: RiskBreakdown = {
    honeypot: 0,
    ownership_risk: 0,
    tax_risk: 0,
    source_risk: 0,
    holder_concentration: 0,
    malicious_flags: 0,
  };
  const flags: string[] = [];
  const raw: Record<string, unknown> = {};

  let resolvedType: Exclude<ScanType, 'auto'>;

  try {
    if (scan_type === 'token') {
      resolvedType = 'token';
      const token = await fetchTokenSecurity(http, chain_id, address);
      if (!token) {
        flags.push('ℹ️ No token security data returned (may not be a token contract)');
      } else {
        raw.token_security = token;
        scoreToken(token, breakdown, flags);
      }
    } else if (scan_type === 'nft') {
      resolvedType = 'nft';
      const nft = await fetchNftSecurity(http, chain_id, address);
      if (!nft) {
        flags.push('ℹ️ No NFT security data returned for this address');
      } else {
        raw.nft_security = nft;
        // NFT endpoint shares several token-style flags; reuse the token scorer.
        scoreToken(nft, breakdown, flags);
      }
    } else if (scan_type === 'wallet') {
      resolvedType = 'wallet';
      const addr = await fetchAddressSecurity(http, chain_id, address);
      raw.address_security = addr;
      scoreAddress(addr, breakdown, flags);
      if (include_approvals) {
        const approvals = await fetchApprovals(http, chain_id, address);
        if (approvals) {
          raw.approvals = approvals;
          const list = Array.isArray(approvals) ? approvals : [];
          if (list.length > 0) {
            flags.push(`ℹ️ ${list.length} token approval(s) found — review for risky spenders`);
          }
        }
      }
    } else {
      // auto — try token first, fall back to wallet/address security
      const token = await fetchTokenSecurity(http, chain_id, address);
      if (token) {
        resolvedType = 'token';
        raw.token_security = token;
        scoreToken(token, breakdown, flags);
      } else {
        resolvedType = 'wallet';
        const addr = await fetchAddressSecurity(http, chain_id, address);
        raw.address_security = addr;
        scoreAddress(addr, breakdown, flags);
      }
    }
  } catch (err: any) {
    const detail = err?.response?.status
      ? `GoPlus API error ${err.response.status}`
      : err?.message ?? 'unknown error';
    return { success: false, error: `Scan failed: ${detail}` };
  }

  // --- Clamp categories and total ---
  (Object.keys(breakdown) as Array<keyof RiskBreakdown>).forEach((k) => {
    breakdown[k] = clamp(breakdown[k], 0, CATEGORY_CAPS[k]);
  });
  const total = clamp(
    Object.values(breakdown).reduce((a, b) => a + b, 0),
    0,
    100,
  );

  const verdict = verdictFromScore(total);
  const risk_score: RiskScore = { total, breakdown };

  const data: ScanData = {
    address,
    chain_id,
    scan_type: resolvedType,
    verdict,
    risk_score,
    summary: buildSummary(address, verdict, flags.filter((f) => !f.startsWith('ℹ️')).length),
    action_recommendation: buildRecommendation(verdict),
    flags,
    raw,
  };

  return { success: true, data };
}

export default pharosSecurityScan;
export * from './types';
export { pharosOnchainMemo, PHAROS_NETWORKS } from './memo';
export type { MemoInput, MemoResult, MemoData, PharosNetworkName } from './memo';

// ---------------------------------------------------------------------------
// CLI entry: `ts-node src/index.ts '{"address":"0x...","chain_id":"1","scan_type":"token"}'`
// ---------------------------------------------------------------------------

if (require.main === module) {
  const arg = process.argv[2];
  if (!arg) {
    console.error(
      'Usage: ts-node src/index.ts \'{"address":"0x...","chain_id":"1","scan_type":"auto"}\'',
    );
    process.exit(1);
  }
  let parsed: ScanInput;
  try {
    parsed = JSON.parse(arg) as ScanInput;
  } catch {
    console.error('Argument must be valid JSON matching ScanInput.');
    process.exit(1);
  }
  pharosSecurityScan(parsed)
    .then((res) => {
      console.log(JSON.stringify(res, null, 2));
      process.exit(res.success ? 0 : 2);
    })
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
