/**
 * pharos-security-scan — type definitions
 *
 * These types form the machine-readable contract that any Pharos Agent can
 * depend on. The `ScanResult` returned by `pharosSecurityScan` is stable and
 * versioned so agents can branch on `data.verdict` without parsing free text.
 */

/** Type of scan to perform. "auto" lets the Skill infer based on address shape/data. */
export type ScanType = 'token' | 'wallet' | 'nft' | 'auto';

/** Machine-readable risk verdict. Agents should branch on this value. */
export type Verdict = 'SAFE' | 'CAUTION' | 'DANGER' | 'CRITICAL';

/** Input to the Skill. Mirrors the `inputs` block in skills/pharos-security-scan.md. */
export interface ScanInput {
  /** EVM wallet or contract address to scan (0x...). */
  address: string;
  /** Chain ID to scan on. "1" = Ethereum, "56" = BSC, "688688" = Pharos, etc. */
  chain_id: string;
  /** Type of scan. Use "auto" to let the Skill detect based on address data. */
  scan_type: ScanType;
  /** For wallet scans — also check risky token approvals. Defaults to false. */
  include_approvals?: boolean;
}

/** Per-category risk contribution. All values are 0..N and sum into `total`. */
export interface RiskBreakdown {
  honeypot: number;
  ownership_risk: number;
  tax_risk: number;
  source_risk: number;
  holder_concentration: number;
  malicious_flags: number;
}

/** Numerical risk score (0–100) with a per-category breakdown. */
export interface RiskScore {
  /** Clamped 0–100 total. Drives the verdict. */
  total: number;
  breakdown: RiskBreakdown;
}

/** The structured, agent-consumable payload. */
export interface ScanData {
  address: string;
  chain_id: string;
  /** The scan type that was actually performed (resolved from "auto"). */
  scan_type: Exclude<ScanType, 'auto'>;
  verdict: Verdict;
  risk_score: RiskScore;
  /** Plain-English summary suitable for user-facing display. */
  summary: string;
  /** What the calling Agent should do next based on the verdict. */
  action_recommendation: string;
  /** Specific, human-readable risk flags detected during the scan. */
  flags: string[];
  /** Raw GoPlus API response for advanced agent use. */
  raw: Record<string, unknown>;
}

/** Top-level result envelope. `success: false` carries an `error` string. */
export interface ScanResult {
  success: boolean;
  data?: ScanData;
  error?: string;
}
