/**
 * pharos-security-scan — local dashboard server.
 *
 * A thin HTTP wrapper around the scan + memo skills, plus a static premium UI.
 * This is a repo/demo convenience (not part of the published npm package): it
 * lets you scan addresses and preview on-chain audit memos from the browser.
 *
 *   npm run ui   ->   http://localhost:4317
 */

import express, { Request, Response } from 'express';
import * as path from 'path';

import { pharosSecurityScan } from '../src/index';
import { pharosOnchainMemo } from '../src/memo';

const app = express();
const PORT = Number(process.env.PORT || 4317);

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// --- Security scan ---
app.post('/api/scan', async (req: Request, res: Response) => {
  try {
    const { address, chain_id, scan_type, include_approvals } = req.body ?? {};
    const result = await pharosSecurityScan({
      address: String(address ?? '').trim(),
      chain_id: String(chain_id ?? '').trim(),
      scan_type: scan_type ?? 'auto',
      include_approvals: Boolean(include_approvals),
    });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ success: false, error: String(err?.message ?? err) });
  }
});

// --- On-chain audit memo (dry run by default; broadcasts only if a key is set) ---
app.post('/api/memo', async (req: Request, res: Response) => {
  try {
    const { address, verdict, risk_score, summary, network } = req.body ?? {};
    const result = await pharosOnchainMemo({
      address: String(address ?? '').trim(),
      verdict,
      risk_score,
      summary,
      network: network ?? 'mainnet',
    });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ success: false, error: String(err?.message ?? err) });
  }
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`\n  ◈ pharos-security-scan dashboard → http://localhost:${PORT}\n`);
});
