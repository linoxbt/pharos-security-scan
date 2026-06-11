/**
 * Live Pharos example — scan on Pharos, then leave an on-chain audit memo.
 *
 * Run: npx ts-node examples/pharos-scan.ts
 *
 * GoPlus indexes Pharos Mainnet under chain_id "1672", so the scanner works on
 * Pharos addresses directly. The memo step is a DRY RUN unless PHAROS_PRIVATE_KEY
 * is set, so this is safe to run with no funds.
 */

import { pharosSecurityScan, pharosOnchainMemo } from '../src/index';

const PHAROS_MAINNET = '1672';

async function main() {
  console.log('=== pharos-security-scan — live on Pharos Mainnet (1672) ===\n');

  // A known sanctioned / theft-linked address (flagged by GoPlus threat intel).
  const target = '0x098B716B8Aaf21512996dC57EB0615e2383E2f96';

  console.log(`Scanning ${target} on Pharos (chain_id ${PHAROS_MAINNET})...`);
  const scan = await pharosSecurityScan({
    address: target,
    chain_id: PHAROS_MAINNET,
    scan_type: 'wallet',
  });

  if (!scan.success || !scan.data) {
    console.error('Scan failed:', scan.error);
    return;
  }

  console.log(`\nVerdict:  ${scan.data.verdict} (score ${scan.data.risk_score.total})`);
  console.log(`Summary:  ${scan.data.summary}`);
  console.log(`Action:   ${scan.data.action_recommendation}`);
  if (scan.data.flags.length) {
    console.log('Flags:');
    scan.data.flags.forEach((f) => console.log(`  ${f}`));
  }

  // --- Composition: write the verdict to Pharos as a tamper-evident audit record ---
  console.log('\n--- Writing on-chain audit memo (pharos-onchain-memo) ---');
  const memo = await pharosOnchainMemo({
    address: target,
    verdict: scan.data.verdict,
    risk_score: scan.data.risk_score.total,
    summary: scan.data.summary,
    network: 'mainnet',
  });

  if (memo.success && memo.data) {
    console.log(`sent:         ${memo.data.sent}`);
    console.log(`network:      ${memo.data.network} (chainId ${memo.data.chainId})`);
    console.log(`content_hash: ${memo.data.content_hash}`);
    if (memo.data.sent) {
      console.log(`tx:           ${memo.data.explorer_url}`);
    } else {
      console.log(`note:         ${memo.data.note}`);
    }
  } else {
    console.error('Memo failed:', memo.error);
  }
}

main().catch(console.error);
