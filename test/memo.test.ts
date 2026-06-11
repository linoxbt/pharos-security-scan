/**
 * Unit tests for pharos-onchain-memo (dry-run path — no network, no key).
 */

import { pharosOnchainMemo, PHAROS_NETWORKS } from '../src/memo';

const SUBJECT = '0x098B716B8Aaf21512996dC57EB0615e2383E2f96';

describe('pharos-onchain-memo (dry run)', () => {
  test('rejects an invalid subject address', async () => {
    const res = await pharosOnchainMemo({ address: 'nope', verdict: 'CRITICAL' });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/Invalid subject address/);
  });

  test('rejects an unknown network', async () => {
    const res = await pharosOnchainMemo({
      address: SUBJECT,
      verdict: 'SAFE',
      // @ts-expect-error testing an invalid value
      network: 'bitcoin',
    });
    expect(res.success).toBe(false);
  });

  test('produces deterministic calldata + content hash for a fixed record', async () => {
    const res = await pharosOnchainMemo({
      address: SUBJECT,
      verdict: 'CRITICAL',
      risk_score: 100,
      summary: 'sanctioned + stealing_attack',
      timestamp: 1_700_000_000,
    });
    expect(res.success).toBe(true);
    expect(res.data?.sent).toBe(false);
    expect(res.data?.chainId).toBe(PHAROS_NETWORKS['atlantic-testnet'].chainId);
    expect(res.data?.content_hash).toMatch(/^0x[0-9a-f]{64}$/);
    // Same input -> same calldata, every time.
    const again = await pharosOnchainMemo({
      address: SUBJECT,
      verdict: 'CRITICAL',
      risk_score: 100,
      summary: 'sanctioned + stealing_attack',
      timestamp: 1_700_000_000,
    });
    expect(again.data?.data_hex).toBe(res.data?.data_hex);
    expect(again.data?.content_hash).toBe(res.data?.content_hash);
  });

  test('targets mainnet (chainId 1672) when requested', async () => {
    const res = await pharosOnchainMemo({
      address: SUBJECT,
      verdict: 'DANGER',
      network: 'mainnet',
    });
    expect(res.data?.network).toBe('mainnet');
    expect(res.data?.chainId).toBe(1672);
  });
});
