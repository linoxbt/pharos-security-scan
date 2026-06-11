/**
 * Unit tests for pharos-security-scan.
 *
 * Network access is mocked so tests are deterministic and run offline.
 */

jest.mock('axios');
import axios from 'axios';
import { pharosSecurityScan } from '../src/index';

const mockedAxios = axios as jest.Mocked<typeof axios>;

// `axios.create()` returns an instance; route its .get/.post to the mock too.
const instance: any = {
  get: jest.fn(),
  post: jest.fn(),
};
(mockedAxios.create as jest.Mock) = jest.fn(() => instance);

const ADDR = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';

beforeEach(() => {
  instance.get.mockReset();
  instance.post.mockReset();
});

describe('input validation', () => {
  test('rejects a malformed address', async () => {
    const res = await pharosSecurityScan({
      address: 'not-an-address',
      chain_id: '1',
      scan_type: 'token',
    });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/Invalid EVM address/);
  });

  test('rejects an invalid scan_type', async () => {
    const res = await pharosSecurityScan({
      address: ADDR,
      chain_id: '1',
      // @ts-expect-error testing an invalid value
      scan_type: 'bogus',
    });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/Invalid scan_type/);
  });
});

describe('token scan scoring', () => {
  test('clean token resolves to SAFE', async () => {
    instance.get.mockResolvedValueOnce({
      data: {
        result: {
          [ADDR.toLowerCase()]: {
            is_open_source: '1',
            is_honeypot: '0',
            buy_tax: '0',
            sell_tax: '0',
          },
        },
      },
    });
    const res = await pharosSecurityScan({ address: ADDR, chain_id: '1', scan_type: 'token' });
    expect(res.success).toBe(true);
    expect(res.data?.verdict).toBe('SAFE');
    expect(res.data?.risk_score.total).toBeLessThanOrEqual(20);
  });

  test('honeypot token resolves to CRITICAL', async () => {
    instance.get.mockResolvedValueOnce({
      data: {
        result: {
          [ADDR.toLowerCase()]: {
            is_open_source: '0',
            is_honeypot: '1',
            can_take_back_ownership: '1',
            sell_tax: '0.99',
            buy_tax: '0.1',
          },
        },
      },
    });
    const res = await pharosSecurityScan({ address: ADDR, chain_id: '1', scan_type: 'token' });
    expect(res.success).toBe(true);
    expect(res.data?.verdict).toBe('CRITICAL');
    expect(res.data?.flags).toEqual(
      expect.arrayContaining(['🚨 HONEYPOT DETECTED — cannot sell token']),
    );
  });
});

describe('wallet scan scoring', () => {
  test('sanctioned address flags malicious risk', async () => {
    instance.get.mockResolvedValueOnce({
      data: { result: { sanctioned: '1', cybercrime: '1' } },
    });
    const res = await pharosSecurityScan({ address: ADDR, chain_id: '1', scan_type: 'wallet' });
    expect(res.success).toBe(true);
    expect(res.data?.risk_score.breakdown.malicious_flags).toBeGreaterThan(0);
    expect(['DANGER', 'CRITICAL']).toContain(res.data?.verdict);
  });
});
