import { pharosSecurityScan } from '../src/index';

async function main() {
  console.log('=== pharos-security-scan demo ===\n');

  // Test 1: Known safe token (USDC on Ethereum)
  console.log('Test 1: USDC on Ethereum (expected: SAFE)');
  const usdc = await pharosSecurityScan({
    address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    chain_id: '1',
    scan_type: 'token',
  });
  console.log(`Verdict: ${usdc.data?.verdict} | Score: ${usdc.data?.risk_score.total}`);
  console.log(`Summary: ${usdc.data?.summary}\n`);

  // Test 2: Wallet scan (vitalik.eth)
  console.log('Test 2: Wallet scan (expected: variable)');
  const wallet = await pharosSecurityScan({
    address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    chain_id: '1',
    scan_type: 'wallet',
    include_approvals: false,
  });
  console.log(`Verdict: ${wallet.data?.verdict} | Score: ${wallet.data?.risk_score.total}`);
  console.log(`Flags: ${wallet.data?.flags?.join(', ') || 'none'}\n`);

  // Test 3: BSC token
  console.log('Test 3: Token on BSC');
  const bscToken = await pharosSecurityScan({
    address: '0x64c37c3d6b5ff0fdea26eec0c8b6de487105291c',
    chain_id: '56',
    scan_type: 'token',
  });
  console.log(`Verdict: ${bscToken.data?.verdict} | Score: ${bscToken.data?.risk_score.total}`);
  console.log(`Flags:\n${bscToken.data?.flags?.map((f) => `  ${f}`).join('\n') || '  none'}\n`);
  console.log(`Action: ${bscToken.data?.action_recommendation}`);
}

main().catch(console.error);
