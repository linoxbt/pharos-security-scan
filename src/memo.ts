#!/usr/bin/env node
/**
 * pharos-onchain-memo
 *
 * Writes a tamper-evident audit record to the Pharos chain. Pair it with
 * `pharos-security-scan` to create an on-chain trail of every security verdict
 * an Agent acted on — before it moves user funds.
 *
 * The memo is encoded into the calldata (`data`) of a 0-value transaction, so
 * it works without deploying a dedicated contract: the record lives in the
 * transaction itself and is permanently retrievable from the chain.
 *
 * Network config mirrors the Pharos Skill Engine's assets/networks.json so the
 * two skills agree on RPC endpoints, chain IDs, and explorers.
 */

import { JsonRpcProvider, Wallet, keccak256, toUtf8Bytes, hexlify, ZeroAddress } from 'ethers';
import * as dotenv from 'dotenv';

import { Verdict } from './types';

dotenv.config();

export type PharosNetworkName = 'atlantic-testnet' | 'mainnet';

interface PharosNetwork {
  name: PharosNetworkName;
  rpcUrl: string;
  chainId: number;
  explorerUrl: string;
  nativeToken: string;
}

/** Matches PharosNetwork Skill Engine assets/networks.json (v0.1.0). */
export const PHAROS_NETWORKS: Record<PharosNetworkName, PharosNetwork> = {
  'atlantic-testnet': {
    name: 'atlantic-testnet',
    rpcUrl: 'https://atlantic.dplabs-internal.com',
    chainId: 688689,
    explorerUrl: 'https://atlantic.pharosscan.xyz/',
    nativeToken: 'PHRS',
  },
  mainnet: {
    name: 'mainnet',
    rpcUrl: 'https://rpc.pharos.xyz',
    chainId: 1672,
    explorerUrl: 'https://www.pharosscan.xyz/',
    nativeToken: 'PROS',
  },
};

export interface MemoInput {
  /** The address the verdict is about (the scanned subject). */
  address: string;
  /** The verdict being recorded. */
  verdict: Verdict;
  /** Optional 0–100 risk score to embed. */
  risk_score?: number;
  /** Optional human summary to embed. */
  summary?: string;
  /** Pharos network to write to. Defaults to "atlantic-testnet" (Engine default). */
  network?: PharosNetworkName;
  /** Recipient of the memo tx. Defaults to the sender's own address. */
  to?: string;
  /** Unix seconds for the record. Defaults to now. */
  timestamp?: number;
  /** Private key. Defaults to env PHAROS_PRIVATE_KEY || PRIVATE_KEY. Omit for a dry run. */
  privateKey?: string;
  /** Override RPC URL (else taken from the network config). */
  rpcUrl?: string;
}

export interface MemoData {
  /** true if a transaction was broadcast; false for a dry run (no key). */
  sent: boolean;
  network: PharosNetworkName;
  chainId: number;
  to: string;
  /** Human-readable JSON record that was encoded. */
  payload: string;
  /** Hex calldata carried by the memo transaction. */
  data_hex: string;
  /** keccak256 of the calldata — a stable fingerprint of the record. */
  content_hash: string;
  /** Present when sent === true. */
  tx_hash?: string;
  /** Present when sent === true. */
  explorer_url?: string;
  note: string;
}

export interface MemoResult {
  success: boolean;
  data?: MemoData;
  error?: string;
}

const MEMO_STD = 'pharos-security-scan';
const MEMO_VER = '1';

function isHexAddress(addr: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(addr);
}

/**
 * Build (and optionally broadcast) an on-chain audit memo for a scan verdict.
 *
 * Without a private key this performs a DRY RUN: it returns the exact calldata,
 * target chain, and content hash an Agent would broadcast — safe to run with no
 * funds and useful for previews and tests.
 */
export async function pharosOnchainMemo(input: MemoInput): Promise<MemoResult> {
  const {
    address,
    verdict,
    risk_score,
    summary,
    network = 'atlantic-testnet',
    to,
    timestamp,
    rpcUrl,
  } = input ?? ({} as MemoInput);

  if (!address || !isHexAddress(address)) {
    return { success: false, error: `Invalid subject address: ${address ?? '(missing)'}` };
  }
  const net = PHAROS_NETWORKS[network];
  if (!net) {
    return { success: false, error: `Unknown network: ${network}` };
  }
  if (to && !isHexAddress(to)) {
    return { success: false, error: `Invalid recipient address: ${to}` };
  }

  // Build the canonical record. Keys are short to keep calldata small.
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const record: Record<string, unknown> = {
    std: MEMO_STD,
    ver: MEMO_VER,
    subject: address,
    verdict,
    ts,
  };
  if (typeof risk_score === 'number') record.score = risk_score;
  if (summary) record.summary = summary;

  const payload = JSON.stringify(record);
  const data_hex = hexlify(toUtf8Bytes(payload));
  const content_hash = keccak256(data_hex);

  const privateKey = input.privateKey ?? process.env.PHAROS_PRIVATE_KEY ?? process.env.PRIVATE_KEY;

  // --- Dry run (no key) ---
  if (!privateKey) {
    return {
      success: true,
      data: {
        sent: false,
        network,
        chainId: net.chainId,
        to: to ?? ZeroAddress,
        payload,
        data_hex,
        content_hash,
        note:
          'DRY RUN — no private key. Set PHAROS_PRIVATE_KEY (or pass privateKey) to broadcast. ' +
          'Calldata above is ready to send to any recipient as a 0-value memo tx.',
      },
    };
  }

  // --- Broadcast ---
  try {
    const provider = new JsonRpcProvider(rpcUrl ?? net.rpcUrl, net.chainId);
    const wallet = new Wallet(privateKey, provider);
    const recipient = to ?? wallet.address;

    const tx = await wallet.sendTransaction({
      to: recipient,
      value: 0n,
      data: data_hex,
    });
    await tx.wait(1);

    return {
      success: true,
      data: {
        sent: true,
        network,
        chainId: net.chainId,
        to: recipient,
        payload,
        data_hex,
        content_hash,
        tx_hash: tx.hash,
        explorer_url: `${net.explorerUrl.replace(/\/$/, '')}/tx/${tx.hash}`,
        note: `Audit memo written to Pharos ${network}.`,
      },
    };
  } catch (err: any) {
    const msg = String(err?.shortMessage ?? err?.message ?? err);
    let friendly = msg;
    if (/insufficient funds/i.test(msg)) {
      friendly = `Insufficient ${net.nativeToken} balance to write the memo on ${network}.`;
    } else if (/could not detect network|ECONNREFUSED|ENOTFOUND|timeout/i.test(msg)) {
      friendly = `Could not reach Pharos ${network} RPC (${rpcUrl ?? net.rpcUrl}).`;
    }
    return { success: false, error: `Memo broadcast failed: ${friendly}` };
  }
}

export default pharosOnchainMemo;

// ---------------------------------------------------------------------------
// CLI: ts-node src/memo.ts '{"address":"0x...","verdict":"CRITICAL","network":"atlantic-testnet"}'
// ---------------------------------------------------------------------------

if (require.main === module) {
  const arg = process.argv[2];
  if (!arg) {
    console.error(
      'Usage: ts-node src/memo.ts \'{"address":"0x...","verdict":"CRITICAL","risk_score":90}\'',
    );
    process.exit(1);
  }
  let parsed: MemoInput;
  try {
    parsed = JSON.parse(arg) as MemoInput;
  } catch {
    console.error('Argument must be valid JSON matching MemoInput.');
    process.exit(1);
  }
  pharosOnchainMemo(parsed)
    .then((res) => {
      console.log(JSON.stringify(res, null, 2));
      process.exit(res.success ? 0 : 2);
    })
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
