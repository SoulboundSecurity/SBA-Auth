// SPDX-License-Identifier: AGPL-3.0-only
/**
 * End-to-end SBA-Auth demonstration against a local anvil node.
 *
 * Flow: deploy the identity registry, set terms, enroll the admin wallet
 * (open enrollment), build the allowlist from the enrolled identity, start
 * the example server in-process, then exercise every path: session-gated
 * read, request-gated mutation, replay rejection, body-tamper rejection,
 * unenrolled-key rejection, and session revocation.
 *
 * Prereqs: `anvil` running on 127.0.0.1:8545, `forge build` done.
 * Run: npm run demo
 */

import { readFileSync } from 'node:fs';
import { createPublicClient, createWalletClient, http, keccak256, toBytes, zeroHash, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { createApp } from './server.js';
import { signSession, signRequest, bodyHashOf } from '../client/sba-client.js';

const RPC_URL = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
// anvil default accounts 0 (admin) and 1 (stranger)
const ADMIN_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as Hex;
const STRANGER_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as Hex;

const artifact = JSON.parse(
  readFileSync(new URL('../out/SoulboundAuthToken.sol/SoulboundAuthToken.json', import.meta.url), 'utf8'),
);

function check(name: string, pass: boolean) {
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) process.exitCode = 1;
}

async function main() {
  const admin = privateKeyToAccount(ADMIN_KEY);
  const stranger = privateKeyToAccount(STRANGER_KEY);
  const publicClient = createPublicClient({ chain: foundry, transport: http(RPC_URL) });
  const adminWallet = createWalletClient({ account: admin, chain: foundry, transport: http(RPC_URL) });
  const strangerWallet = createWalletClient({ account: stranger, chain: foundry, transport: http(RPC_URL) });

  // ── Deploy: open enrollment (no enrollment authority) ──────────────
  const deployHash = await adminWallet.deployContract({
    abi: artifact.abi,
    bytecode: artifact.bytecode.object as Hex,
    args: [admin.address, '0x0000000000000000000000000000000000000000'],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash: deployHash });
  const registry = receipt.contractAddress as Address;
  console.log(`registry deployed at ${registry}`);

  const eulaHash = keccak256(toBytes('SBA example terms v1'));
  await publicClient.waitForTransactionReceipt({
    hash: await adminWallet.writeContract({
      address: registry, abi: artifact.abi, functionName: 'setEulaHash', args: [eulaHash],
    }),
  });

  // ── Enroll the admin (gas-paying mint from the candidate key) ──────
  await publicClient.waitForTransactionReceipt({
    hash: await adminWallet.writeContract({
      address: registry, abi: artifact.abi, functionName: 'mintIdentity', args: [zeroHash, eulaHash, '0x'],
    }),
  });
  const identityId = (await publicClient.readContract({
    address: registry, abi: artifact.abi, functionName: 'identityOf', args: [admin.address],
  })) as Hex;
  console.log(`admin enrolled, identity ${identityId}`);

  // ── Server with the enrolled identity allowlisted ───────────────────
  const chainId = foundry.id;
  const { app, sessionAuth } = createApp({
    rpcUrl: RPC_URL, chainId, registry, allowlist: [identityId],
  });
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const addr = server.address();
  const base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`;

  const clientConfig = { chainId, verifyingContract: registry };

  // ── Session mode: read ──────────────────────────────────────────────
  const session = await signSession(adminWallet, admin, clientConfig);
  let res = await fetch(`${base}/admin/status`, { headers: { 'x-sba-session': session.header } });
  check('session-gated read authorizes the enrolled admin', res.status === 200);

  res = await fetch(`${base}/admin/status`);
  check('missing session header is denied', res.status === 403);

  const strangerSession = await signSession(strangerWallet, stranger, clientConfig);
  res = await fetch(`${base}/admin/status`, { headers: { 'x-sba-session': strangerSession.header } });
  check('valid signature from an unenrolled key is denied', res.status === 403);

  // ── Request mode: mutation, bound to method + path + body ──────────
  const body = JSON.stringify({ action: 'rotate-keys' });
  const signed = await signRequest(adminWallet, admin, clientConfig, {
    method: 'POST', path: '/admin/action', body,
  });
  res = await fetch(`${base}/admin/action`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-sba-request': signed.header },
    body,
  });
  check('request-gated mutation authorizes with a per-action signature', res.status === 200);

  res = await fetch(`${base}/admin/action`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-sba-request': signed.header },
    body,
  });
  check('replaying the same request signature is denied (single-use nonce)', res.status === 403);

  const signed2 = await signRequest(adminWallet, admin, clientConfig, {
    method: 'POST', path: '/admin/action', body,
  });
  const tampered = JSON.stringify({ action: 'drain-wallet' });
  res = await fetch(`${base}/admin/action`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-sba-request': signed2.header },
    body: tampered,
  });
  check('tampering with the body under a valid signature is denied', res.status === 403);
  check('sanity: tampered body hash differs', bodyHashOf(body) !== bodyHashOf(tampered));

  // ── Session revocation ──────────────────────────────────────────────
  sessionAuth.revoke(session.nonce);
  res = await fetch(`${base}/admin/status`, { headers: { 'x-sba-session': session.header } });
  check('revoked session is denied instantly', res.status === 403);

  server.close();
  console.log(process.exitCode ? 'DEMO FAILED' : 'DEMO COMPLETE: all checks passed');
}

main().catch((err) => { console.error(err); process.exit(1); });
