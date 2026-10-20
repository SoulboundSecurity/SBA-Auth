// SPDX-License-Identifier: AGPL-3.0-only
/**
 * End-to-end SBA-Auth demonstration and rejection matrix against a local
 * anvil node.
 *
 * Flow: deploy the identity registry, set terms, enroll two keys under
 * open enrollment (one allowlisted, one not), start the example server
 * in-process, then exercise every acceptance and rejection path the
 * specification claims. Each check names the SPEC.md section or audit
 * finding it demonstrates. Exit code is non-zero on any FAIL.
 *
 * Prereqs: `anvil` running on 127.0.0.1:8545, `forge build` done.
 * Run: npm run demo
 */

import { readFileSync } from 'node:fs';
import express from 'express';
import { createPublicClient, createWalletClient, http, keccak256, toBytes, zeroHash, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { createApp, EXAMPLE_PURPOSE, summarize } from './server.js';
import { signSession, signRequest, bodyHashOf } from '../client/sba-client.js';
import {
  sbaSessionAuth,
  sbaRequestAuth,
  deriveIdentityLocal,
  SBA_DEFAULTS,
  SBA_SESSION_TYPES,
  SBA_REQUEST_TYPES,
} from '../server/sba-auth.js';

const RPC_URL = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
// anvil default accounts 0 (admin, allowlisted), 1 (stranger, enrolled but
// not allowlisted), 2 (outsider, never enrolled)
const ADMIN_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as Hex;
const STRANGER_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as Hex;
const OUTSIDER_KEY = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' as Hex;

const artifact = JSON.parse(
  readFileSync(new URL('../out/SoulboundAuthToken.sol/SoulboundAuthToken.json', import.meta.url), 'utf8'),
);

let passed = 0;
let failed = 0;
function check(name: string, pass: boolean) {
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  pass ? passed++ : failed++;
}
function throws(fn: () => unknown): boolean {
  try { fn(); return false; } catch { return true; }
}
function encode(payload: Record<string, string>, signature: Hex): string {
  return Buffer.from(JSON.stringify({ payload, signature }), 'utf8').toString('base64');
}
async function listen(app: express.Express): Promise<{ base: string; close: () => void }> {
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return { base: `http://127.0.0.1:${port}`, close: () => server.close() };
}

async function main() {
  const admin = privateKeyToAccount(ADMIN_KEY);
  const stranger = privateKeyToAccount(STRANGER_KEY);
  const outsider = privateKeyToAccount(OUTSIDER_KEY);
  const publicClient = createPublicClient({ chain: foundry, transport: http(RPC_URL) });
  const adminWallet = createWalletClient({ account: admin, chain: foundry, transport: http(RPC_URL) });
  const strangerWallet = createWalletClient({ account: stranger, chain: foundry, transport: http(RPC_URL) });
  const outsiderWallet = createWalletClient({ account: outsider, chain: foundry, transport: http(RPC_URL) });

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

  // ── Enroll admin and stranger (gas-paying mints from the candidate keys)
  for (const wallet of [adminWallet, strangerWallet]) {
    await publicClient.waitForTransactionReceipt({
      hash: await wallet.writeContract({
        address: registry, abi: artifact.abi, functionName: 'mintIdentity', args: [zeroHash, eulaHash, '0x'],
      }),
    });
  }
  const identityId = (await publicClient.readContract({
    address: registry, abi: artifact.abi, functionName: 'identityOf', args: [admin.address],
  })) as Hex;
  console.log(`admin enrolled, identity ${identityId}; stranger enrolled, not allowlisted`);
  check('SPEC 2: on-chain identity equals the local derivation',
    identityId.toLowerCase() === deriveIdentityLocal(admin.address, 'SBA_SALT_V1', foundry.id).toLowerCase());

  // ── Server with only the admin identity allowlisted ─────────────────
  const chainId = foundry.id;
  const { app, sessionAuth } = createApp({ rpcUrl: RPC_URL, chainId, registry, allowlist: [identityId] });
  const main = await listen(app);

  const cfg = { chainId, verifyingContract: registry, purpose: EXAMPLE_PURPOSE };
  const domain: { name: string; version: string; chainId: number; verifyingContract: Address } =
    { name: SBA_DEFAULTS.domainName, version: SBA_DEFAULTS.domainVersion, chainId, verifyingContract: registry };
  const get = (path: string, header?: string) =>
    fetch(`${main.base}${path}`, { headers: header ? { 'x-sba-session': header } : {} }).then((r) => r.status);
  const post = (path: string, header: string, body?: string) =>
    fetch(`${main.base}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-sba-request': header },
      body,
    }).then((r) => r.status);
  /** Sign an arbitrary session payload (for expiry and domain tests). */
  const rawSession = async (payload: Record<string, string>, dom = domain) =>
    encode(payload, await adminWallet.signTypedData({ account: admin, domain: dom, types: SBA_SESSION_TYPES, primaryType: 'SbaSession', message: payload as never }));
  /** Sign an arbitrary request payload (for freshness and binding tests). */
  const rawRequest = async (payload: Record<string, string>) =>
    encode(payload, await adminWallet.signTypedData({ account: admin, domain, types: SBA_REQUEST_TYPES, primaryType: 'SbaRequest', message: payload as never }));
  const nonce = () => Math.random().toString(16).slice(2);

  // ═══ Session mode ═══════════════════════════════════════════════════
  const session = await signSession(adminWallet, admin, cfg);
  check('session: enrolled + allowlisted admin is authorized', await get('/admin/status', session.header) === 200);
  check('session: missing envelope is denied', await get('/admin/status') === 403);
  const outsiderSession = await signSession(outsiderWallet, outsider, cfg);
  check('session: valid signature from a never-enrolled key is denied', await get('/admin/status', outsiderSession.header) === 403);
  const strangerSession = await signSession(strangerWallet, stranger, cfg);
  check('session: enrolled but not allowlisted key is denied (SPEC 3 tail)', await get('/admin/status', strangerSession.header) === 403);
  const wrongPurpose = await signSession(adminWallet, admin, { ...cfg, purpose: 'Some Other Service' });
  check('session: wrong purpose is denied (V-01: purpose is the audience)', await get('/admin/status', wrongPurpose.header) === 403);
  const wrongContract = await signSession(adminWallet, admin, { ...cfg, verifyingContract: admin.address });
  check('session: signature for another verifyingContract is denied (SPEC 3 domain)', await get('/admin/status', wrongContract.header) === 403);
  const wrongChain = await signSession(adminWallet, admin, { ...cfg, chainId: 1 });
  check('session: signature for another chainId is denied (SPEC 3 domain)', await get('/admin/status', wrongChain.header) === 403);
  const expired = await rawSession({ purpose: EXAMPLE_PURPOSE, nonce: nonce(), validUntil: new Date(Date.now() - 1000).toISOString() });
  check('session: expired validUntil is denied, no grace (SPEC 9)', await get('/admin/status', expired) === 403);
  const tooLong = await rawSession({ purpose: EXAMPLE_PURPOSE, nonce: nonce(), validUntil: new Date(Date.now() + SBA_DEFAULTS.sessionWindowMs + 120_000).toISOString() });
  check('session: validUntil beyond window + 60 s is denied (SPEC 9)', await get('/admin/status', tooLong) === 403);
  const v1Domain = await rawSession({ purpose: EXAMPLE_PURPOSE, nonce: nonce(), validUntil: new Date(Date.now() + 60_000).toISOString() }, { ...domain, version: '1' });
  check('session: a v1-format envelope does not verify against the v2 domain', await get('/admin/status', v1Domain) === 403);

  // ═══ Request mode ═══════════════════════════════════════════════════
  const body = JSON.stringify({ action: 'rotate-keys' });
  const summary = summarize(JSON.parse(body));
  const signed = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body, summary });
  check('request: per-action signature with matching summary is authorized', await post('/admin/action', signed.header, body) === 200);
  check('request: replaying the same envelope is denied (single-use nonce)', await post('/admin/action', signed.header, body) === 403);

  const signed2 = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body, summary });
  const tampered = JSON.stringify({ action: 'drain-wallet' });
  check('request: body tampered after signing is denied (bodyHash)', await post('/admin/action', signed2.header, tampered) === 403);
  check('sanity: tampered body hash differs', bodyHashOf(body) !== bodyHashOf(tampered));

  const lyingSummary = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body: tampered, summary: summarize({ action: 'rotate-keys' }) });
  check('request: summary that does not describe the body is denied (V-04: the signer sees what executes)', await post('/admin/action', lyingSummary.header, tampered) === 403);
  const emptySummary = await rawRequest({ purpose: EXAMPLE_PURPOSE, method: 'POST', path: '/admin/action', bodyHash: bodyHashOf(body), summary: '', nonce: nonce(), issuedAt: new Date().toISOString() });
  check('request: empty summary is denied (absence never passes a gate)', await post('/admin/action', emptySummary, body) === 403);

  const wrongMethod = await signRequest(adminWallet, admin, cfg, { method: 'PUT', path: '/admin/action', body, summary });
  check('request: method mismatch is denied', await post('/admin/action', wrongMethod.header, body) === 403);
  const wrongPath = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/other', body, summary });
  check('request: path mismatch is denied', await post('/admin/action', wrongPath.header, body) === 403);
  const noQuery = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body, summary });
  check('request: unsigned query string is denied (V-02: the full URL is bound)', await post('/admin/action?to=attacker&amount=1000000', noQuery.header, body) === 403);
  const withQuery = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action?dry=1', body, summary });
  check('request: signed query string is accepted exactly as signed', await post('/admin/action?dry=1', withQuery.header, body) === 200);
  const mountedFull = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/console/action', body, summary });
  check('request: mounted router, signature over the full original URL is accepted (V-02)', await post('/console/action', mountedFull.header, body) === 200);
  const mountedBare = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/action', body, summary });
  check('request: mounted router, signature over the mount-relative path is denied (V-02)', await post('/console/action', mountedBare.header, body) === 403);

  const stale = await rawRequest({ purpose: EXAMPLE_PURPOSE, method: 'POST', path: '/admin/action', bodyHash: bodyHashOf(body), summary, nonce: nonce(), issuedAt: new Date(Date.now() - 120_000).toISOString() });
  check('request: issuedAt older than requestMaxAgeMs is denied (SPEC 9)', await post('/admin/action', stale, body) === 403);
  const future = await rawRequest({ purpose: EXAMPLE_PURPOSE, method: 'POST', path: '/admin/action', bodyHash: bodyHashOf(body), summary, nonce: nonce(), issuedAt: new Date(Date.now() + 120_000).toISOString() });
  check('request: issuedAt more than 60 s in the future is denied (SPEC 9)', await post('/admin/action', future, body) === 403);
  const wrongPurposeReq = await signRequest(adminWallet, admin, { ...cfg, purpose: 'Some Other Service' }, { method: 'POST', path: '/admin/action', body, summary });
  check('request: wrong purpose is denied (V-01)', await post('/admin/action', wrongPurposeReq.header, body) === 403);
  const strangerReq = await signRequest(strangerWallet, stranger, cfg, { method: 'POST', path: '/admin/action', body, summary });
  check('request: enrolled but not allowlisted key is denied', await post('/admin/action', strangerReq.header, body) === 403);

  // ═══ Raw-body capture (V-09) ════════════════════════════════════════
  {
    const noCapture = createApp({ rpcUrl: RPC_URL, chainId, registry, allowlist: [identityId], captureRawBody: false });
    const srv = await listen(noCapture.app);
    const post2 = (header: string, body?: string) =>
      fetch(`${srv.base}/admin/action`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-sba-request': header }, body }).then((r) => r.status);
    const emptySig = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body: '', summary: summarize({}) });
    check('request: no raw-body capture, empty-body signature, attacker body is denied (V-09)', await post2(emptySig.header, '{"action":"drain-wallet"}') === 403);
    const emptySig2 = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body: '', summary: summarize({}) });
    check('request: no raw-body capture, bodyless request with empty-body signature is accepted', await post2(emptySig2.header, undefined) === 200);
    const nonEmptySig = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body, summary });
    check('request: no raw-body capture, signature over a body carried in the request is denied', await post2(nonEmptySig.header, body) === 403);
    srv.close();
  }

  // ═══ Nonce cache is fail-closed at capacity (V-05) ══════════════════
  {
    const tiny = createApp({ rpcUrl: RPC_URL, chainId, registry, allowlist: [identityId], nonceCacheMax: 2 });
    const srv = await listen(tiny.app);
    const post3 = (header: string) =>
      fetch(`${srv.base}/admin/action`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-sba-request': header }, body }).then((r) => r.status);
    const first = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body, summary });
    const second = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body, summary });
    const third = await signRequest(adminWallet, admin, cfg, { method: 'POST', path: '/admin/action', body, summary });
    const results = [await post3(first.header), await post3(second.header), await post3(third.header)];
    check('request: nonceCacheMax 2, third live request is refused rather than evicting a live nonce (V-05)', JSON.stringify(results) === JSON.stringify([200, 200, 403]));
    check('request: the first nonce is still single-use after the refusal', await post3(first.header) === 403);
    srv.close();
  }

  // ═══ Lying registry (SPEC 3 tail, V-03) ═════════════════════════════
  {
    const lying = sbaSessionAuth({
      chainId, verifyingContract: registry, purpose: EXAMPLE_PURPOSE,
      predicate: async () => ({ identityId }),
      deriveIdentity: (a) => deriveIdentityLocal(a, 'SBA_SALT_V1', chainId),
      allowlist: [identityId],
    });
    const lyingApp = express();
    lyingApp.get('/x', lying, (_req, res) => { res.json({ ok: true }); });
    const srv = await listen(lyingApp);
    const res = await fetch(`${srv.base}/x`, { headers: { 'x-sba-session': outsiderSession.header } });
    check('session: a predicate vouching the admin identity for a foreign signer is denied (V-03: derivation check is mandatory)', res.status === 403);
    srv.close();
  }

  // ═══ Construction-time guards (2026-10-13 hardening, V-01, V-03, V-05) ═
  const good = {
    chainId, verifyingContract: registry, purpose: EXAMPLE_PURPOSE,
    predicate: async () => null,
    deriveIdentity: (a: Address) => deriveIdentityLocal(a, 'SBA_SALT_V1', chainId),
    allowlist: [identityId],
    summaryOf: () => 'x',
  };
  check('construct: missing purpose throws (V-01)', throws(() => sbaSessionAuth({ ...good, purpose: '' })));
  check('construct: missing deriveIdentity throws (V-03)', throws(() => sbaSessionAuth({ ...good, deriveIdentity: undefined as never })));
  check('construct: nonceCacheMax 0 throws (V-05)', throws(() => sbaRequestAuth({ ...good, nonceCacheMax: 0 })));
  check('construct: nonceCacheMax -1 throws (V-05)', throws(() => sbaRequestAuth({ ...good, nonceCacheMax: -1 })));
  check('construct: nonceCacheMax NaN throws (V-05)', throws(() => sbaRequestAuth({ ...good, nonceCacheMax: NaN })));
  check('construct: request mode without summaryOf throws (V-04)', throws(() => sbaRequestAuth({ ...good, summaryOf: undefined })));
  check('construct: zero verifyingContract throws (zero-semantics)', throws(() => sbaSessionAuth({ ...good, verifyingContract: '0x0000000000000000000000000000000000000000' })));
  check('construct: zero identity in allowlist throws (zero-semantics)', throws(() => sbaSessionAuth({ ...good, allowlist: [zeroHash] })));
  check('construct: a well-formed config constructs', !throws(() => sbaSessionAuth(good)) && !throws(() => sbaRequestAuth(good)));

  // ═══ Session revocation ═════════════════════════════════════════════
  sessionAuth.revoke(session.nonce);
  check('session: revoked session is denied instantly on this instance', await get('/admin/status', session.header) === 403);

  main.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  console.log(failed ? 'DEMO FAILED' : 'DEMO COMPLETE: all checks passed');
  process.exitCode = failed ? 1 : 0;
}

main().catch((err) => { console.error(err); process.exit(1); });
