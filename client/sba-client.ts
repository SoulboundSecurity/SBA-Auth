// SPDX-License-Identifier: AGPL-3.0-only
/**
 * SBA-Auth client helpers: build and sign the session and request
 * envelopes the server middleware verifies. Works with any viem
 * WalletClient (browser EIP-1193 or local account).
 *
 * Session mode: one signature, reusable until expiry, revocable
 * server-side by its nonce. Request mode: one signature per action,
 * bound to method + full URL + body bytes + a human-readable summary the
 * server recomputes and verifies, single-use.
 */

import { keccak256, toBytes, type Address, type Hex } from 'viem';

export interface SbaClientConfig {
  /** Chain id of the deployment; part of the EIP-712 domain. */
  chainId: number;
  /** REQUIRED domain binding: the identity registry address by
   *  convention. A signature produced for this registry verifies against
   *  no other domain. It does not stop a page from soliciting a signature
   *  for this very deployment; read what your wallet shows. */
  verifyingContract: Address;
  domainName?: string;
  domainVersion?: string;
  /** REQUIRED, no default: the audience string the wallet displays; must
   *  match the server's exactly. */
  purpose: string;
}

const DEFAULTS = {
  domainName: 'SBA Auth',
  domainVersion: '2',
  sessionWindowMs: 60 * 60 * 1000,
};

const SESSION_TYPES = {
  SbaSession: [
    { name: 'purpose', type: 'string' },
    { name: 'nonce', type: 'string' },
    { name: 'validUntil', type: 'string' },
  ],
} as const;

const REQUEST_TYPES = {
  SbaRequest: [
    { name: 'purpose', type: 'string' },
    { name: 'method', type: 'string' },
    { name: 'path', type: 'string' },
    { name: 'bodyHash', type: 'string' },
    { name: 'summary', type: 'string' },
    { name: 'nonce', type: 'string' },
    { name: 'issuedAt', type: 'string' },
  ],
} as const;

type TypedDataSigner = {
  signTypedData: (args: {
    account: never;
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    primaryType: string;
    message: Record<string, string>;
  }) => Promise<Hex>;
};

function domainOf(config: SbaClientConfig) {
  return {
    name: config.domainName ?? DEFAULTS.domainName,
    version: config.domainVersion ?? DEFAULTS.domainVersion,
    chainId: config.chainId,
    verifyingContract: config.verifyingContract,
  };
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function encodeHeader(payload: Record<string, string>, signature: Hex): string {
  const json = JSON.stringify({ payload, signature });
  return typeof Buffer !== 'undefined'
    ? Buffer.from(json, 'utf8').toString('base64')
    : btoa(json);
}

/** keccak256 over the exact UTF-8 bytes of the body string; must match the
 *  bytes the server receives. Send the SAME string you hash. */
export function bodyHashOf(rawBody: string): Hex {
  return keccak256(toBytes(rawBody));
}

/** Sign a session envelope: one wallet confirmation authorizes requests
 *  for `windowMs` (server-bounded). Send the returned `header` as
 *  `x-sba-session` on every call; keep it in memory only, never in
 *  browser storage. The returned `nonce` names the session for
 *  server-side revocation; `expiresAt` drives a countdown/re-sign UX. */
export async function signSession(
  walletClient: TypedDataSigner,
  account: unknown,
  config: SbaClientConfig,
  windowMs: number = DEFAULTS.sessionWindowMs,
): Promise<{ header: string; nonce: string; expiresAt: number }> {
  const expiresAt = Date.now() + windowMs;
  const payload = {
    purpose: config.purpose,
    nonce: randomNonce(),
    validUntil: new Date(expiresAt).toISOString(),
  };
  const signature = await walletClient.signTypedData({
    account: account as never,
    domain: domainOf(config),
    types: SESSION_TYPES,
    primaryType: 'SbaSession',
    message: payload,
  });
  return { header: encodeHeader(payload, signature), nonce: payload.nonce, expiresAt };
}

/** Sign one request: header value for `x-sba-request`, bound to this
 *  exact method, full URL, body bytes, and summary; single-use and
 *  short-lived. `path` is the full path as the server will see it in
 *  `req.originalUrl`: mount prefix and query string included. Send the
 *  SAME body string you pass here; any difference in bytes changes the
 *  hash and the server denies. `summary` is the human-readable
 *  description of the action the wallet displays; the server recomputes
 *  it from the request it executes and denies on any difference, so the
 *  text the signer read is what runs. One dangerous action, one
 *  signature, one hardware confirmation. */
export async function signRequest(
  walletClient: TypedDataSigner,
  account: unknown,
  config: SbaClientConfig,
  request: { method: string; path: string; body?: string; summary: string },
): Promise<{ header: string; nonce: string }> {
  const payload = {
    purpose: config.purpose,
    method: request.method.toUpperCase(),
    path: request.path,
    bodyHash: bodyHashOf(request.body ?? ''),
    summary: request.summary,
    nonce: randomNonce(),
    issuedAt: new Date().toISOString(),
  };
  const signature = await walletClient.signTypedData({
    account: account as never,
    domain: domainOf(config),
    types: REQUEST_TYPES,
    primaryType: 'SbaRequest',
    message: payload,
  });
  return { header: encodeHeader(payload, signature), nonce: payload.nonce };
}
