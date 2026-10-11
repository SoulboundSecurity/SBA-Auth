// SPDX-License-Identifier: AGPL-3.0
/**
 * SBA-Auth server middleware: wallet-native authentication with no stored
 * credentials.
 *
 * Two modes, one gauntlet:
 *
 * - Session mode (`sbaSessionAuth`): one EIP-712 signature authorizes
 *   requests for a bounded window. The envelope is a bearer credential for
 *   that window by design; the signed nonce identifies the session so it
 *   can be revoked server-side instantly (`.revoke(nonce)`). Use for reads
 *   and low-stakes surfaces.
 * - Request mode (`sbaRequestAuth`): every request carries its own
 *   signature over (method, path, bodyHash, nonce, issuedAt). Nonces are
 *   single-use and signatures bind to the exact action, so capture and
 *   replay yield nothing. Use for mutations: each dangerous action becomes
 *   one human-readable wallet confirmation.
 *
 * Both modes run the same identity gauntlet after signature recovery:
 * live identity lookup through a pluggable predicate (fail-closed on
 * timeout), a local derivation check binding the identity value to the
 * signer's own address, and an allowlist of identity values. Nothing the
 * server stores can mint access: the allowlist authorizes, it cannot sign.
 *
 * The EIP-712 domain REQUIRES `verifyingContract`: signatures are bound to
 * one deployment and cannot be phished for one system and spent on another.
 *
 * Mounting guidance: place your rate limiter BEFORE these middlewares so
 * unauthenticated traffic is throttled before it costs an identity lookup.
 * For request mode, capture the raw request body (see `rawBodyOf`), e.g.:
 *   express.json({ verify: (req, _res, buf) => { (req as any).rawBody = buf.toString('utf8'); } })
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  recoverTypedDataAddress,
  keccak256,
  encodePacked,
  toBytes,
  type Address,
  type Hex,
} from 'viem';

// ─── Public types ─────────────────────────────────────────────────────

/** Resolves an address to its enrolled identity value, or null. Implement
 *  against any registry exposing the ISBAIdentity surface. */
export type IdentityPredicate = (address: Address) => Promise<{ identityId: Hex } | null>;

export interface SbaConfig {
  /** EIP-712 domain. `verifyingContract` is required: it binds every
   *  signature to one deployment (the identity registry address is the
   *  conventional choice). */
  domainName?: string;
  domainVersion?: string;
  chainId: number;
  verifyingContract: Address;

  /** Fixed purpose string shown in the wallet; must match exactly. */
  purpose?: string;

  /** Live identity lookup (chain read). Fail-closed on null/timeout. */
  predicate: IdentityPredicate;

  /** Local derivation check: returns the identity value expected for an
   *  address. When provided, the predicate's result must equal it, so a
   *  lying registry or RPC cannot vouch for a foreign identity. */
  deriveIdentity?: (address: Address) => Hex;

  /** Authorized identity values (lowercased 0x hex), or a predicate. */
  allowlist: Iterable<string> | ((identityId: string) => boolean);

  /** Session mode: max signature lifetime. Default 1h. */
  sessionWindowMs?: number;
  /** Request mode: max age of a signed request. Default 90s. */
  requestMaxAgeMs?: number;
  /** Identity lookup timeout (fail-closed). Default 3000ms. */
  rpcTimeoutMs?: number;
  /** Request-mode nonce cache capacity. Default 10_000. */
  nonceCacheMax?: number;

  /** Raw request body extractor for request mode. Defaults to
   *  `(req as any).rawBody ?? ''`. */
  rawBodyOf?: (req: Request) => string;
  /** Path extractor for request mode. Defaults to `req.path`. */
  pathOf?: (req: Request) => string;
}

export interface SbaAuthContext {
  address: Address;
  identityId: Hex;
  mode: 'session' | 'request';
  validUntil?: number;
  nonce: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      sbaAuth?: SbaAuthContext;
    }
  }
}

export interface SessionAuthHandler extends RequestHandler {
  /** Instantly invalidate a session by its signed nonce. */
  revoke(nonce: string): void;
}

// ─── Defaults and typed-data shapes ───────────────────────────────────

export const SBA_DEFAULTS = {
  domainName: 'SBA Auth',
  domainVersion: '1',
  purpose: 'SBA Administrative Access',
  sessionWindowMs: 60 * 60 * 1000,
  requestMaxAgeMs: 90 * 1000,
  rpcTimeoutMs: 3000,
  nonceCacheMax: 10_000,
  sessionHeader: 'x-sba-session',
  requestHeader: 'x-sba-request',
} as const;

export const SBA_SESSION_TYPES = {
  SbaSession: [
    { name: 'purpose', type: 'string' },
    { name: 'nonce', type: 'string' },
    { name: 'validUntil', type: 'string' },
  ],
} as const;

export const SBA_REQUEST_TYPES = {
  SbaRequest: [
    { name: 'purpose', type: 'string' },
    { name: 'method', type: 'string' },
    { name: 'path', type: 'string' },
    { name: 'bodyHash', type: 'string' },
    { name: 'nonce', type: 'string' },
    { name: 'issuedAt', type: 'string' },
  ],
} as const;

// ─── Helpers ──────────────────────────────────────────────────────────

/** keccak256 over the exact UTF-8 bytes of the raw body; '' hashes the
 *  empty byte string. Client and server must hash identical bytes. */
export function bodyHashOf(rawBody: string): Hex {
  return keccak256(toBytes(rawBody));
}

/** Canonical identity derivation matching SoulboundAuthToken: forks with a
 *  different salt pass their own. */
export function deriveIdentityLocal(address: Address, salt: string, chainId: number): Hex {
  return keccak256(encodePacked(['address', 'string', 'uint256'], [address, salt, BigInt(chainId)]));
}

/** Build an IdentityPredicate over any ISBAIdentity-shaped registry. */
export function makeViemPredicate(
  client: { readContract: (args: any) => Promise<unknown> },
  registry: Address,
): IdentityPredicate {
  const abi = [
    {
      type: 'function',
      name: 'identityOf',
      stateMutability: 'view',
      inputs: [{ name: 'account', type: 'address' }],
      outputs: [{ type: 'bytes32' }],
    },
  ] as const;
  return async (address: Address) => {
    try {
      const identityId = (await client.readContract({
        address: registry,
        abi,
        functionName: 'identityOf',
        args: [address],
      })) as Hex;
      return { identityId };
    } catch {
      return null; // not enrolled, or registry unreachable: fail closed
    }
  };
}

/** Race a promise against a deadline; timeout and rejection both resolve
 *  null so every failure path through the identity lookup fails CLOSED. */
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(null), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      () => { clearTimeout(t); resolve(null); },
    );
  });
}

/** Every denial is byte-identical: no failure step is distinguishable
 *  from outside, so the gauntlet is not an enumeration oracle. */
function deny(res: Response): void {
  res.status(403).json({ error: 'FORBIDDEN', message: 'SBA signature required' });
}

function parseEnvelope(headerValue: string): { payload: Record<string, unknown>; signature: Hex } | null {
  try {
    const decoded = Buffer.from(headerValue, 'base64').toString('utf8');
    const envelope = JSON.parse(decoded);
    if (!envelope || typeof envelope !== 'object') return null;
    if (!envelope.payload || typeof envelope.payload !== 'object') return null;
    if (typeof envelope.signature !== 'string') return null;
    return envelope;
  } catch {
    return null;
  }
}

function makeAllowCheck(allowlist: SbaConfig['allowlist']): (id: string) => boolean {
  if (typeof allowlist === 'function') return allowlist;
  const set = new Set<string>();
  for (const id of allowlist) set.add(id.toLowerCase());
  return (id: string) => set.has(id.toLowerCase());
}

/** Insertion-ordered nonce cache with TTL; oldest entries evicted at
 *  capacity. Entries are inserted only for fully verified requests, so the
 *  cache is bounded by authenticated traffic. Single-process semantics:
 *  multi-replica deployments back this with a shared store or route
 *  request-mode traffic to one replica. */
class NonceCache {
  private entries = new Map<string, number>();
  constructor(private max: number) {}

  /** Returns false if the nonce was already seen and is still live. */
  consume(nonce: string, ttlMs: number): boolean {
    const now = Date.now();
    const existing = this.entries.get(nonce);
    if (existing !== undefined && existing > now) return false;
    this.entries.delete(nonce);
    this.entries.set(nonce, now + ttlMs);
    if (this.entries.size > this.max) {
      for (const key of this.entries.keys()) {
        if (this.entries.size <= this.max) break;
        this.entries.delete(key);
      }
    }
    return true;
  }
}

/** Shared tail of the gauntlet (SPEC.md steps 5-7): live identity lookup
 *  through the pluggable predicate (fail-closed on timeout), then the
 *  LOCAL derivation check — the returned identity must equal the value
 *  derived from the signer's own address, so a lying registry or RPC
 *  cannot vouch for a foreign identity — then the allowlist. Returns the
 *  verified identity value or null. */
async function verifyIdentity(
  config: SbaConfig,
  address: Address,
  allowCheck: (id: string) => boolean,
): Promise<Hex | null> {
  const timeoutMs = config.rpcTimeoutMs ?? SBA_DEFAULTS.rpcTimeoutMs;
  const identity = await withTimeout(config.predicate(address), timeoutMs);
  if (identity === null) return null;

  if (config.deriveIdentity) {
    const expected = config.deriveIdentity(address).toLowerCase();
    if (identity.identityId.toLowerCase() !== expected) return null;
  }

  if (!allowCheck(identity.identityId)) return null;
  return identity.identityId;
}

// ─── Session mode ─────────────────────────────────────────────────────

/**
 * Session-mode middleware: one EIP-712 signature over
 * `{purpose, nonce, validUntil}` authorizes requests until `validUntil`,
 * bounded by `sessionWindowMs`. The envelope is a bearer credential for
 * that window BY DESIGN; choose this mode for reads and low-stakes
 * surfaces, and request mode for anything that mutates.
 *
 * The signed nonce names the session: `handler.revoke(nonce)` invalidates
 * it instantly (in-process set; multi-replica deployments back revocation
 * with a shared store). The domain carries the mandatory
 * `verifyingContract`, so a session signed for this deployment verifies
 * nowhere else.
 *
 * Gauntlet per request (SPEC.md section 3): envelope shape → purpose →
 * freshness window → signature recovery → live identity predicate
 * (fail-closed timeout) → local derivation check → allowlist. Every
 * failure is an identical 403. Mount your rate limiter BEFORE this
 * handler.
 */
export function sbaSessionAuth(config: SbaConfig): SessionAuthHandler {
  const domain = {
    name: config.domainName ?? SBA_DEFAULTS.domainName,
    version: config.domainVersion ?? SBA_DEFAULTS.domainVersion,
    chainId: config.chainId,
    verifyingContract: config.verifyingContract,
  };
  const purpose = config.purpose ?? SBA_DEFAULTS.purpose;
  const windowMs = config.sessionWindowMs ?? SBA_DEFAULTS.sessionWindowMs;
  const allowCheck = makeAllowCheck(config.allowlist);
  const revoked = new Set<string>();

  const handler = (async (req: Request, res: Response, next: NextFunction) => {
    try {
      const headerValue = req.header(SBA_DEFAULTS.sessionHeader);
      if (!headerValue) return deny(res);

      const envelope = parseEnvelope(headerValue);
      if (!envelope) return deny(res);
      const { payload, signature } = envelope;

      if (
        typeof payload.purpose !== 'string' ||
        typeof payload.nonce !== 'string' ||
        typeof payload.validUntil !== 'string'
      ) return deny(res);
      if (payload.purpose !== purpose) return deny(res);
      if (revoked.has(payload.nonce)) return deny(res);

      const validUntilMs = Date.parse(payload.validUntil);
      if (!Number.isFinite(validUntilMs)) return deny(res);
      const now = Date.now();
      if (validUntilMs <= now) return deny(res);
      if (validUntilMs > now + windowMs + 60_000) return deny(res);

      let recovered: Address;
      try {
        recovered = await recoverTypedDataAddress({
          domain,
          types: SBA_SESSION_TYPES,
          primaryType: 'SbaSession',
          message: payload as never,
          signature,
        });
      } catch {
        return deny(res);
      }

      const identityId = await verifyIdentity(config, recovered, allowCheck);
      if (identityId === null) return deny(res);

      req.sbaAuth = {
        address: recovered,
        identityId,
        mode: 'session',
        validUntil: validUntilMs,
        nonce: payload.nonce,
      };
      next();
    } catch {
      deny(res);
    }
  }) as unknown as SessionAuthHandler;

  handler.revoke = (nonce: string) => { revoked.add(nonce); };
  return handler;
}

// ─── Request mode ─────────────────────────────────────────────────────

/**
 * Request-mode middleware: every call carries its own EIP-712 signature
 * over `{purpose, method, path, bodyHash, nonce, issuedAt}`. The
 * signature binds to the exact action: method and path must match the
 * request, `bodyHash` must equal keccak256 of the raw body bytes
 * received (capture them via `rawBodyOf`; see the file header for the
 * express.json verify hook), `issuedAt` bounds age to `requestMaxAgeMs`,
 * and the nonce is single-use, so a captured envelope replays as a 403.
 *
 * This is the recommended mode for every mutation: one dangerous action
 * equals one human-readable confirmation on the signer's hardware
 * display, and what the display shows is what executes.
 *
 * Nonce single-use is enforced in-process (`NonceCache`); multi-replica
 * deployments back it with a shared store or pin request-mode traffic to
 * one replica (SPEC.md section 9). Same gauntlet tail and identical-403
 * discipline as session mode; mount your rate limiter BEFORE this
 * handler.
 */
export function sbaRequestAuth(config: SbaConfig): RequestHandler {
  const domain = {
    name: config.domainName ?? SBA_DEFAULTS.domainName,
    version: config.domainVersion ?? SBA_DEFAULTS.domainVersion,
    chainId: config.chainId,
    verifyingContract: config.verifyingContract,
  };
  const purpose = config.purpose ?? SBA_DEFAULTS.purpose;
  const maxAgeMs = config.requestMaxAgeMs ?? SBA_DEFAULTS.requestMaxAgeMs;
  const allowCheck = makeAllowCheck(config.allowlist);
  const nonces = new NonceCache(config.nonceCacheMax ?? SBA_DEFAULTS.nonceCacheMax);
  const rawBodyOf = config.rawBodyOf ?? ((req: Request) => (req as { rawBody?: string }).rawBody ?? '');
  const pathOf = config.pathOf ?? ((req: Request) => req.path);

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const headerValue = req.header(SBA_DEFAULTS.requestHeader);
      if (!headerValue) return deny(res);

      const envelope = parseEnvelope(headerValue);
      if (!envelope) return deny(res);
      const { payload, signature } = envelope;

      if (
        typeof payload.purpose !== 'string' ||
        typeof payload.method !== 'string' ||
        typeof payload.path !== 'string' ||
        typeof payload.bodyHash !== 'string' ||
        typeof payload.nonce !== 'string' ||
        typeof payload.issuedAt !== 'string'
      ) return deny(res);
      if (payload.purpose !== purpose) return deny(res);

      // The signature binds to the exact action.
      if (payload.method !== req.method) return deny(res);
      if (payload.path !== pathOf(req)) return deny(res);
      if (payload.bodyHash.toLowerCase() !== bodyHashOf(rawBodyOf(req)).toLowerCase()) return deny(res);

      const issuedAtMs = Date.parse(payload.issuedAt);
      if (!Number.isFinite(issuedAtMs)) return deny(res);
      const now = Date.now();
      if (issuedAtMs > now + 60_000) return deny(res);
      if (now - issuedAtMs > maxAgeMs) return deny(res);

      let recovered: Address;
      try {
        recovered = await recoverTypedDataAddress({
          domain,
          types: SBA_REQUEST_TYPES,
          primaryType: 'SbaRequest',
          message: payload as never,
          signature,
        });
      } catch {
        return deny(res);
      }

      const identityId = await verifyIdentity(config, recovered, allowCheck);
      if (identityId === null) return deny(res);

      // Single-use, consumed only AFTER full verification: insertions are
      // unforgeable (valid signature from an enrolled, allowlisted identity
      // required), so the cache is bounded by authenticated traffic and
      // cannot be flooded to evict a live nonce; and a transient
      // verification failure never burns a valid signature. Of two
      // concurrent replays passing verification, exactly one wins: consume
      // is a synchronous map operation.
      if (!nonces.consume(payload.nonce, maxAgeMs + 60_000)) return deny(res);

      req.sbaAuth = {
        address: recovered,
        identityId,
        mode: 'request',
        nonce: payload.nonce,
      };
      next();
    } catch {
      deny(res);
    }
  };
}
