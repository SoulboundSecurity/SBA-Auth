// SPDX-License-Identifier: AGPL-3.0-only
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
 *   single-use and the signature binds to the exact action: method and
 *   full URL in clear, the body as a hash. Use for mutations.
 *
 * Both modes run the same identity gauntlet after signature recovery:
 * live identity lookup through a pluggable predicate (fail-closed on
 * timeout), a mandatory local derivation check binding the identity value
 * to the signer's own address, and an allowlist of identity values.
 * Nothing the server stores can mint access: the allowlist authorizes, it
 * cannot sign.
 *
 * The EIP-712 domain REQUIRES `verifyingContract`: a signature is bound to
 * one registry deployment and verifies against no other domain. The
 * `purpose` string is REQUIRED and has no default: it is the audience the
 * signer sees, and services that share a registry must not share it.
 * Neither defends against a page soliciting a signature for this very
 * deployment; that is the signer-endpoint residual (SPEC.md section 6).
 *
 * Mounting guidance: place your rate limiter BEFORE these middlewares so
 * unauthenticated traffic is throttled before it costs an identity lookup.
 * For request mode, capture the raw request body (see `rawBodyOf`), e.g.:
 *   express.json({ verify: (req, _res, buf) => { (req as any).rawBody = buf.toString('utf8'); } })
 * A request that carries a body without a captured raw body is denied.
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

  /** REQUIRED, no default. The audience string the signer sees in the
   *  wallet; must match exactly. Give every service its own value:
   *  services sharing a registry, domain name, AND purpose accept each
   *  other's envelopes. */
  purpose: string;

  /** Live identity lookup (chain read). Fail-closed on null/timeout. */
  predicate: IdentityPredicate;

  /** REQUIRED local derivation check: returns the identity value expected
   *  for an address. The predicate's result must equal it, so a lying
   *  registry or RPC cannot vouch for a foreign identity. Forks pass
   *  `deriveIdentityLocal` with their own salt. */
  deriveIdentity: (address: Address) => Hex;

  /** Authorized identity values (lowercased 0x hex), or a predicate. */
  allowlist: Iterable<string> | ((identityId: string) => boolean);

  /** Session mode: max signature lifetime. Default 1h. */
  sessionWindowMs?: number;
  /** Request mode: max age of a signed request. Default 90s. */
  requestMaxAgeMs?: number;
  /** Identity lookup timeout (fail-closed). Default 3000ms. */
  rpcTimeoutMs?: number;
  /** Request-mode nonce cache capacity; a positive integer. Default
   *  10_000. A cache full of live nonces DENIES new requests rather than
   *  evicting a live nonce, so capacity bounds authenticated request-mode
   *  traffic per freshness window instead of weakening single-use. */
  nonceCacheMax?: number;

  /** Request mode: raw request body extractor. Return the exact body
   *  string received, '' for a bodyless request, or `undefined` to deny.
   *  The default reads `(req as any).rawBody`; when that is absent and
   *  the request carries a body (Content-Length or Transfer-Encoding),
   *  it returns `undefined` and the request is denied. */
  rawBodyOf?: (req: Request) => string | undefined;
  /** Request mode: path extractor. Defaults to `req.originalUrl`, the
   *  full path as requested including any mount prefix and query string.
   *  The client signs exactly this string. */
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

const ZERO_IDENTITY = /^0x0{64}$/;
const WELL_FORMED_IDENTITY = /^0x[0-9a-fA-F]{64}$/;

/** Loud-at-construction config validation. An absent or zero domain
 *  binding, a nonsense chain id, or a zero allowlist entry would silently
 *  configure a weaker gate; defaults must fail at construction, never be
 *  interpreted at the gate. (See the zero-semantics entry in audits/.) */
function assertConfig(config: SbaConfig): void {
  if (
    typeof config.verifyingContract !== 'string' ||
    !/^0x[0-9a-fA-F]{40}$/.test(config.verifyingContract) ||
    /^0x0{40}$/.test(config.verifyingContract)
  ) {
    throw new Error('sba-auth: verifyingContract must be a non-zero address (domain binding is mandatory)');
  }
  if (!Number.isInteger(config.chainId) || config.chainId <= 0) {
    throw new Error('sba-auth: chainId must be a positive integer');
  }
  if (typeof config.purpose !== 'string' || config.purpose.length === 0) {
    throw new Error('sba-auth: purpose is required and has no default (it is the audience the signer sees)');
  }
  if (typeof config.predicate !== 'function') {
    throw new Error('sba-auth: predicate is required');
  }
  if (typeof config.deriveIdentity !== 'function') {
    throw new Error('sba-auth: deriveIdentity is required (the registry is never the sole witness)');
  }
  if (
    config.nonceCacheMax !== undefined &&
    (!Number.isInteger(config.nonceCacheMax) || config.nonceCacheMax <= 0)
  ) {
    throw new Error('sba-auth: nonceCacheMax must be a positive integer');
  }
}

function makeAllowCheck(allowlist: SbaConfig['allowlist']): (id: string) => boolean {
  if (typeof allowlist === 'function') return allowlist;
  const set = new Set<string>();
  for (const id of allowlist) {
    const value = id.toLowerCase();
    if (ZERO_IDENTITY.test(value)) {
      // Zero is what a sloppy registry returns for "absent"; authorizing
      // it would let absence through the gate. Refuse loudly.
      throw new Error('sba-auth: zero identity in allowlist (absence can never be authorized)');
    }
    set.add(value);
  }
  return (id: string) => set.has(id.toLowerCase());
}

/** Insertion-ordered nonce cache with TTL. Entries are inserted only for
 *  fully verified requests, so the cache is bounded by authenticated
 *  traffic. At capacity, expired entries are evicted first; if the cache
 *  is still full of LIVE nonces the new request is refused, never a live
 *  nonce evicted: single-use is a guarantee, capacity is a rate ceiling
 *  on authenticated request-mode traffic per freshness window.
 *  Single-process semantics: state does not span replicas or survive a
 *  restart (SPEC.md section 9). */
class NonceCache {
  private entries = new Map<string, number>();
  constructor(private max: number) {}

  /** Returns false if the nonce was already seen and is still live, or if
   *  the cache is full of live nonces (fail closed). */
  consume(nonce: string, ttlMs: number): boolean {
    const now = Date.now();
    const existing = this.entries.get(nonce);
    if (existing !== undefined && existing > now) return false;
    this.entries.delete(nonce);
    if (this.entries.size >= this.max) {
      for (const [key, expiresAt] of this.entries) {
        if (expiresAt <= now) this.entries.delete(key);
      }
      if (this.entries.size >= this.max) return false;
    }
    this.entries.set(nonce, now + ttlMs);
    return true;
  }
}

/** Shared tail of the gauntlet (SPEC.md section 3, identity tail): live
 *  identity lookup through the pluggable predicate (fail-closed on
 *  timeout), then the mandatory LOCAL derivation check (the returned
 *  identity must equal the value derived from the signer's own address,
 *  so a lying registry or RPC cannot vouch for a foreign identity), then
 *  the allowlist. Returns the verified identity value or null. */
async function verifyIdentity(
  config: SbaConfig,
  address: Address,
  allowCheck: (id: string) => boolean,
): Promise<Hex | null> {
  const timeoutMs = config.rpcTimeoutMs ?? SBA_DEFAULTS.rpcTimeoutMs;
  const identity = await withTimeout(config.predicate(address), timeoutMs);
  if (identity === null) return null;

  // A zero or malformed identity never reaches the allowlist,
  // unconditionally. The reference registry reverts for absent identities,
  // but the predicate is pluggable: a registry that returns bytes32(0) for
  // "not enrolled" instead of reverting would otherwise flow its storage
  // default toward a trust decision. Zero means absence; absence never
  // passes a trust gate.
  if (
    typeof identity.identityId !== 'string' ||
    !WELL_FORMED_IDENTITY.test(identity.identityId) ||
    ZERO_IDENTITY.test(identity.identityId)
  ) return null;

  // Unconditional: the registry is never the sole witness to the binding
  // between a signer and an identity value.
  const expected = config.deriveIdentity(address).toLowerCase();
  if (identity.identityId.toLowerCase() !== expected) return null;

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
 * it instantly on this instance (in-process set: it does not span
 * replicas or survive a restart). The domain carries the mandatory
 * `verifyingContract`, so a session signed for this registry verifies
 * against no other domain; the mandatory `purpose` separates services
 * that share a registry.
 *
 * Gauntlet per request (SPEC.md section 3): envelope shape → purpose →
 * not revoked → freshness window → signature recovery → live identity
 * predicate (fail-closed timeout) → local derivation check → allowlist.
 * Every failure is an identical 403. Mount your rate limiter BEFORE this
 * handler.
 */
export function sbaSessionAuth(config: SbaConfig): SessionAuthHandler {
  assertConfig(config);
  const domain = {
    name: config.domainName ?? SBA_DEFAULTS.domainName,
    version: config.domainVersion ?? SBA_DEFAULTS.domainVersion,
    chainId: config.chainId,
    verifyingContract: config.verifyingContract,
  };
  const purpose = config.purpose;
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

/** Default raw-body extractor. A captured string is the body. No capture
 *  and no body (no Content-Length or Transfer-Encoding) is the empty
 *  string. No capture WITH a body is `undefined`, which denies: an
 *  absent capture must never be read as an empty body, or a signature
 *  over nothing would authorize anything. */
function defaultRawBodyOf(req: Request): string | undefined {
  const raw = (req as { rawBody?: unknown }).rawBody;
  if (typeof raw === 'string') return raw;
  if (raw !== undefined) return undefined;
  const length = req.headers['content-length'];
  const hasBody =
    (length !== undefined && length !== '0') ||
    req.headers['transfer-encoding'] !== undefined;
  return hasBody ? undefined : '';
}

/**
 * Request-mode middleware: every call carries its own EIP-712 signature
 * over `{purpose, method, path, bodyHash, nonce, issuedAt}`.
 * The signature binds to the exact action: `method` must match the
 * request, `path` must equal the full original URL (mount prefix and
 * query string included, exact bytes), `bodyHash` must equal keccak256
 * of the raw body bytes received (captured via `rawBodyOf`; see the file
 * header for the express.json verify hook; a body without a capture is
 * denied), `issuedAt` bounds age to `requestMaxAgeMs`,
 * and the nonce is single-use, so a captured envelope replays as a 403.
 *
 * This is the recommended mode for every mutation: one dangerous action
 * equals one hardware confirmation bound to exactly the bytes that
 * execute. The device shows `method` and `path` in clear and the body as
 * a hash.
 *
 * Nonce single-use is enforced in-process (`NonceCache`, fail-closed at
 * capacity); state does not span replicas or survive a restart (SPEC.md
 * section 9). Same gauntlet tail and identical-403 discipline as session
 * mode; mount your rate limiter BEFORE this handler.
 */
export function sbaRequestAuth(config: SbaConfig): RequestHandler {
  assertConfig(config);
  const domain = {
    name: config.domainName ?? SBA_DEFAULTS.domainName,
    version: config.domainVersion ?? SBA_DEFAULTS.domainVersion,
    chainId: config.chainId,
    verifyingContract: config.verifyingContract,
  };
  const purpose = config.purpose;
  const maxAgeMs = config.requestMaxAgeMs ?? SBA_DEFAULTS.requestMaxAgeMs;
  const allowCheck = makeAllowCheck(config.allowlist);
  const nonces = new NonceCache(config.nonceCacheMax ?? SBA_DEFAULTS.nonceCacheMax);
  const rawBodyOf = config.rawBodyOf ?? defaultRawBodyOf;
  const pathOf = config.pathOf ?? ((req: Request) => req.originalUrl);

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

      // The signature binds to the exact action: method, full URL, body
      // bytes.
      if (payload.method !== req.method) return deny(res);
      if (payload.path !== pathOf(req)) return deny(res);
      const rawBody = rawBodyOf(req);
      if (rawBody === undefined) return deny(res);
      if (payload.bodyHash.toLowerCase() !== bodyHashOf(rawBody).toLowerCase()) return deny(res);

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
      // required), so the cache is bounded by authenticated traffic; a
      // cache full of live nonces refuses rather than evicts; and a
      // transient verification failure never burns a valid signature. Of
      // two concurrent replays passing verification, exactly one wins:
      // consume is a synchronous map operation.
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
