# SBA-Auth Specification

Wallet-native authentication with no stored credentials. Version 1.1.

## 1. Design goal

**No credential the server stores can mint access.** The credential
classes that power common account-takeover attacks (passwords, email
resets, phone numbers, SIM swaps, TOTP seeds, recoverable sessions) do not
exist anywhere in this pattern. The only secret in the system is the
signer's wallet key, held in whatever custody the deployment chooses; the
server holds authorization data that cannot sign.

## 2. The enrollment / authentication split

SBA-Auth separates identity establishment from identity verification, the
same split WebAuthn makes between registration and authentication, with
the authenticator registry on a public chain and the registration policy
in a smart contract.

**Enrollment** is the expensive, organization-defined, one-time ceremony:
the candidate key sends a gas-paying transaction that mints a
non-transferable identity whose value derives from the key's own address
(a one-way hash over the address, a deployment salt, and the chain id).
Properties enrollment buys:

- **Key liveness, not just signing.** The candidate proves it can
  transact, which a phished signature cannot.
- **Terms acceptance** recorded cryptographically at mint.
- **Policy attachment.** Under approval-gated enrollment, the mint
  requires an EIP-712 co-signature from an enrollment authority over the
  candidate address: KYC, HR onboarding, and multi-party approval push
  into this single gate and never touch the per-request hot path. Under
  open enrollment, the allowlist (below) is the sole authorizer.
- **A public, append-only roster of eligibility.** Every identity that
  could ever be authorized is a visible on-chain event with a timestamp
  and a gas receipt. Identities cannot transfer, so a new key means a
  new, publicly visible enrollment. The registry records enrollment, not
  authorization: which enrolled identities are authorized at any moment
  is the allowlist (below), which is deployment configuration, and
  grants or removals within the enrolled set emit no chain event.
  Deployments that need an auditable authorization history keep the
  allowlist under change control.
- **An attachment point for verified identity**: the enrollment carries an
  opaque commitment field for zero-knowledge identity proofs.

**Authentication** is the cheap, stateless, per-request part: recover a
signer from an EIP-712 signature, confirm against live chain state that
the signer holds an enrolled identity, confirm locally that the identity
value derives from the signer's own address, and confirm the value is on
the deployment's allowlist.

## 3. The verification gauntlet

Run in full on every request, in the order below; every failure returns
an identical 403. The two modes share a head and a tail and differ in
the middle.

**Session mode**

1. The `x-sba-session` envelope is present, base64-decodes to JSON, and
   carries string `purpose`, `nonce`, and `validUntil`.
2. `purpose` equals the deployment's configured purpose string.
3. `nonce` has not been revoked on this instance.
4. `validUntil` parses, is in the future, and is no further ahead than
   the session window plus 60 seconds.
5. The signer's address is recovered from the EIP-712 signature over
   `SbaSession`.
6. Identity tail (below).

**Request mode**

1. The `x-sba-request` envelope is present, decodes, and carries string
   `purpose`, `method`, `path`, `bodyHash`, `nonce`, and `issuedAt`.
2. `purpose` equals the deployment's configured purpose string.
3. Action binding: `method` equals the request method; `path` equals
   the full original URL as requested, mount prefix and query string
   included, byte for byte (default extractor `req.originalUrl`); the
   raw body bytes were captured (a request that carries a body without a
   captured raw body is denied, never read as empty) and `bodyHash`
   equals their keccak256.
4. `issuedAt` parses, is no more than 60 seconds in the future, and is
   no older than `requestMaxAgeMs` (default 90 seconds).
5. The signer's address is recovered from the EIP-712 signature over
   `SbaRequest`.
6. Identity tail (below).
7. `nonce` is consumed: denied if already seen and still live on this
   instance, and denied if the cache is full of live nonces (capacity is
   a ceiling on authenticated request-mode traffic per window, never a
   reason to evict a live nonce); recorded otherwise. Consumption
   happens only after the full tail succeeds, so insertions require a
   valid signature from an enrolled, allowlisted identity.

**Identity tail (both modes)**

- Live identity lookup through the deployment's predicate, raced against
  a timeout and **fail-closed**: no answer is a denial, and so is a
  malformed or zero identity value. Zero means absence, and absence
  never reaches the allowlist, regardless of what a non-conforming
  registry returns.
- Local derivation check, mandatory: the returned identity value must
  equal the value derived from the signer's own address, so a lying
  registry or RPC cannot vouch for a foreign identity and possession of
  someone else's public identity value is worthless. `deriveIdentity`
  is required configuration; the middleware refuses to construct
  without it.
- The identity value is on the allowlist (authorization data, loaded at
  construction; an empty list denies everything).

**What the domain and the purpose bind.** The EIP-712 domain is
`{name, version, chainId, verifyingContract}` and **`verifyingContract`
is mandatory**: a signature produced for one registry on one chain
verifies against no other domain. The domain identifies a registry
deployment, not a service. The signed `purpose` is the audience: it is
**mandatory configuration with no default**, the middleware refuses to
construct without it, and services that share a registry must each use
their own. Two services configured with the same registry, domain name,
and purpose have declared themselves one audience and accept each
other's envelopes.

## 4. Modes

**Session mode.** One signature over `{purpose, nonce, validUntil}`
authorizes requests until `validUntil` (bounded by the deployment window).
The envelope is a bearer credential for that window *by design*; the
signed nonce names the session so the server can revoke it instantly.
Use for reads and low-stakes surfaces. Deployments that cannot tolerate
any bearer window use request mode exclusively.

**Request mode.** Every call carries its own signature over
`{purpose, method, path, bodyHash, nonce, issuedAt}`:

- `bodyHash` is a keccak256 over the exact raw body bytes. The signature
  is a commitment to exactly the bytes that execute: any change to the
  body after signing, in transit or at the browser, changes the hash and
  fails the action-binding check (section 3, request step 3). The
  signer's device displays `method` and `path` in clear and the body as
  a hash, not as fields; a front end that composes a malicious body
  *before* requesting the signature is not detected by the hash. That
  case is the signer-endpoint residual in section 6.
- `path` is the full original URL, mount prefix and query string
  included, so no parameter travels outside the signature.
- `nonce` is single-use (server-side TTL cache, per process, fail-closed
  at capacity), so capture and replay on the same instance yield
  nothing.
- `issuedAt` bounds signature age (default 90 seconds).

One dangerous action equals one hardware confirmation bound to exactly
those bytes. This is the recommended mode for every mutation.

## 5. The layer model

| Layer | Secret? | What its compromise alone yields |
| --- | --- | --- |
| Signer wallet key | **Yes, the only one** | Access, bounded by mode semantics |
| Chain possession (enrolled identity, address-derived) | No | Nothing without the key |
| Allowlist | No (authorization data) | Nothing without the key; changing it requires deployment-level access |
| Freshness | No | Bounds signature lifetime |

Compromise matrix: **database** yields nothing (no credentials exist
there); **server** yields nothing an attacker can present (authorization
data cannot sign); **registry or RPC alone** yields nothing (the
mandatory local derivation check is computed from the signer's own
address, not from anything the registry returns); **deployment configuration
tampering** requires access that is root-equivalent by definition. Access
reduces to possession of an enrolled, allowlisted hardware key, verified
against live chain state on every request.

## 6. Threat model

**Structurally eliminated:** credential stuffing, password reset abuse,
SIM swap, TOTP seed theft, server-side session theft, database-driven
privilege escalation, silent authority transfer to a new key.

**Mitigated by construction:** cross-deployment signature reuse (the
bound domain: a signature for one registry verifies nowhere else);
replay (request-mode nonces, per instance; session revocation, per
instance); post-signing action tampering (body hash, full URL); registry
equivocation (mandatory local derivation check); registry outage
(fail-closed).

**Explicitly out of scope:** the signer endpoint. This covers a
compromised operator machine during an active window, and also
*same-deployment signature solicitation*: a page that knows a
deployment's registry address, purpose string, and routes (all public
for an open deployment) can ask an enrolled signer to sign a valid
envelope for that deployment. The bound domain does not defend against
this. Request mode bounds both cases to one signed action per
confirmation; session mode bounds them to the window and the revocation
latency; network posture (section below) bounds who can present an
envelope at all. No authentication protocol survives the signer itself;
the pattern's job is to ensure the signer is the *only* thing that must
be defended.

**Operational layer (deployment guidance, not protocol):** dedicated
hardware signers per operator; rate limiting mounted before verification;
IP-fenced front ends for high-value deployments; allowlist changes
through change-controlled deployment configuration. See USE_CASES.md.

## 7. Privacy property

Stated precisely: the server stores **no addresses at rest**. The
identity value is attestation-linkable by design (it binds identity to an
address through public chain data, which is what makes the roster
independently auditable). Systems that additionally need usage records
decorrelated from chain identities derive a second, salted internal
identifier from the identity value with a server-held secret, as the
reference deployment does; without that salt, platform records cannot be
joined to chain identities.

## 8. Reference implementation

- `contracts/SoulboundAuthToken.sol` — the enrollment registry: open or
  approval-gated enrollment, EULA gate, commitment field, appointment-
  semantics administration (controller rotates configuration;
  administrative authority never travels with anything it administers).
- `contracts/interfaces/ISBAIdentity.sol` — the minimal predicate surface
  (MIT-licensed): `hasIdentity`, `identityOf`.
- `server/sba-auth.ts` — both modes for Express + viem, pluggable
  predicate, mandatory local derivation check, fail-closed timeouts and raw-body handling, session
  revocation, single-use request nonces.
- `client/sba-client.ts` — envelope construction and signing for any viem
  wallet client.
- `example/` — a runnable end-to-end demonstration against a local anvil
  node: deploy, enroll, authorize, and a 39-check acceptance and
  rejection matrix covering every claim in this document (domain, chain,
  purpose, expiry, freshness, method, full URL, body, raw-body
  capture, nonce capacity, lying registry, construction guards,
  revocation). `npm run demo`; also run in CI on every push.

The production-grade identity contract this pattern generalizes from is
the SoulBound Protocol's identity layer; its role model is specified in
[sbf-protocol's Role and Trust Model](https://github.com/SoulboundSecurity/sbf-protocol/blob/master/docs/PROTOCOL_SPEC.md#7-role-and-trust-model),
which this repo's contracts follow.

## 9. Interoperability notes

- Any registry exposing `ISBAIdentity` works; the predicate is pluggable.
- Replay and revocation state is per process and in memory: the
  request-mode nonce cache and the session revocation set live in the
  middleware instance that created them. They do not span replicas and
  do not survive a restart, which forgets revocations and consumed
  nonces for the remainder of their windows (at most the session window
  for a revoked session, at most `requestMaxAgeMs` plus 60 seconds for
  a consumed nonce). Multi-replica deployments route request-mode
  traffic to one replica or wrap the middleware with a shared store; the
  reference implementation does not yet expose a store interface.
- Forks MUST set their own identity salt: the salt namespaces identity
  derivation per deployment.
- Timestamp bounds, as implemented: request mode accepts `issuedAt` up
  to `requestMaxAgeMs` in the past (default 90 seconds, no additional
  grace) and up to 60 seconds in the future. Session mode rejects an
  expired `validUntil` with no grace and accepts a `validUntil` up to
  the session window plus 60 seconds ahead.
