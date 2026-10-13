# SBA-Auth Specification

Wallet-native authentication with no stored credentials. Version 1.0.

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
- **A public, append-only roster.** Every identity that could ever be
  authorized is a visible on-chain event with a timestamp and a gas
  receipt. Identities cannot transfer, so authority cannot quietly move
  to a new key: a new key means a new, publicly visible enrollment.
- **An attachment point for verified identity**: the enrollment carries an
  opaque commitment field for zero-knowledge identity proofs.

**Authentication** is the cheap, stateless, per-request part: recover a
signer from an EIP-712 signature, confirm against live chain state that
the signer holds an enrolled identity, confirm locally that the identity
value derives from the signer's own address, and confirm the value is on
the deployment's allowlist.

## 3. The verification gauntlet

Run in full on every request; every failure returns an identical 403.

1. The signed envelope is present, decodes, and is well-formed.
2. The signed purpose matches the deployment's fixed constant.
3. Freshness holds (mode-specific, section 4).
4. The signer's address is recovered from the EIP-712 signature. The
   domain is `{name, version, chainId, verifyingContract}` and
   **`verifyingContract` is mandatory**: a signature is bound to one
   deployment and cannot be obtained for one system and spent on another.
5. Live identity lookup through the deployment's predicate, raced against
   a timeout and **fail-closed**: no answer is a denial, and so is a
   malformed or zero identity value — zero means absence, and absence
   never reaches the allowlist, regardless of what a non-conforming
   registry returns.
6. Local derivation check: the returned identity value must equal the
   value derived from the signer's own address. A lying registry or RPC
   cannot vouch for a foreign identity, and possession of someone else's
   public identity value is worthless.
7. The identity value is on the allowlist (authorization data, loaded at
   startup; an empty list denies everything).

## 4. Modes

**Session mode.** One signature over `{purpose, nonce, validUntil}`
authorizes requests until `validUntil` (bounded by the deployment window).
The envelope is a bearer credential for that window *by design*; the
signed nonce names the session so the server can revoke it instantly.
Use for reads and low-stakes surfaces. Deployments that cannot tolerate
any bearer window use request mode exclusively.

**Request mode.** Every call carries its own signature over
`{purpose, method, path, bodyHash, nonce, issuedAt}`:

- `bodyHash` is a keccak256 over the exact raw body bytes, so what the
  signer's hardware displays is what executes; tampering in transit or at
  a compromised browser changes the hash and dies at step 3.
- `nonce` is single-use (server-side TTL cache), so capture and replay
  yield nothing.
- `issuedAt` bounds signature age (default 90 seconds).

One dangerous action equals one human-readable confirmation on the
signer's hardware display. This is the recommended mode for every
mutation.

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
derivation check is computed locally); **deployment configuration
tampering** requires access that is root-equivalent by definition. Access
reduces to possession of an enrolled, allowlisted hardware key, verified
against live chain state on every request.

## 6. Threat model

**Structurally eliminated:** credential stuffing, password reset abuse,
SIM swap, TOTP seed theft, server-side session theft, database-driven
privilege escalation, silent authority transfer to a new key.

**Mitigated by construction:** cross-deployment signature phishing (the
bound domain); replay (request-mode nonces; session revocation); action
tampering (body hash); registry equivocation (local derivation check);
registry outage (fail-closed).

**Explicitly out of scope:** a compromised signer endpoint during an
active window. Request mode bounds this to the actions the operator
visibly confirms on hardware; session mode bounds it to the window and
the revocation latency. No authentication protocol survives the signer
itself; the pattern's job is to ensure the signer is the *only* thing
that must be defended.

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
  predicate, local derivation check, fail-closed timeouts, session
  revocation, single-use request nonces.
- `client/sba-client.ts` — envelope construction and signing for any viem
  wallet client.
- `example/` — a runnable end-to-end demonstration against a local anvil
  node: deploy, enroll, authorize, and the full rejection matrix (replay,
  tamper, unenrolled key, revocation). `npm run demo`.

The production-grade identity contract this pattern generalizes from is
the SoulBound Protocol's identity layer; its role model is specified in
[sbf-protocol's Role and Trust Model](https://github.com/SoulboundSecurity/sbf-protocol/blob/master/docs/PROTOCOL_SPEC.md#7-role-and-trust-model),
which this repo's contracts follow.

## 9. Interoperability notes

- Any registry exposing `ISBAIdentity` works; the predicate is pluggable.
- Multi-replica servers must back the request-mode nonce cache with a
  shared store, or route request-mode traffic to one replica.
- Forks MUST set their own identity salt: the salt namespaces identity
  derivation per deployment.
- Clock skew tolerance is 60 seconds on both freshness bounds.
