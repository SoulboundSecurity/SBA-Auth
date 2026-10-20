# SBA-Auth · Soulbound Auth

**Wallet-native authentication with no stored credentials.** The
credential classes behind most account takeovers — passwords, email
resets, phone numbers, SIM swaps, TOTP seeds, recoverable sessions — do
not exist in this pattern. The only secret is the signer's wallet key;
the server holds authorization data that cannot sign. Built for the
surfaces where populations are small and stakes are high: exchange
hot-wallet consoles, protocol operator panels, custodian approvals,
infrastructure fleet administration.

**Provenance.** [Soulbound Finance](https://soulbound.finance) has gated
its operator control surface with the SBA concept since April 2026,
using its own implementation built from the original MIT concept
specification (the [`v0-concept`](../../tree/v0-concept) tag). This
repository is a separate implementation of the pattern, built for
AGPL-3.0 adopters. Soulbound Finance does not run this code;
improvements made here may be carried back into that system over time.

## How it works

SBA-Auth is an **enrollment / authentication split** — WebAuthn's
registration/authentication model with the authenticator registry on a
public chain and the registration policy in a smart contract:

- **Enroll once, on-chain.** A candidate key pays gas to mint a
  non-transferable identity whose value derives from the key's own
  address. Enrollment policy is the organization's extension point: open,
  or co-signed by an enrollment authority (KYC, HR onboarding, dual
  approval — all pushed into one ceremony). The enrollment log is a
  public, append-only roster of who could ever be authorized: a new key
  is a new, visible enrollment. Who is authorized now is the allowlist,
  deployment configuration under change control.
- **Authenticate per request, statelessly.** Every request recovers a
  signer from an EIP-712 signature (domain-bound to one registry
  deployment), checks live chain state that the signer holds an enrolled
  identity, checks *locally* that the identity derives from the signer's
  own address, and checks a deployment allowlist. Fail-closed throughout.
- **Two modes.** Session mode: one signature per bounded window,
  instantly revocable. Request mode: one signature per action, bound to
  method + full URL + body hash + a human-readable summary the server
  recomputes and verifies, single-use — every dangerous action becomes
  one hardware-wallet confirmation that shows the action and binds the
  bytes.

Database compromise yields nothing. Server compromise yields nothing an
attacker can present. RPC compromise alone yields nothing. Access reduces
to possession of an enrolled, allowlisted hardware key.

Full pattern: [SPEC.md](SPEC.md). Deployment scenarios and configuration
guidance: [USE_CASES.md](USE_CASES.md).

## Quickstart

```bash
npm install
forge build
anvil &          # local chain
npm run demo     # deploy, enroll, authenticate, full rejection matrix
```

The demo exercises the whole pattern end to end as a 48-check acceptance
and rejection matrix: domain, chain, and purpose binding; expiry and
freshness; method, full-URL, body, and summary binding; raw-body
capture; nonce capacity; a lying registry; construction guards;
environment loading; and instant session revocation. The same matrix
runs in CI on every push.

The whole authentication configuration of a deployment is five
environment variables, none of them secret (see
[`.env.example`](.env.example)). Anyone who reads them learns who is
authorized and still cannot sign as any of them, so they live in
change-controlled deployment configuration, not a vault:

```bash
SBA_CHAIN_ID=42161
SBA_REGISTRY=0x…                          # this organization's enrollment registry
SBA_PURPOSE="Treasury Console"            # the audience every signature names; unique per service
SBA_IDENTITY_SALT=…                       # namespaces identities; matches the registry
SBA_ALLOWLIST=0x3f1c…,0x9a07…,0x52de…     # enrolled identity values, not secrets
```

Server integration is one middleware per surface:

```ts
import { sbaSessionAuth, sbaRequestAuth, makeViemPredicate } from './server/sba-auth.js';
import { sbaConfigFromEnv } from './server/sba-env.js';

const env = sbaConfigFromEnv();                 // throws on anything missing, zero, or malformed
const config = {
  ...env,                                       // chainId, verifyingContract, purpose, deriveIdentity, allowlist
  predicate: makeViemPredicate(publicClient, env.verifyingContract),
  summaryOf: (req) => `withdraw ${req.body.amount} ${req.body.token} to ${req.body.to}`,
};

app.get('/admin/balances', rateLimiter, sbaSessionAuth(config), handler);
app.post('/admin/withdraw', rateLimiter, sbaRequestAuth(config), handler);
```

Onboarding an operator is one enrollment and one new allowlist entry;
offboarding is deleting the entry and redeploying.

The client signs the same summary string; the signer's device shows it;
the server recomputes it from the request it executes and denies on any
difference.
## Deployment model

Enrollment is identity proofing and credential registration in one
on-chain step: each operator enrolls from a dedicated hardware signer
with a gas-paying transaction, gated by whatever vetting the
organization requires. The enrollment log is an immutable,
independently auditable roster.

Day-to-day operation maps to familiar enterprise controls, minus the
credential store. Session establishment is one wallet signature with a
bounded TTL, instantly revocable. Privileged mutations are step-up
authorization: one hardware-confirmed signature per action, showing a
summary the server verifies against exactly what executes. There is no
password lifecycle, no MFA reset
desk, and no server-side credential to steal or rotate. Deprovisioning
is a one-line allowlist change; database, backend, or RPC compromise
mints no access, because nothing the server stores can sign.

## Operating envelope

- **Floor: signer custody.** All secrecy concentrates in the operator
  keys. Key custody, operator phishing discipline, a device that renders
  EIP-712 fields (so the request summary is seen, not only signed), and
  a re-enrollment plan for lost keys are deployment responsibilities; no
  configuration compensates for them.
- **Ceiling: population and availability.** Built for the small
  privileged population that touches funds or production, not
  workforce SSO: no roles, no recovery flow (a lost key is a new,
  publicly visible enrollment, by design). Identity checks fail
  closed: an unreachable chain or RPC locks the control surface shut.
  Per-action confirmation is deliberate friction, and the signed
  envelopes are the raw material for an attributable audit trail when
  the deployment retains them with the request bodies.

Inside that envelope — small vetted population, real key custody,
reachable chain — the server side offers no credential to attack.

## Security review

This repository is reviewed adversarially in two stages, by engineering
before publication and by the security team after it, and the whole
record is public in [`audits/`](audits/): every finding, its severity,
what we did about it, and where we were wrong.

| Date | Review | Outcome |
| --- | --- | --- |
| [2026-10-11](audits/2026-10-11-internal-adversarial-review.md) | Engineering adversarial review, pre-publication | 1 Medium (nonce consumed before verification), fixed in the same revision |
| [2026-10-13](audits/2026-10-13-zero-semantics-hardening.md) | Engineering review against the zero-semantics class | 2 Low hardened: unconditional zero-identity rejection, loud construction-time config validation |
| [2026-10-16](audits/2026-10-16-soulbound-security-audit.md) | **Security team review**, conducted blind to platform context, harness-verified ([PDF](audits/2026-10-16-soulbound-security-audit.pdf)) | 13 findings and 3 notes, all reproduced (20/20 on the review's harness): 1 High claim, 5 Medium, 6 Low, 1 Informational. Documents corrected, implementation fixes shipped as v1.1 (envelope format 2), rejection matrix extended from 8 to 48 checks and moved into CI; one false statement in our own 2026-10-11 review corrected in place |

The standard we hold ourselves to: findings are published with
severity and reasoning, fixes ship in the open, claims that turn out to
be stronger than the code are corrected in the record rather than
quietly edited, and external reviewers are credited. Reviews are
welcome at security@soulboundsecurity.io; see [SECURITY.md](SECURITY.md).

## What's new in 1.1

**Signers can read what they sign.** Request-mode typed data now carries
a `summary` field, so the EIP-712 confirmation on a hardware wallet shows
the action in words ("withdraw 250000 USDC to 0x…") rather than a body
hash, and the server recomputes that summary from the request it
executes and denies on any difference. The text the operator read on the
device is proven to describe the bytes that run. It came out of the
2026-10-16 security team review (V-04), alongside the fixes recorded in
the review entry: purpose and derivation check mandatory, full URL signed,
raw-body absence denied, nonce cache fail-closed. v1 envelopes do not
verify against the 1.1 domain. Full list: [SPEC.md changelog](SPEC.md#10-changelog).

## Repository layout

| Path | What | License |
| --- | --- | --- |
| `SPEC.md`, `USE_CASES.md` | The pattern and its deployments | AGPL-3.0 (freely readable; ideas aren't licensed) |
| `contracts/SoulboundAuthToken.sol` | Enrollment registry (open or approval-gated) | AGPL-3.0 |
| `contracts/interfaces/ISBAIdentity.sol` | Minimal identity predicate surface | **MIT** — integrate against it without license questions |
| `server/sba-auth.ts`, `server/sba-env.ts`, `client/sba-client.ts` | Verifier middleware, environment-file configuration, envelope signing | AGPL-3.0 |
| `example/` | Runnable end-to-end demo against anvil | AGPL-3.0 |

## Licensing

SBA-Auth follows the Soulbound Security licensing model:

- **Concepts stay free.** The original MIT concept exploration remains
  available, unchanged, at the [`v0-concept`](../../tree/v0-concept) tag.
- **Interfaces stay permissive.** `ISBAIdentity` is MIT so any system can
  expose or consume the predicate surface freely.
- **The implementation is AGPL-3.0.** Deploy it openly and share your
  modifications, or license it commercially for proprietary embedding:
  **sales@soulboundsecurity.io**. Commercial engagements include
  deployment support — enrollment ceremony design, signer custody, and
  allowlist operations are where the real work lives.

Contributions are accepted under [CLA.md](CLA.md).

## Name use

The code is AGPL; the name is not. Forks and derived deployments may not
call themselves "Soulbound Auth" or "SBA-Auth" or imply Soulbound
Security's endorsement. Describe compatibility nominatively ("implements
the SBA-Auth pattern") and name your deployment yourself.

## Related

- [sbf-protocol](https://github.com/SoulboundSecurity/sbf-protocol) — the
  AGPL-3.0 SoulBound Protocol; its
  [Role and Trust Model](https://github.com/SoulboundSecurity/sbf-protocol/blob/master/docs/PROTOCOL_SPEC.md#7-role-and-trust-model)
  is the role-administration pattern these contracts follow, and its
  identity layer is the production-grade ancestor of this registry.
- Product release: [SBA-Auth: Four Factors, One Key](https://blog.soulbound.finance/p/sba-auth-four-factors-one-key)
- Research: [blog.soulbound.finance](https://blog.soulbound.finance)

**Security contact:** security@soulboundsecurity.io ·
[SECURITY.md](SECURITY.md)
