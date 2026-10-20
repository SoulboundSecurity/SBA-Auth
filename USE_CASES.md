# SBA-Auth Use Cases

Who this is for, what it replaces, and how to configure it per deployment.
Every case below shares one property: **the population is small and the
stakes are high.** That is the regime where wallet-native authentication is
both viable UX and a strict security upgrade. For the inverse regime, see
[What not to use this for](#what-not-to-use-this-for).

Terms used throughout:

- **Enrollment** — the one-time, on-chain ceremony: a candidate key mints a
  non-transferable identity whose value derives from the key's own address.
  Enrollment policy (open, or approval-co-signed) is where an organization
  attaches KYC, HR onboarding, background checks, or multi-party approval.
- **Session mode** — one wallet signature authorizes requests for a bounded
  window (default 1h); revocable server-side at any instant by its nonce.
- **Request mode** — every call carries its own signature bound to method,
  path, and body hash; single-use, non-replayable. One dangerous action =
  one hardware confirmation bound to exactly the bytes that execute.

---

## 1. Exchange hot-wallet and treasury operations console

**Today:** the console that moves real funds sits behind SSO + TOTP + VPN,
and dangerous actions are "approved" through Slack threads and shared
spreadsheets. Every layer is a stored credential or a phishable factor, and
the audit trail is whatever the ticketing system remembers.

**With SBA-Auth:**

- Enrollment: approval-gated. The security team's enrollment-authority
  key co-signs each operator's enrollment after internal vetting; the
  operator mints from a dedicated hardware wallet, and the enrollment is
  permanently visible on-chain. The reference registry verifies ECDSA
  approvals, so the authority is an EOA or a threshold-ECDSA signer;
  contract-wallet (ERC-1271) authorities are queued. The enrollment log
  is the roster of who could ever be authorized.
- Mode: request mode for everything that moves value or changes limits
  (each withdrawal approval, limit change, or address-list edit is one
  hardware-wallet confirmation bound to exactly the bytes submitted);
  session mode for dashboards.
- Allowlist: per-console configuration pinning enrolled identity values.
  This is the record of who is authorized now; keep it under change
  control, because grants and removals within the enrolled set emit no
  chain event. Removing an operator is a config change, and their
  identity remains on-chain as a historical record.
- Deployment: IP-fenced front end, dedicated signing hardware per
  operator, rate limiter mounted before the verifier.

**Eliminated:** passwords, TOTP seeds, SSO session theft, SIM swaps,
approval-by-screenshot. **Residual:** a compromised operator endpoint
during an active window (bounded by request mode to exactly the actions
the operator visibly confirms).

## 2. Protocol operator console (the reference deployment)

**Today:** DeFi and infrastructure protocols run backend consoles that can
pause systems, change parameters, and trigger recovery actions, typically
gated by the same session auth their users get, or by nothing but network
position.

**With SBA-Auth:** the operator authenticates with a hardware-signed
envelope re-verified against live chain state on every request; no session
store, account row, or recovery path exists to attack. Database, backend,
and RPC compromise each yield nothing: the console's authorization data
cannot sign. This is the configuration Soulbound Finance has run in
production since April 2026: session mode with a one-hour window, reads
and preset-validated writes behind the same gauntlet, every mutation
audit-logged under a salted identity derivative.

- Enrollment: open (the allowlist does the authorizing) or approval-gated.
- Mode: session for reads, request mode recommended for mutations.
- Allowlist: deployment configuration; one to a handful of identities.

## 3. Custodian and fund back-office approvals

**Today:** disbursement and rebalancing approvals flow through email chains
and admin panels authenticated by the weakest laptop in the office.

**With SBA-Auth:** each approver enrolls once (approval-gated, co-signed by
the compliance function); every approval is a request-mode signature whose
body hash covers the exact disbursement payload. The approval artifact is
cryptographic and attributable: the signed envelope, the raw request
body, and the on-chain enrollment together prove *which enrolled
identity signed exactly which bytes*. The application must retain all
three; the middleware verifies and attaches the result to the request,
it does not persist it. The signed `issuedAt` is asserted by the signer;
the server's receipt time is the attested time of approval.

Dual control is an application-level two-step, not two middlewares on
one route (one request carries one signer's envelope): the first
approver's request-mode call creates a pending action keyed by its body
hash; the second approver, from a disjoint allowlist, submits a
request-mode call over the same bytes; the application matches the two
hashes within an expiry and executes.

**Eliminated:** approval forgery, after-the-fact ambiguity about who
approved what. **Residual:** collusion among enrolled approvers, same as
any approval system.

## 4. Validator and infrastructure fleet administration

**Today:** break-glass panels, signer dashboards, and fleet controls for
staking operations sit behind SSH keys and bastion VPNs; key sprawl is
unaudited and offboarding is a prayer.

**With SBA-Auth:** the panel's auth reduces to enrolled hardware keys
checked against chain state per request. Offboarding is removing one
identity value from the allowlist; the on-chain enrollment history shows
every identity that was ever eligible, with timestamps, independent of
the operator's own records, and the change-controlled allowlist shows
who was authorized when. Chain-read dependency is a feature here:
validators already run nodes, so the predicate reads their own
infrastructure.

## 5. Regulated deployment with verified-identity enrollment

**Today:** regulated venues need operator actions attributable to
verified natural persons, but identity verification and system
authentication live in different silos.

**With SBA-Auth:** the enrollment mint carries a zero-knowledge identity
commitment (the `commitment` field): KYC happens once, off-chain, and its
proof commits on-chain at enrollment, bound to the operator's key. Every
subsequent authentication is cryptographically downstream of a verified
enrollment, with no personal data in the authentication path and none
stored by the platform. The commitment field is deliberately opaque to
this protocol: Privado-style ZK KYC, attestation registries, or internal
HR attestations all fit.

## 6. Internal tooling at crypto-native organizations

**Today:** the 5-to-20-person subset of the company that can touch money
or production uses the same Okta tenant as everyone else, and the IdP is
therefore the single credential store whose compromise is game over.

**With SBA-Auth:** the money-touching tools move off the IdP entirely.
No stored credential exists for them; the IdP compromise blast radius no
longer includes fund movement. The general workforce stays on the IdP for
everything else: this pattern deliberately does not replace workforce SSO.

---

## Choosing a configuration

| Decision | Options | Guidance |
| --- | --- | --- |
| Enrollment policy | Open mint + allowlist, or approval-co-signed mint | Open is honest when the allowlist is the real gate (small teams). Approval-gated when enrollment itself must encode process (KYC, HR, dual sign-off) |
| Mode per surface | Session / request | Reads: session. Anything that moves value, changes limits, or alters authorization: request mode, no exceptions |
| Allowlist custody | Deployment config | Treat as authorization data, not secret; changes should require deployment-level access and leave a change trail |
| Signer custody | Hardware wallet per operator, dedicated to this role | The signer key is the only secret in the system; give it the custody that fact deserves |
| Network posture | IP-fenced front end for high-value deployments | Defense in depth; bounds unauthenticated probing without touching the auth path |

## What not to use this for

- **Consumer authentication at scale.** Per-request wallet ceremonies are
  wrong UX for thousands of users; use SIWE-style session auth for your
  product surface and reserve SBA-Auth for its control surface.
- **General workforce SSO.** WebAuthn/passkeys behind an IdP are the right
  tool for the 95% of staff who never touch funds.
- **High-population RBAC.** The allowlist model is deliberately flat and
  small. If you need hundreds of principals and role hierarchies, this is
  not your layer.
- **Anything whose signer cannot be given real key custody.** The pattern
  concentrates all secrecy into the signer keys; shared browser-extension
  hot wallets on general-purpose laptops squander exactly the property
  being bought.
