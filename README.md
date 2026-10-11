# SBA-Auth · Soulbound Auth

**Wallet-native authentication with no stored credentials.** The
credential classes behind most account takeovers — passwords, email
resets, phone numbers, SIM swaps, TOTP seeds, recoverable sessions — do
not exist in this pattern. The only secret is the signer's wallet key;
the server holds authorization data that cannot sign. Built for the
surfaces where populations are small and stakes are high: exchange
hot-wallet consoles, protocol operator panels, custodian approvals,
infrastructure fleet administration.

In production gating the operator control surface of
[Soulbound Finance](https://soulbound.finance) since April 2026.

## What deploying this feels like

Setup is a ceremony, and then daily life gets simpler than what you had.
On day one, each operator takes a dedicated hardware wallet, pays a few
cents of gas, and enrolls — that one transaction is where you bolt on
whatever vetting your organization requires, and it's carved into a
public ledger forever. After that, there are no passwords to rotate,
nothing to reset, no codes to read off a phone, and nothing on your
servers worth stealing: an operator taps their wallet once to open an
hour of dashboards, and physically confirms each dangerous action on the
device's screen, which shows exactly what will execute. Offboarding
someone is editing one config line. Your database can be dumped, your
backend rooted, your RPC provider can lie — none of it mints a login,
because nothing you store can sign.

**The limits, left and right.** On the left, the floor is your signer
hardware and the humans holding it — the design deliberately concentrates
every secret into those keys, so sloppy key custody, a phished operator
who confirms something they shouldn't, or a lost wallet with no
re-enrollment plan is entirely your problem, and no amount of
configuration here saves you. On the right, the ceiling is scale and
convenience: this is for the five-to-twenty people who can touch money,
not your workforce (no SSO, no roles, no recovery flow — a lost key means
a fresh public enrollment, by design); your chain or RPC being
unreachable locks the console shut rather than open, because fail-closed
is the contract; and every mutation costs a physical button press, which
your operators will call friction in week one and call the audit trail by
month three. Fly between those limits — tiny vetted population, real key
custody, reachable chain — and the system is close to unattackable from
the server side. Drift past either edge and you're flying a different
aircraft than the one that was certified.

## How it works

SBA-Auth is an **enrollment / authentication split** — WebAuthn's
registration/authentication model with the authenticator registry on a
public chain and the registration policy in a smart contract:

- **Enroll once, on-chain.** A candidate key pays gas to mint a
  non-transferable identity whose value derives from the key's own
  address. Enrollment policy is the organization's extension point: open,
  or co-signed by an enrollment authority (KYC, HR onboarding, dual
  approval — all pushed into one ceremony). The enrollment log is a
  public, append-only roster: authority can never quietly move to a new
  key.
- **Authenticate per request, statelessly.** Every request recovers a
  signer from an EIP-712 signature (domain-bound to one deployment),
  checks live chain state that the signer holds an enrolled identity,
  checks *locally* that the identity derives from the signer's own
  address, and checks a deployment allowlist. Fail-closed throughout.
- **Two modes.** Session mode: one signature per bounded window,
  instantly revocable. Request mode: one signature per action, bound to
  method + path + body hash, single-use — every dangerous action becomes
  a human-readable hardware-wallet confirmation.

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

The demo exercises the whole pattern end to end: session-gated reads,
request-gated mutations, replay rejection, body-tamper rejection,
unenrolled-key rejection, and instant session revocation.

Server integration is one middleware per surface:

```ts
import { sbaSessionAuth, sbaRequestAuth, makeViemPredicate, deriveIdentityLocal } from './server/sba-auth.js';

const config = {
  chainId,
  verifyingContract: REGISTRY_ADDRESS,          // binds every signature to this deployment
  predicate: makeViemPredicate(publicClient, REGISTRY_ADDRESS),
  deriveIdentity: (a) => deriveIdentityLocal(a, 'YOUR_FORK_SALT', chainId),
  allowlist: ADMIN_IDENTITY_IDS,                // authorization data, not a secret
};

app.get('/admin/stats',  rateLimiter, sbaSessionAuth(config), handler);
app.post('/admin/action', rateLimiter, sbaRequestAuth(config), handler);
```

## Repository layout

| Path | What | License |
| --- | --- | --- |
| `SPEC.md`, `USE_CASES.md` | The pattern and its deployments | AGPL-3.0 (freely readable; ideas aren't licensed) |
| `contracts/SoulboundAuthToken.sol` | Enrollment registry (open or approval-gated) | AGPL-3.0 |
| `contracts/interfaces/ISBAIdentity.sol` | Minimal identity predicate surface | **MIT** — integrate against it without license questions |
| `server/sba-auth.ts`, `client/sba-client.ts` | Verifier middleware and envelope signing | AGPL-3.0 |
| `example/` | Runnable end-to-end demo against anvil | AGPL-3.0 |

## Licensing

SBA-Auth follows the Soulbound Security licensing model:

- **Concepts stay free.** The original MIT concept exploration remains
  available, unchanged, at the [`v0-concept`](../../tree/v0-concept) tag.
- **Interfaces stay permissive.** `ISBAIdentity` is MIT so any system can
  expose or consume the predicate surface freely.
- **The implementation is AGPL-3.0.** Deploy it openly and share your
  modifications, or license it commercially for proprietary embedding:
  **legal@soulboundsecurity.io**. Commercial engagements include
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
- Research: [blog.soulbound.finance](https://blog.soulbound.finance)

**Security contact:** security@soulboundsecurity.io ·
[SECURITY.md](SECURITY.md)
