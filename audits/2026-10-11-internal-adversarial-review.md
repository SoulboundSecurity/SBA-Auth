# Internal Adversarial Review — SBA-Auth v1.0 — 2026-10-11

Pre-publication adversarial review of the v1.0 implementation, conducted
internally by Soulbound Security against the repo's own stated threat
model (SPEC.md section 6), treating the repo as a standalone artifact.
Scope: the enrollment contract, the interface, both middleware modes, the
client helpers, the example, and every claim SPEC.md and README make.

**External review is welcome.** We publish our own findings as a matter
of course (see the
[sbf-protocol audits log](https://github.com/SoulboundSecurity/sbf-protocol/tree/master/audits)
for the house convention), we accept responsible disclosures at
security@soulboundsecurity.io, and we welcome pull requests under
[CLA.md](../CLA.md).

---

## Fixed in this revision

### MEDIUM · Request-mode nonce was consumed before authentication

As originally written, the request-mode verifier consumed the single-use
nonce before signature recovery and identity verification. Two
consequences: an unauthenticated flood of well-formed envelopes carrying
random nonces could fill the cache and evict a live legitimate nonce,
permitting replay of a captured envelope within its freshness window —
degrading the mode's core single-use guarantee exactly under the capture
scenario it exists to defeat; and a legitimate request failing on a
transient identity-read timeout (fail-closed) permanently burned its
signature, forcing a re-sign.

**Fix:** the nonce is now consumed only after full verification
(signature recovery, live identity check, local derivation check,
allowlist). Insertions are therefore unforgeable and the cache is bounded
by authenticated traffic; transient failures no longer burn signatures;
and of two concurrent replays passing verification, exactly one wins,
because consumption is a synchronous operation. The end-to-end rejection
matrix (`npm run demo`) passes unchanged.

## Documented choices (deliberate; adopter- or deployment-specific)

These were raised in review and are recorded here as design decisions
rather than defects. Each sits at the boundary where the right answer
depends on the deployment, which is precisely the work this repository
leaves to adopters. Soulbound Security provides deployment support under
commercial license for organizations that want these decided and
implemented with us.

| Item | The choice |
| --- | --- |
| Construction-time config validation | The middleware trusts its configuration (`verifyingContract`, `chainId`, allowlist) as typed rather than re-validating at runtime. TypeScript enforces presence; adopters integrating from untyped code should validate their own wiring. The demo is the reference for correct construction |
| Enrollment approval lifetime | `EnrollmentApproval(candidate, eulaHash)` carries no deadline by design (minimal struct). The revocation lever is structural: rotating `currentEulaHash` invalidates every outstanding approval, because the hash is inside the signed struct and must match at mint. Organizations wanting time-bounded approvals add a deadline field in their fork or handle it at the enrollment-authority layer |
| Per-process state | The request-mode nonce cache and the session revocation set are in-process. Single-replica deployments (the intended shape for small-population control surfaces) get correct semantics for free; multi-replica deployments back both with a shared store or pin traffic, per SPEC.md section 9 |
| Deny-path timing | All denials return identical 403s, but response timing can distinguish early failures from late ones. Exploiting the distinction requires a valid signature from an enrolled identity, and discloses only the caller's own allowlist status. Accepted |
| Salt in two places | The identity salt exists in the contract and in the verifier's `deriveIdentity` configuration. A fork updating one but not the other fails closed on every request — safe, but worth knowing before an evening of debugging |

Minor notes, same category: the registry reuses `EulaMismatch` for the
zero-hash guard in `setEulaHash`; the session revocation set grows
monotonically (operator-driven, practically bounded); the client's
`crypto.getRandomValues` assumes Node 19+ or a browser.

## Reviewed and found sound

Signature malleability (replay is keyed on the payload nonce, not
signature bytes, so a malleated signature buys nothing); cross-mode
replay (distinct primary types produce distinct digests); payload field
smuggling (hashing follows the declared types; extra fields cannot reach
the digest); missing raw-body capture at the adopter (fails closed,
forcing correct wiring); enrollment-approval cross-deployment replay
(domain-bound to contract address and chain id); contract reentrancy and
fund surface (no external calls beyond ecrecover, no funds); registry or
RPC equivocation (defeated by the local derivation check); open
enrollment abuse (enrollment grants nothing; the allowlist authorizes).

## Verdict

The pattern's core claims hold as specified: nothing server-side can
sign, failure is closed, the derivation check binds identities to their
own addresses, and the published rejection matrix demonstrates each
guarantee executably. One Medium was found and fixed in the same
revision as this record.
