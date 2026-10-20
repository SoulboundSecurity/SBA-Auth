# External Adversarial Review — SBA-Auth v1.0 — 2026-10-16

Independent adversarial review of the v1.0 implementation and its
documented security claims, conducted by **Gakarot** against the
repository as a standalone artifact (no access to private platform
context, deployment assumptions, or other repositories). Scope: the
enrollment contract, both middleware modes, the client helpers, the
example, SPEC.md, USE_CASES.md, README.md, and the two prior entries in
this log. Method: code and document reading, plus an external harness of
20 checks exercising the repository's own signing and verification code
through Express, and an ERC-1271 proof against a local chain.

The reviewer's report is reproduced in full as
[`2026-10-16-external-adversarial-review.pdf`](2026-10-16-external-adversarial-review.pdf).
We re-ran the reviewer's harness against `main` at `a1e9974` before
triage: **20 of 20 checks reproduce.** Every finding below is confirmed.

Thirteen findings and three notes. None is an authentication bypass
under the documented configuration. Three have practical impact when a
deployment drifts from the example (V-02, V-03, V-09); two are
claim-accuracy problems in our own documents (V-01, V-04); one
contradicts a statement in our 2026-10-11 review, which is corrected
below and in place. Severity below is ours, graded by impact under
realistic deployment conditions; the reviewer's classification is kept
in parentheses.

---

## Findings and dispositions

| ID | Finding | Severity | Disposition |
| --- | --- | --- | --- |
| V-01 | No service-specific audience binding; services sharing a registry, domain name, and purpose accept each other's signatures (design + claim) | Medium | **Fix.** The default `purpose` is a shared default reaching a trust gate, the class hardened on 2026-10-13. The default is removed and `purpose` becomes mandatory per service, documented as the audience. Claims scoped in SPEC §3/§6 and README to "one registry deployment" |
| V-02 | Request signature does not cover the query string; default path is mount-relative (impl) | Medium | **Fix.** Default `pathOf` becomes the full original URL (mount path plus query, exact bytes). Documented for mounted routers |
| V-03 | `deriveIdentity` is optional, so the lying-registry defence depends on configuration (impl vs spec) | Medium | **Fix.** `deriveIdentity` becomes required and is asserted at construction, making SPEC §3 step 6 true by construction |
| V-04 | Request mode signs method, path, and a body hash; the signer's display shows a hash, not the action's fields (claim) | **High** (claim) | **Fix, two parts.** Documents corrected now: the confirmation is bound to exactly the bytes that execute, not a human-readable rendering of them, and a malicious front end composing the body before signing is the signer-endpoint residual, not a defended case. Implementation: a server-verified, human-readable `summary` field added to the request struct, so the device shows the action and the server proves the summary matches the body |
| V-05 | `nonceCacheMax` unvalidated; zero or negative capacity disables single-use, small capacity permits replay after eviction (impl) | Low | **Fix.** Validated as a positive integer at construction. Eviction made fail-closed: expired entries are evicted first and a cache still full of live nonces denies rather than evicts, so capacity bounds authenticated request-mode traffic per window instead of weakening single-use |
| V-06 | In-process revocation and nonce state do not survive restarts or span instances; no injectable store (impl) | Low | **Documented; interface queued.** A deliberate choice for single-replica control surfaces, but our 2026-10-11 wording ("correct semantics for free") overlooked restart. Corrected there and in SPEC §9. An injectable nonce/revocation store interface is queued |
| V-07 | Enrollment authority and operators are EOA-only; the multisig authority in USE_CASES §1 is unsupported (impl vs docs) | Medium | **Documented; contract change queued.** USE_CASES §1 now states an ECDSA authority (EOA or threshold-ECDSA). ERC-1271 verification for the enrollment authority is queued for the next contract revision; operator signatures remain EOA by design (hardware signers) |
| V-08 | The on-chain roster records enrollment, not authorization changes (claim) | Low | **Documented.** SPEC §2, README, and USE_CASES §1/§4 now distinguish the registry (who could ever be authorized, public) from the allowlist (who is, deployment configuration under change control) |
| V-09 | Missing raw-body capture lets a signature over an empty body be accepted with any body (impl) | Medium | **Fix; record corrected.** The default raw-body extractor now denies when capture is absent and the request carries a body; bodyless requests still hash the empty string. Our 2026-10-11 and 2026-10-13 entries both stated this case fails closed; it did not, and both are amended in place |
| V-10 | Dual-control described as two chained gates, which cannot both pass on one request (claim) | Low | **Documented.** USE_CASES §3 now describes dual control as an application-level two-step approval keyed by body hash, and names the state it needs |
| V-11 | Attributable audit trail depends on adopter-side retention; `issuedAt` is signer-asserted (claim) | Low | **Documented; hook queued.** README and USE_CASES §3 now say what the application must retain and that server receipt time is the attested time. A verification callback for audit logging is queued |
| V-12 | Asymmetric clock-skew tolerance versus SPEC §9 (spec mismatch) | Low | **Documented.** SPEC §9 now states the actual bounds: request age up to `requestMaxAgeMs` in the past, 60 s in the future; session expiry with no grace, issuance up to window plus 60 s ahead |
| V-13 | SPEC misstates the verification sequence; "dies at step 3" refers to the freshness step (doc) | Informational | **Documented.** SPEC §3 rewritten per mode in execution order, including action binding, revocation, and nonce consumption |
| N-1 | `CLA.md` names "SBF Protocol" | Informational | **Fixed.** Names SBA-Auth |
| N-2 | License identifiers disagree: SPDX `AGPL-3.0`, package `AGPL-3.0-only`, LICENSE preamble "or any later version" | Low | **Fixed.** `AGPL-3.0-only` everywhere, including the LICENSE preamble; the dual-license model depends on a single, unambiguous grant |
| N-3 | No unit tests, contract tests, or CI; the demo's eight checks do not cover the cases the reviewer lists | Medium (process) | **Queued.** The rejection matrix is extended to the reviewer's gap list (wrong chain or contract, wrong purpose, expired session, stale or future issuance, method or path mismatch, enrolled-but-not-allowlisted key, lying predicate) and run in CI against a local chain. Our 2026-10-11 wording is amended |

## Corrected in this log

Two statements in our own entries were wrong and are amended in place
with a dated note:

- **2026-10-11, "Reviewed and found sound":** "missing raw-body capture
  at the adopter (fails closed, forcing correct wiring)". False for a
  signature over an empty body (V-09). The default extractor substituted
  the empty string for an absent capture, so an empty-body signature
  verified against any body.
- **2026-10-13, "Where the design was already immune":** listed missing
  raw-body capture among absences that resolve to denial. Same error,
  repeated from the earlier entry rather than re-verified.

Also amended: the 2026-10-11 claims that single-replica deployments get
"correct semantics for free" (restart was overlooked, V-06) and that the
demo "demonstrates each guarantee executably" (it demonstrates eight
cases, N-3).

## A residual the review implies and we now state

V-01 and V-04 compose. A page that knows a deployment's registry
address, purpose, and routes (all public for an open deployment) can ask
an enrolled signer to sign a valid envelope for that deployment: a
session envelope, or a request envelope over a body the page composed.
The bound domain does not defend against this; it defends against a
signature for one deployment being spent on another. SPEC §6 previously
listed cross-deployment phishing as mitigated and was silent on the
same-deployment case. It now names the case as part of the
signer-endpoint residual, bounded by request mode (one bound action per
signature), the server-verified summary field (the device shows the
action), and network posture (who can present an envelope at all).

## Reviewed by the external review and found to hold

The reviewer did not contest, and the harness confirms: every denial is
an identical 403; request-mode replay on one instance is denied after
first use; a tampered body under a valid signature is denied when
capture is configured; a different purpose rejects a foreign session;
the derivation check, when configured, defeats a lying predicate; the
registry rejects a non-authority enrollment approval; revocation is
immediate on the instance that revoked. The contract was not found to
have a fund surface, a reentrancy path, or a signature-malleability
issue.

## Verdict

The pattern's core claim survives: nothing the server stores can sign,
failure is closed, and access reduces to an enrolled, allowlisted key
verified against live chain state. What did not survive unchanged is a
set of statements that described the implementation as stronger than it
was: by construction where it was by configuration (V-03), human-readable
where it was hash-bound (V-04), one deployment where it was one registry
(V-01), and fail-closed where it was not (V-09). Those statements are
corrected in this revision; the implementation changes they call for
ship in the next, with this entry updated to record them.

We thank Gakarot for a review that was evidence-first, reproducible, and
precise about its own limits. External review of this repository
remains welcome at security@soulboundsecurity.io; accepted findings are
recorded here and credited.
