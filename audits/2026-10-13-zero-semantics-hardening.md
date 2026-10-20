# Zero-Semantics Hardening — SBA-Auth — 2026-10-13

Follow-up review of SBA-Auth against the vulnerability class described
in Soulbound Security Research's analysis of the Nomad bridge incident,
[When Zero Meant Trusted](https://blog.soulbound.finance/p/when-zero-meant-trusted-how-a-default):
default and absent values acquiring privileged meaning at trust gates.
The question asked of every zero, default, and absent value in this
repository: *can "no record" ever reach a trust gate wearing "approved"
clothing?*

---

## Where the design was already immune

- **Absent registry entries cannot flow zero outward.** `identityOf()`
  reverts for unenrolled addresses rather than returning `bytes32(0)` —
  the inverse of the silent-default mapping read at the center of the
  Nomad incident. `hasIdentity()` gates on an explicit existence flag,
  never a zero-compare.
- **Zero terms hash fails closed.** Enrollment reverts `EulaNotSet` when
  no terms hash is configured, and the setter rejects zero.
- **Zero-address signature recovery is rejected** in both the contract
  and the verification path.
- **Every absence in the middleware resolves to denial**: empty
  allowlist, null predicate result, ~~missing raw-body capture~~.
  *Corrected 2026-10-16:* the raw-body item was repeated from the
  2026-10-11 entry rather than re-verified, and it was false: an absent
  capture resolved to the empty string, which is a default reaching a
  trust gate, the exact class this entry is about. Found by the external
  review (V-09); fixed in the following revision. See
  [`2026-10-16-external-adversarial-review.md`](2026-10-16-external-adversarial-review.md).
- **The incident's trigger class cannot occur**: the vulnerability was
  born in an upgrade reinterpreting surviving storage, and these
  contracts have no proxies, no upgrade path, and an append-only
  registry. No "new logic reads old state" seam exists.

## Hardened in this revision

### LOW · Zero and malformed identity values now rejected unconditionally at the gate

The identity predicate is pluggable by design. The reference registry
reverts for absent identities, but a non-conforming adopter registry
that returns `bytes32(0)` for "not enrolled" — the exact default-flow
mistake from the incident analysis — could previously carry that zero
into the verification tail, where only the optional derivation check and
allowlist hygiene stood between absence and authorization. Defense by
improbability, not construction.

**Fix:** `verifyIdentity` now rejects any identity value that is
malformed or zero before the allowlist is consulted, regardless of
predicate, derivation-check configuration, or allowlist contents; and
the allowlist constructor refuses zero entries loudly. Zero means
absence, and absence never passes a trust gate — now true for every
registry anyone ever plugs in.

### LOW · Configuration is validated loudly at construction

Previously recorded (2026-10-11 review) as a documented adopter choice:
the middleware trusted its configuration as typed. The incident
analysis's own checklist — *validate initializer parameters, and treat
values set at deploy time as part of the attack surface* — upgrades that
disposition. An absent or zero `verifyingContract` from untyped code
would have silently configured a verifier without domain binding; a
zero `chainId` likewise.

**Fix:** both middleware constructors now throw at construction on a
missing or zero `verifyingContract`, a non-positive `chainId`, a missing
predicate, or a zero allowlist entry. Defaults fail at construction,
never get interpreted at the gate. The 2026-10-11 review's
documented-choices table is amended accordingly.

## Documented characteristic (deliberate; queued for next revision)

`setEnrollmentAuthority(address(0))` intentionally switches the registry
to open enrollment: a sentinel zero carrying mode semantics at a gate.
It is controller-gated, event-emitting, and not externally exploitable,
but a controller-side scripting default resolving to zero would silently
convert approval-gated enrollment into open enrollment. Queued for the
next contract revision: an explicit `disableEnrollmentApproval()` with a
zero-rejecting setter, making the downgrade a named act rather than a
value collision. Until then, this entry is the loud note.

## Verification

`npm run demo` passes the full end-to-end rejection matrix unchanged
(8/8) after the hardening; TypeScript strict typecheck clean.
