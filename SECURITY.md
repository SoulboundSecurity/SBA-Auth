# Security Policy

## Review history

Findings from reviews of this repository, and the changes shipped in
response, are recorded in [`audits/`](audits/). The implementation carries a
pre-publication adversarial review by engineering
([2026-10-11](audits/2026-10-11-internal-adversarial-review.md)), a
follow-up hardening against the zero-semantics vulnerability class
([2026-10-13](audits/2026-10-13-zero-semantics-hardening.md)), and a
full security audit by the Soulbound Security security team, conducted
blind to platform context
([2026-10-16](audits/2026-10-16-soulbound-security-audit.md),
[report PDF](audits/2026-10-16-soulbound-security-audit.pdf)) whose
13 findings were all reproduced on the audit's harness and are
dispositioned there. External audits are welcome and will be recorded
in the same log.

## How we review

- Two stages: engineering reviews adversarially before publication;
  the security team audits after it, without platform context, so its
  findings hold for any adopter and not only for our deployment.
- Every finding is recorded with a severity and the reasoning behind
  it, including the ones we decline, and including the ones that show
  our own earlier statements were wrong. Corrections are made in place
  with a dated note; nothing is quietly edited out of the record.
- Fixes ship in the open and the entry that motivated them says so.
- External reviewers are named and credited. Internal reviews are
  attributed to Soulbound Security, not to individuals.
- Reproducibility counts: where a reviewer supplies a harness, we re-run
  it before triage and record the result.

## Reporting

Report vulnerabilities to **security@soulboundsecurity.io**. Accepted
disclosures and the changes shipped in response are credited; see the
[sbf-protocol audits log](https://github.com/SoulboundSecurity/sbf-protocol/tree/master/audits)
for the house convention.

## Scope

In scope: the verification gauntlet (`server/sba-auth.ts`), envelope
construction (`client/sba-client.ts`), the enrollment registry
(`contracts/`), and any property SPEC.md claims.

Out of scope by design (SPEC.md section 6): a compromised signer
endpoint during an active window. The pattern concentrates all secrecy
into the signer key so that the signer is the only thing that must be
defended; deployments choose custody accordingly.

## Deployment responsibility

This repository publishes a pattern and a reference implementation.
Deployments own their enrollment policy, signer custody, allowlist
operations, and network posture (USE_CASES.md). Soulbound Security
supports commercial deployments under license; unsupported forks are
responsible for their own configuration, and modified deployments must
not carry the SBA-Auth name (README, Name use).
