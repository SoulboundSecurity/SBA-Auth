# Security Policy

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
