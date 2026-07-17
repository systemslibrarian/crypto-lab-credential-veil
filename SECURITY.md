# Security Policy

## What this project is

Credential Veil is a **teaching demo** of BBS+ selective disclosure. It is explicitly
not production cryptography: no constant-time discipline, no side-channel review, no
key management, no audit. Do not build a wallet, issuer, or verifier on this code. The
known, accepted limitations are documented in
[docs/design-note.md](docs/design-note.md#known-security-limitations) and
[docs/threat-model.md](docs/threat-model.md) — reports that restate those are welcome
as documentation issues, but they are not vulnerabilities.

## What counts as a vulnerability here

- A soundness break: the demo's real verifier accepting a forged or tampered
  presentation or age proof that the design note says must be rejected.
- A divergence from draft-irtf-cfrg-bbs-signatures in the KAT-covered code paths.
- Hidden-field or linkability leakage beyond what the threat model already concedes.
- Anything that makes the deployed GitHub Pages site serve content other than this
  repository's build.

## Reporting

Please report privately via **GitHub Security Advisories**:
<https://github.com/systemslibrarian/crypto-lab-credential-veil/security/advisories/new>.

Because this is an educational side project, there is no SLA — but reports are read,
and confirmed soundness issues will be fixed and credited in the advisory. If the
issue also affects other crypto-lab demos, say so and it will be checked fleet-wide.
