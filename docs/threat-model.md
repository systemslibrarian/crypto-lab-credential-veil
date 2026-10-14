# Credential Veil — Threat Model

What this lab's cryptography defends, against whom, and — at least as important —
what it deliberately does not. Companion to [design-note.md](design-note.md).

**Scope reminder:** this is a teaching demo. "Protected" below means "protected by the
math running on this page, assuming an honest browser, honest page code, and working
`crypto.getRandomValues`." There is no deployment, no wallet, no network protocol.

## Actors

| Actor | Capabilities assumed |
|---|---|
| **Issuer** | Knows every field it signs and its own keys. Honest-but-curious at minimum; colluding at worst. |
| **Holder** | Runs the wallet (this page). May be honest, or may try to prove false statements (the tamper/forge exhibits). |
| **Verifier** | Sees whatever a presentation contains. May log everything, forever. |
| **Colluding verifiers** | Pool their logs and try to link presentations of the same credential. |
| **Issuer + verifier collusion** | Pool issuance records with presentation logs. |
| **Network observer** | Sees traffic metadata (who talked to whom, when, how much). |

## Assets

1. **Undisclosed attribute values** (e.g. the birth date behind an age proof).
2. **Unlinkability across presentations** of one credential.
3. **Integrity of claims** — a verifier must not accept a value the issuer never signed,
   or a predicate that does not hold.
4. **The issuer's signature** as a reusable bearer artifact.

## What the cryptography on this page protects

| Threat | Defense | Where demonstrated |
|---|---|---|
| Verifier learns hidden fields from a presentation | ZK property of the BBS proof — hidden messages enter only as uniformly blinded responses | Exhibit 2 (fields are *absent*, not redacted) |
| Issuer and verifier(s) link credentials through the standard BBS proof value | The draft's zero-knowledge presentation argument covers issuer–verifier coalitions, with fresh proof randomness | Exhibit 3 illustrates randomization; its byte comparison does not prove unlinkability |
| Holder alters a disclosed value after proving | Verifier recomputes disclosed scalars from claimed values inside the challenge | Exhibit 2, "break it yourself" |
| Holder proves a predicate that is false | Bit-decomposition + bit-sum consistency bound to the signed DOB (design note, Statement 2) | Exhibit 4, honest-refusal and forge paths |
| Verifier replays an age proof against a different cutoff | Cutoff is serialized into the Fiat–Shamir challenge | `ageProof.test.ts` |
| Signature theft from presentations | The signature never appears in any presentation | Exhibits 2–4 |

The proof-value guarantee is clarified in [BBS draft-13 §3.3.7 and §5 (13 October 2026)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-13#section-3.3.7).
It compares credentials satisfying the same disclosed statement, even when the
adversary issued both. This is a draft clarification, not a new attack. The
implementation remains checked against draft-13; these statements do not establish
security of the custom age-proof composition or of a production deployment.

## What it does NOT protect (out of scope, on purpose)

- **Revealed values that identify you.** Reveal your name at two verifiers and they can
  link you; no cryptography can prevent that. (Exhibit 3's caveat.)
- **Correlation through accompanying values.** An issuer and verifier can match
  identifying disclosures or distinctive headers and per-holder issuer keys against
  issuance records. Standard BBS protects the proof value against their collusion;
  it does not conceal this context.
- **Network metadata.** IP addresses, timing, TLS session reuse — a network observer or
  verifier can correlate on all of it. This page never even leaves the tab.
- **Presentation-header tagging.** A verifier who hands each holder a unique
  presentation header has created a correlation tag; the draft discusses this tension.
- **Revocation correlation.** Checking a status-list bit reveals a stable index —
  exhibit 5 exists to make this cost visible. ZK accumulator membership would repair it
  at real cost; not built here.
- **RNG failure.** A repeated blinding scalar can leak hidden messages. The page trusts
  `crypto.getRandomValues` unconditionally.
- **Side channels.** No constant-time discipline; timing/cache behavior of BigInt and
  curve arithmetic is unreviewed. See design-note §Known security limitations.
- **Malicious page or extension.** The holder's secrets live in tab memory; anything
  that can read the tab wins. There is no key isolation, HSM, or wallet boundary.
- **Issuance integrity.** The demo issuer signs whatever it is given; identity-proofing
  at issuance is entirely out of scope.
- **Wire-format security.** No W3C VC / SD-JWT / mdoc serialization, no DIDs, no
  transport. The crypto is the subject, not the plumbing.

## Non-goals

Building a production wallet, issuer, or verifier; standard-conformant interchange;
performance at scale; post-quantum migration (BLS12-381 pairings are
discrete-log-based and not PQ).
