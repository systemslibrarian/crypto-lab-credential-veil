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
| Verifier(s) link two presentations by their bytes | Fresh random scalars per presentation; `Ā = A·(r1·r2)` re-randomization | Exhibit 3 (byte-level diff, three showings) |
| Holder alters a disclosed value after proving | Verifier recomputes disclosed scalars from claimed values inside the challenge | Exhibit 2, "break it yourself" |
| Holder proves a predicate that is false | Bit-decomposition + bit-sum consistency bound to the signed DOB (design note, Statement 2) | Exhibit 4, honest-refusal and forge paths |
| Verifier replays an age proof against a different cutoff | Cutoff is serialized into the Fiat–Shamir challenge | `ageProof.test.ts` |
| Signature theft from presentations | The signature never appears in any presentation | Exhibits 2–4 |

## What it does NOT protect (out of scope, on purpose)

- **Revealed values that identify you.** Reveal your name at two verifiers and they can
  link you; no cryptography can prevent that. (Exhibit 3's caveat.)
- **Issuer + verifier collusion.** The issuer knows all fields and the public key it
  signed under. Collusion at scale is a governance problem, not a math problem.
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
