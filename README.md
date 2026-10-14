# Credential Veil — crypto-lab

Anonymous credentials with **BBS selective disclosure** over BLS12-381, in the browser. Prove you're over 18 from a signed credential containing your birth date — without showing the birth date, without showing the signature, and without the verifier being able to link this presentation to the last one.

## What It Is

A signed credential (a JWT, a mobile driver's license) is an **all-or-nothing artifact**: to prove one field, you hand over the whole document plus the signature that binds it — and that signature is a stable byte string that links every place you show it. BBS signatures (Boneh–Boyen–Shacham lineage, modernized by Camenisch–Drijvers–Lehmann, specified in the evolving **CFRG BBS Internet-Draft**) break that: the issuer signs N messages once; the holder proves knowledge of that signature while revealing only the k messages they choose, in a freshly randomized presentation each time.

**On the name:** this lab implements the CFRG draft's scheme, which the draft calls plain **BBS** — its signature is the pair `(A, e)`. **BBS+** is a distinct scheme: the Au–Susilo–Mu variant (*Constant-Size Dynamic k-TAA*, SCN 2006), whose signature carries an extra blinding scalar, `(A, e, s)`. The two are often conflated; this repo means the former throughout.

**What's real:** the BBS implementation on this page is hand-rolled to the draft's pseudocode (ciphersuite **BLS12-381-SHA-256**) on top of `@noble/curves` for the BLS12-381 pairing arithmetic, and passes the official fixture KATs — signing, verification, proof generation and proof verification. The Ed25519 baseline, the Pedersen-commitment age range proof, and the status-list bitstring are also real and run live.

**Current BBS baseline:** [draft-13, 13 October 2026](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-13.txt),
with all 30 fixture files matched byte for byte to [publisher commit 104bdcd](https://github.com/decentralized-identity/bbs-signature/tree/104bdcd85869ac05d1c621e064222441404e019b).
The SHA-256 BBS core is reviewed and tested against this numbered reference,
including publisher intermediate traces and malformed-input controls.
See the [baseline review](docs/bbs-baseline-review.md) and [source pins](docs/spec-provenance.md).
This remains a draft and does not validate the custom age-proof composition.

**What's simulated:** the credential itself (issuer, wallet, fields) is a stage prop; keys are generated per session and live only in tab memory.

**Privacy scope:** standard BBS protects the proof value even when the issuer and verifiers collude. That does not establish privacy for a whole deployment: identifying disclosures, distinctive headers or issuer keys, revocation handles, and network metadata can still enable tracking. [Draft-13 §§3.3.7 and 5 (13 October 2026)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-13#section-3.3.7) clarify this boundary. The declared SHA-256 BBS core is now checked against draft-13; the baseline review records the version comparison and input-domain change. The standard guarantee does not validate this lab's custom age-proof composition. **Not production crypto — a teaching demo.** The implementation is not constant-time and has seen no side-channel review.

One deliberate encoding deviation, for honesty: five credential fields are mapped to scalars exactly as the draft's signatures interface does (`messages_to_scalars`); the **DOB field is signed as its integer day count** so the age range proof can do arithmetic on it. The draft's core operations take scalars directly, so this stays within the core; only that one field's message-to-scalar mapping is custom. The age proof extends the draft's Fiat–Shamir challenge with the Pedersen-link and range-proof transcript (a standard sigma-protocol AND composition) — that extension is this lab's, not the draft's.

## Exhibits

1. **The problem: all-or-nothing disclosure** — prove "over 18" with an Ed25519-signed credential and watch the verifier receive all six fields plus a reusable signature. Signature valid; privacy verdict: broken. The two indicators disagree on purpose.
2. **Selective disclosure (the headline)** — check exactly the fields to reveal; step through issuer-signs-once → holder-chooses → re-randomize-and-prove → verifier-checks-a-pairing, with the real artifacts at every step. The hidden fields aren't redacted on the verifier's side — they're *absent*, and the signature never appears. Then **break it yourself**: tamper a revealed value after proving and hand it to the real verifier.
3. **Randomized presentations** — present the same credential three times; the page counts and highlights shared 8-byte runs and reports repeated disclosed values. Flip to Ed25519 to see the identical signature, three times. The byte comparison illustrates randomization; it cannot prove unlinkability or diagnose a privacy failure from a matching run.
4. **Age ≥ 18 predicate** — a bit-decomposition range proof over a Pedersen commitment, challenge-linked into the BBS proof so the committed value *is* the signed DOB. The verifier learns one bit. Try it honestly with a 2010 birth date (no proof exists), then force a forgery and watch the real verifier separate "genuine signature" from "impossible transcript".
5. **Revocation, the honest tension** — a real status-list bitstring. Revoke bit #17, check it as the verifier, and read the price: the index is a stable correlation handle that undoes the unlinkability you just saw. Stated, not solved.
6. **What hides what, from whom** — BBS vs blind signatures (signer-blind at issuance, still all-or-nothing at showing) vs ring signatures (hides *who*, not *what*) vs plain JWT/mDL.

## When to Use It

- Teaching or learning what "anonymous credentials" and "selective disclosure" actually mean at the algebra level.
- Understanding why W3C Verifiable Credentials / ISO mDoc communities are adopting BBS for privacy-preserving presentation.
- Seeing why revocation is the hard open edge of credential privacy.
- **Do NOT use** this code to build a production wallet or issuer: it is a demo — no constant-time discipline, no key management, no protocol hardening, no audit.

## Live Demo

<https://systemslibrarian.github.io/crypto-lab-credential-veil/> — issue the credential, reveal any subset of the six fields, present three times and diff the bytes, prove age ≥ 18 without a birth date, then revoke and feel the tension.

## What Can Go Wrong

- **Reveal something identifying and unlinkability is gone** — cryptographic unlinkability cannot survive revealing your name at two verifiers.
- **The header/presentation-header carry context** — a unique presentation header chosen by a verifier is itself a tag; the draft discusses this tradeoff.
- **Revocation checks can re-link presentations** — any stable checkable handle (status-list index) is a correlation handle. ZK accumulator membership repairs this at real cost.
- **Collusion using identifying context** — standard BBS proof values remain protected against colluding issuers and verifiers. But those parties can match revealed identifiers, distinctive headers or per-holder issuer keys against issuance records. Protecting the proof value does not hide those accompanying values.
- **Bad randomness in proof generation** — BBS proof security leans on fresh uniform scalars per presentation; a repeated blinding scalar can leak hidden messages.

## Real-World Usage

- **draft-irtf-cfrg-bbs-signatures-13** (CFRG) — the work-in-progress reference for this lab's declared SHA-256 BBS baseline, with versioned publisher test vectors.
- **W3C Verifiable Credentials / Data Integrity BBS cryptosuites** — selective-disclosure VC presentations.
- **ISO mDL / mdoc privacy work** and government digital-identity pilots evaluating BBS for unlinkable age/attribute proofs.
- Lineage: CL signatures → Idemix (IBM), U-Prove (Microsoft), Hyperledger AnonCreds — the same problem, earlier algebra.

## How to Run Locally

```bash
npm ci
npm run dev        # local dev server
npm test           # unit tests incl. official spec KATs + adversarial suite
npm run build      # typecheck + production build
npm run test:a11y  # axe WCAG 2.1 A/AA gate — Chromium/Firefox/WebKit/mobile, dark theme (port 4620)
npm run bench      # reproducible performance numbers (see docs/benchmarks.md)
```

Requires Node 20.19+; CI uses Node 22.

## Related Demos

- [crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) — the BLS12-381 pairing this lab consumes as a primitive.
- [crypto-lab-blind-sign](https://systemslibrarian.github.io/crypto-lab-blind-sign/) — blind at *issuance* (the signer can't see), where BBS is blind at *showing* (the verifier can't see).
- [crypto-lab-bulletproofs](https://systemslibrarian.github.io/crypto-lab-bulletproofs/) — the logarithmic-size range proof; this lab uses the inspectable O(n) bit decomposition instead.
- [crypto-lab-ring-sign](https://systemslibrarian.github.io/crypto-lab-ring-sign/) — anonymity among a set of signers, not selective disclosure of attributes.

## Build & Verify

- **102 unit tests** (Vitest), colocated in `src/`, executed by the CI gate before deploy —
  including a property-based/adversarial suite (`src/credential/adversarial.test.ts`)
  that byte-flips, truncates, and re-targets valid proofs and requires every mutation to
  fail closed.
- Six primitive compatibility controls cover BLS pairing cancellation and identity rejection, point encoding/scalar boundaries, and actual Ed25519 baseline signatures checked independently with native WebCrypto.
- **25 official spec KATs** from the draft-irtf-cfrg-bbs-signatures fixtures (BLS12-381-SHA-256): 10 signature, 15 proof — plus keypair, hash-to-scalar, 10 message-to-scalar cases, the full generator set (P1, Q1, H1–H10), and the mocked-RNG vectors, in `src/bbs/fixtures/`.
- **Accessibility gate:** `@axe-core/playwright` scans the production build in the configured **dark theme** at 1280px and 380px after driving every exhibit to its post-interaction state; zero WCAG 2.1 A/AA violations required for deploy (`.github/workflows/deploy.yml`). Light-theme verification is not established by this gate.
- **Browser matrix:** the a11y/interaction drive runs on Chromium, Firefox, WebKit, and
  a mobile (Pixel-7) project — four projects, dark-theme scans, serialized because
  parallel pairing math can starve a browser renderer.

## Reviewing the cryptography

Start with [docs/design-note.md](docs/design-note.md) — it states exactly what each
proof proves, separates standard BBS from this lab's extensions (the DOB scalar
encoding and the challenge-linked age predicate), and lists the known limitations.
Companions: [docs/threat-model.md](docs/threat-model.md) (who is protected from whom,
and what is out of scope) and [docs/spec-provenance.md](docs/spec-provenance.md) (which
draft text, which fixtures, which library versions). Security reports: see
[SECURITY.md](SECURITY.md). License: [MIT](LICENSE).

## Performance

All proof work runs in a **Web Worker** with `@noble/curves` (pure JS, no WASM), so the
page never freezes; the age-proof buttons stream coarse progress ("committing 15 bits…",
"checking the pairing…") and a cancel button hard-stops the worker mid-proof. A
selective-disclosure proof takes ~100 ms; prove-plus-verify for the age predicate is
~1.5 s of real group operations and a pairing. Reproducible numbers, proof sizes, and
methodology: [docs/benchmarks.md](docs/benchmarks.md) (`npm run bench`). Nothing is
precomputed or faked to hide the cost.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Issuance, presentation and research assumptions (12 October 2026)

[On the Concrete Security of BBS/BBS+ Signatures](https://eprint.iacr.org/2025/1093), received 11 June 2025, revised 22 October 2025 (ASIACRYPT 2025), gives q-signature key-recovery attacks comparable to Θ(q)-DL, about O(sqrt(p/q)) for suitable q. Here q concerns issuer-signature exposure, not the number of randomized credential presentations. [Tight Security for BBS Signatures](https://eprint.iacr.org/2025/1973), received 22 October 2025, revised 20 February 2026 (EUROCRYPT 2026), gives a tight q-SDH reduction for once-per-message issuance, covering deterministic signing; its multiple-randomized-signatures-on-one-message result is an algebraic proof-tightness limitation, not an exploit.

This lab derives CoreSign’s e deterministically from the signing key, signed tuple and domain. Repeating the same issuance yields the same signature artifact; changing a signed field or header changes its context. Presenting the existing credential generates fresh proof randomness without issuing a new signature. The live three-presentation exhibit demonstrates that distinction. These theorems do not prove this custom DOB/age composition or browser side-channel safety.

The active baseline is now [draft-13-sha256-20261014](docs/spec-provenance.md): numbered draft-13 plus an immutable publisher fixture/tooling snapshot, source review and executed vector/boundary tests. Existing fixture bytes are unchanged. The original editor-draft/download revision remains unknown and is retained as a brief historical note; it is no longer the active reference.
