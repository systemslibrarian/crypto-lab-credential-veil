# Credential Veil — crypto-lab

Anonymous credentials with **BBS+ selective disclosure** over BLS12-381, in the browser. Prove you're over 18 from a signed credential containing your birth date — without showing the birth date, without showing the signature, and without the verifier being able to link this presentation to the last one.

## What It Is

A signed credential (a JWT, a mobile driver's license) is an **all-or-nothing artifact**: to prove one field, you hand over the whole document plus the signature that binds it — and that signature is a stable byte string that links every place you show it. BBS signatures (Boneh–Boyen–Shacham lineage, modernized by Camenisch–Drijvers–Lehmann, standardized in **draft-irtf-cfrg-bbs-signatures**) break that: the issuer signs N messages once; the holder proves knowledge of that signature while revealing only the k messages they choose, in a freshly randomized presentation each time.

**What's real:** the BBS implementation on this page is hand-rolled to the draft's pseudocode (ciphersuite **BLS12-381-SHA-256**) on top of `@noble/curves` for the BLS12-381 pairing arithmetic, and passes the official fixture KATs — signing, verification, proof generation and proof verification. The Ed25519 baseline, the Pedersen-commitment age range proof, and the status-list bitstring are also real and run live.

**What's simulated:** the credential itself (issuer, wallet, fields) is a stage prop; keys are generated per session and live only in tab memory.

**What it does NOT prove:** that a deployment is private in practice. Issuer–verifier collusion, network metadata, and revealing self-identifying values (your name is your name) are all outside what the math protects. Revocation privacy is presented as an open tension, not a solved problem. **Not production crypto — a teaching demo.** The implementation is not constant-time and has seen no side-channel review.

One deliberate encoding deviation, for honesty: five credential fields are mapped to scalars exactly as the draft's signatures interface does (`messages_to_scalars`); the **DOB field is signed as its integer day count** so the age range proof can do arithmetic on it. The draft's core operations take scalars directly, so this stays within the core; only that one field's message-to-scalar mapping is custom. The age proof extends the draft's Fiat–Shamir challenge with the Pedersen-link and range-proof transcript (a standard sigma-protocol AND composition) — that extension is this lab's, not the draft's.

## Exhibits

1. **The problem: all-or-nothing disclosure** — prove "over 18" with an Ed25519-signed credential and watch the verifier receive all six fields plus a reusable signature. Signature valid; privacy verdict: broken. The two indicators disagree on purpose.
2. **Selective disclosure (the headline)** — check exactly the fields to reveal; step through issuer-signs-once → holder-chooses → re-randomize-and-prove → verifier-checks-a-pairing, with the real artifacts at every step. The hidden fields aren't redacted on the verifier's side — they're *absent*, and the signature never appears. Then **break it yourself**: tamper a revealed value after proving and hand it to the real verifier.
3. **Unlinkability** — present the same credential three times; the page diffs the proof bytes (any 8-byte run shared by all three would be highlighted — there are none). Flip to Ed25519: the identical signature, three times. You do the diff.
4. **Age ≥ 18 predicate** — a bit-decomposition range proof over a Pedersen commitment, challenge-linked into the BBS proof so the committed value *is* the signed DOB. The verifier learns one bit. Try it honestly with a 2010 birth date (no proof exists), then force a forgery and watch the real verifier separate "genuine signature" from "impossible transcript".
5. **Revocation, the honest tension** — a real status-list bitstring. Revoke bit #17, check it as the verifier, and read the price: the index is a stable correlation handle that undoes the unlinkability you just saw. Stated, not solved.
6. **What hides what, from whom** — BBS+ vs blind signatures (signer-blind at issuance, still all-or-nothing at showing) vs ring signatures (hides *who*, not *what*) vs plain JWT/mDL.

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
- **Issuer collusion** — the issuer knows all fields and the public key it signed under; issuer+verifier collusion at scale is a governance problem, not a math problem.
- **Bad randomness in proof generation** — BBS proof security leans on fresh uniform scalars per presentation; a repeated blinding scalar can leak hidden messages.

## Real-World Usage

- **draft-irtf-cfrg-bbs-signatures** (CFRG) — the standardization this lab implements, with its official test vectors.
- **W3C Verifiable Credentials / Data Integrity BBS cryptosuites** — selective-disclosure VC presentations.
- **ISO mDL / mdoc privacy work** and government digital-identity pilots evaluating BBS for unlinkable age/attribute proofs.
- Lineage: CL signatures → Idemix (IBM), U-Prove (Microsoft), Hyperledger AnonCreds — the same problem, earlier algebra.

## How to Run Locally

```bash
npm ci
npm run dev        # local dev server
npm test           # unit tests incl. official spec KATs
npm run build      # typecheck + production build
npm run test:a11y  # axe-core WCAG 2.1 A/AA gate, both themes (uses port 4351)
```

## Related Demos

- [crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) — the BLS12-381 pairing this lab consumes as a primitive.
- [crypto-lab-blind-sign](https://systemslibrarian.github.io/crypto-lab-blind-sign/) — blind at *issuance* (the signer can't see), where BBS is blind at *showing* (the verifier can't see).
- [crypto-lab-bulletproofs](https://systemslibrarian.github.io/crypto-lab-bulletproofs/) — the logarithmic-size range proof; this lab uses the inspectable O(n) bit decomposition instead.
- [crypto-lab-ring-sign](https://systemslibrarian.github.io/crypto-lab-ring-sign/) — anonymity among a set of signers, not selective disclosure of attributes.

## Build & Verify

- **66 unit tests** (Vitest), colocated in `src/`, all executed in CI before deploy.
- **25 official spec KATs** from the draft-irtf-cfrg-bbs-signatures fixtures (BLS12-381-SHA-256): 10 signature, 15 proof — plus keypair, hash-to-scalar, 10 message-to-scalar cases, the full generator set (P1, Q1, H1–H10), and the mocked-RNG vectors, in `src/bbs/fixtures/`.
- **Accessibility gate:** `@axe-core/playwright` scans the production build in **both themes** after driving every exhibit to its post-interaction state; zero WCAG 2.1 A/AA violations required for deploy (`.github/workflows/deploy.yml`).

## Performance

Everything runs on the main thread with `@noble/curves` (pure JS, no WASM). A selective-disclosure proof takes well under a second; the age-predicate proof does ~50 extra group operations plus a pairing and takes a few seconds — the buttons say so while they work. Nothing is precomputed or faked to hide that cost.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
