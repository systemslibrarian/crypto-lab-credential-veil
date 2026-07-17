# Credential Veil — Cryptographic Design Note

**Read this first if you are reviewing the cryptography.** This document states exactly
what each proof in this lab proves, which parts are standard
draft-irtf-cfrg-bbs-signatures and which parts are this lab's extensions, and why the
extensions are sound. Companion documents: [threat-model.md](threat-model.md) (who is
protected from whom) and [spec-provenance.md](spec-provenance.md) (which draft, which
fixtures, which library versions).

**Status: teaching demo.** Nothing here has had independent cryptographic review, and no
constant-time or side-channel claims are made. See [Known security
limitations](#known-security-limitations).

---

## Module map

| Module | Contents | Standard or custom |
|---|---|---|
| `src/bbs/ciphersuite.ts` | BLS12-381-SHA-256 suite constants, I2OSP/OS2IP, `hash_to_scalar`, `serialize`, point (de)serialization with subgroup checks, pairing-product check | Standard (draft §Ciphersuites), on top of `@noble/curves` |
| `src/bbs/generators.ts` | `create_generators` chain, cached interface generators, the fixed base `P1` | Standard (draft §Generators Calculation) |
| `src/bbs/bbs.ts` | KeyGen, `messages_to_scalars`, CoreSign/CoreVerify, CoreProofGen/CoreProofVerify and their Init/Challenge/Finalize internals, the signatures interface | Standard (draft pseudocode), **plus one extension hook** (`extra` on `proofChallenge`) |
| `src/credential/credential.ts` | The six-field demo credential, field→scalar mapping, present/verifyPresentation | Mostly standard usage; **one custom mapping** (DOB, below) |
| `src/predicate/ageProof.ts` | The linked age≥18 range proof | **This lab's extension** (standard sigma-protocol building blocks, composed here) |
| `src/baseline/ed25519.ts` | The all-or-nothing Ed25519 baseline | Standard Ed25519 via `@noble/curves` |
| `src/revocation/statusList.ts` | Published status-list bitstring | Trivial; the point is the privacy analysis, not the code |

Everything BBS-specific is hand-rolled to the draft's pseudocode; `@noble/curves`
supplies only BLS12-381 group arithmetic, pairings, and `expand_message_xmd` /
`hash_to_curve`. The KATs in `src/bbs/fixtures/` pin the hand-rolled parts to the
official fixture outputs (see [spec-provenance.md](spec-provenance.md)).

---

## Statement 1 — selective-disclosure presentation

**What the proof proves.** For issuer public key `W`, header `crypto-lab-credential-veil/demo-driver-license/v1`,
and disclosed pairs `{(i, m_i) : i ∈ R}`:

> "I know a valid BBS signature `(A, e)` under `W` over `L = 6` messages whose values at
> the disclosed indexes `R` are exactly the disclosed scalars, and I know the values of
> the undisclosed messages."

This is the draft's CoreProofGen/CoreProofVerify, unmodified (the `extra` hook is empty
for plain presentations, which makes the challenge input byte-identical to the draft's
ProofChallengeCalculate — verified by the proof KATs). Zero-knowledge and unlinkability
come from the fresh random scalars `(r1, r2, ẽ, r̃1, r̃3, m̃_j)` per presentation; the
signature point is re-randomized as `Ā = A·(r1·r2)` so no byte of the signature appears
in any proof.

**Verifier inputs.** Only: proof octets, disclosed `(index, field-value)` pairs, issuer
public key, the two headers. The verifier recomputes disclosed scalars from the claimed
field values itself (`verifyPresentation`), so lying about a disclosed value changes the
challenge input and verification fails — that is the "tamper" exhibit.

## Statement 2 — age predicate (this lab's extension)

**What the proof proves.** For a public cutoff day-count `t` (the latest birth date that
is ≥18 years old on the check date):

> "I know a valid BBS signature under `W` over 6 messages, none disclosed, **and** the
> message at the DOB index is an integer `dob` with `0 ≤ t − dob < 2^15`."

That is exactly "born on or before the cutoff" — one bit. It is an AND-composition of
four sigma protocols sharing **one** Fiat–Shamir challenge `c`:

1. **The BBS proof itself** (standard, nothing disclosed).
2. **Commitment link.** A Pedersen commitment `C = G·dob + H·r_c` over generators
   `(G, H)` with unknown discrete-log relation (derived by the draft's
   `create_generators` chain under the distinct DST suffix `H2G_HM2S_PREDICATE_`, so
   they are independent of the BBS generators and of each other). Its Schnorr
   commitment is `T3 = G·m̃_dob + H·r̃_c` where `m̃_dob` is **the same blinding scalar
   the BBS proof uses for the undisclosed DOB message**. The verifier recomputes
   `T3 = G·m̂_dob + H·r̂_c − C·c` using `m̂_dob` taken **from inside the BBS proof**
   (`mHat[DOB_INDEX]`; positions match field order because nothing is disclosed).
3. **Bit commitments.** `C_i = G·b_i + H·r_i` for `i = 0..14`, each with a
   Chaum–Pedersen OR proof that `C_i ∈ ⟨H⟩` or `C_i − G ∈ ⟨H⟩` (i.e. `b_i ∈ {0,1}`),
   using the standard simulated-branch technique with challenge shares
   `c_0 + c_1 = c (mod r)`.
4. **Bit-sum consistency.** A Schnorr proof on base `H` that
   `P = Σ 2^i·C_i + C − G·t` lies in `⟨H⟩`.

**Soundness intuition, step by step.**

- Expanding `P` over the generators:
  `P = G·(Σ 2^i·b_i + dob − t) + H·(Σ 2^i·r_i + r_c)`.
  If `P ∈ ⟨H⟩` and the DL of `H` to base `G` is unknown, the `G`-coefficient must be
  zero: `Σ 2^i·b_i = t − dob`. A prover producing a valid opening with a non-zero
  `G`-coefficient would yield a discrete-log relation between `G` and `H`.
- The OR proofs force each `b_i ∈ {0, 1}`, so `Σ 2^i·b_i ∈ [0, 2^15)`. Combined:
  `0 ≤ t − dob < 2^15`, the predicate.
- The commitment link (2) forces the `dob` inside `C` to be the same value the issuer
  signed: extracting from the two transcripts that share `m̃_dob` and `c` gives equal
  openings, and a prover who used a different committed value makes the verifier's
  recomputed `T3` differ, which changes the challenge input, which makes the challenge
  check fail. Sharing one blinding scalar and one challenge across transcripts is the
  standard sigma-protocol equality/AND composition.
- All predicate material (`C`, `T3`, `T_Δ`, every `C_i`, both OR-proof `a`-values per
  bit, `t`, and `N_BITS`) is serialized into the challenge via the `extra` hook using the
  draft's own `serialize` encoding, so none of it can be swapped after the fact. The
  presentation header `ph` is left empty for predicate presentations because the
  predicate context rides in `extra` instead.

**The Fiat–Shamir extension is the only change to BBS itself.** `proofChallenge` takes
an `extra: SerializableElement[]` parameter appended between the draft's transcript
elements and the `ph` length framing. With `extra = []` the byte stream is identical to
the draft's (KAT-verified). This is a *transcript extension*, not a change to
ProofInit/ProofFinalize/ProofVerifyInit; a standard BBS verifier would not accept these
predicate presentations (by design — the statement being proven is different).

**Why the forged proof fails the way it does.** The forge path commits to
`v mod 2^15` (the only value for which bit proofs exist) instead of the true negative
`v`. The pairing check still passes — a genuine signature really is behind the proof —
but the bit-sum consistency cannot reach the committed DOB, so the recomputed challenge
differs and `bbsChallengeOk` fails. The demo surfaces both results separately on
purpose: "signature genuine" and "transcript impossible" teach where soundness actually
lives.

## The DOB encoding deviation

Five fields are mapped to scalars exactly as the draft's signatures interface does:
`hash_to_scalar("key:value", api_id ‖ "MAP_MSG_TO_SCALAR_AS_HASH_")`. The DOB field is
instead signed as the **integer scalar of its day count** (days since 1900-01-01, UTC).

- **Why:** a range proof needs arithmetic structure. `hash_to_scalar(dob)` is a random
  element of a 255-bit field; "hashed DOB ≤ hashed cutoff" is meaningless.
- **Where it lives:** the draft's *core* operations take scalars directly; only the
  message-to-scalar mapping for this one field is custom. Nothing inside
  CoreSign/CoreProofGen changes.
- **Invariants required:**
  - `dobToDays` rejects values outside `[0, 2^20)`, so the scalar is a small positive
    integer, far below the group order `r` — no modular wraparound in `t − dob`.
  - Both prover and verifier recompute the mapping from the ISO date string; a disclosed
    DOB in a plain presentation is verified through the same mapping
    (`verifyPresentation` special-cases the `dob` key).
  - `N_BITS = 15` bounds the provable difference at 2^15 days ≈ 89 years; a cutoff more
    than 89 years after the DOB would need a wider decomposition (fails closed: the
    honest prover throws `RangeError`).
- **Privacy note:** the DOB scalar has ~15 bits of entropy instead of a full field
  element. BBS proofs hide undisclosed messages information-theoretically (perfectly
  hiding commitments / uniform blinding), not by entropy of the message, so this does
  not weaken hiding — but it is exactly the kind of decision an auditor should check,
  which is why it is called out here, in the README, in the page copy, and in the code.

## Known security limitations

Stated here once, plainly. These are why the README says "not production crypto."

- **Not constant-time.** JavaScript `BigInt` arithmetic is variable-time;
  `@noble/curves` makes a best effort but this lab adds unreviewed scalar handling on
  top (bit decomposition loops directly on secret values, branch on `b === 1`, etc.).
  Timing/side-channel review has never been done.
- **Browser RNG dependence.** All blinding scalars come from `crypto.getRandomValues`.
  A repeated or biased blinding scalar can leak hidden messages — BBS proof security
  requires fresh uniform scalars per presentation.
- **In-browser execution.** Proofs run in a dedicated Web Worker (`src/worker/`) —
  that keeps the page responsive, but it is a scheduling boundary, not a security
  boundary: co-resident JS in the same origin can still observe coarse timing and read
  worker payloads.
- **No serialization versioning.** `AgeProof` hex fields and `Presentation` shapes are
  demo-internal and unversioned; nothing rejects cross-version artifacts.
- **Key management is a stage prop.** Keys are generated per tab session and never
  stored, rotated, or protected.
- **Revocation is deliberately unsolved.** The status-list index is a stable
  correlation handle; the page says so. Accumulator-based ZK non-revocation is named,
  not built.
- **The predicate composition is this lab's own.** The core BBS path is pinned by
  official KATs; the age-proof composition has unit/adversarial tests (including
  forged-witness, tampered-commitment, swapped-bit, wrong-cutoff, wrong-issuer cases)
  but **no external validation surface** — there is no independent implementation of
  this exact composition to differ against. Treat it as reviewable teaching material,
  not a vetted protocol.

## Review checklist (suggested reading order)

1. `docs/spec-provenance.md` — what "standard" means here, and which bytes pin it.
2. `src/bbs/ciphersuite.ts` then `src/bbs/generators.ts` — the suite floor.
3. `src/bbs/bbs.ts` against the draft pseudocode, with `src/bbs/bbs.test.ts` open
   (KATs name their fixture files).
4. `src/credential/credential.ts` — the DOB mapping and both sides of presentation.
5. `src/predicate/ageProof.ts` against Statement 2 above — check the challenge
   serialization order in `challengeExtras` matches between prover and verifier, check
   the `T3`/`T_Δ` recomputations, check the OR-proof branch simulation.
6. `docs/threat-model.md` — what none of the above protects.
