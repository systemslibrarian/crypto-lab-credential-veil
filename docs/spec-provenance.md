# Credential Veil — Spec & Fixture Provenance

Exactly which specification text, test fixtures, and library versions this lab's
claims rest on.

## Specification

- **Document:** *The BBS Signature Scheme*, `draft-irtf-cfrg-bbs-signatures` (CFRG,
  Looker / Kalos / Whitehead / Lodder). The working copy this implementation was written
  against is committed verbatim at [`spec-notes/draft-irtf-cfrg-bbs-signatures.md`](../spec-notes/draft-irtf-cfrg-bbs-signatures.md)
  (the upstream `-latest` editor's draft as committed here on 2026-07-17); that file —
  not a memory of the draft — is the source of truth for the pseudocode this repo
  hand-rolls.
- **Ciphersuite:** `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_` (BLS12-381-SHA-256),
  `api_id = ciphersuite_id ‖ "H2G_HM2S_"`, `expand_len = 48`,
  octet_scalar_length = 32, octet_point_length = 48.
- **Interface used:** the draft's *BBS Signatures Interface* (octet-string messages
  hashed via `messages_to_scalars`) for five of six credential fields; the *core*
  operations directly for the sixth (the DOB integer-scalar deviation — documented in
  [design-note.md](design-note.md), the README, and the page itself).

## Official test fixtures

- **Source:** `github.com/decentralized-identity/bbs-signature`,
  `tooling/fixtures/fixture_data/bls12-381-sha-256/` — the fixture set published by the
  draft's own tooling. Retrieved 2026-07-17 into `src/bbs/fixtures/` (committed, so the
  exact bytes tested against are in this repo's history).
- **Files and what they pin:**

  | Fixture | Pins |
  |---|---|
  | `keypair.json` | KeyGen + SkToPk (key material → sk → 96-byte pk) |
  | `h2s.json` | `hash_to_scalar` |
  | `MapMessageToScalarAsHash.json` | `messages_to_scalars`, 10 cases |
  | `generators.json` | `P1`, `Q1`, `H_1..H_10` from `create_generators` |
  | `mockedRng.json` | `seeded_random_scalars` (the draft's mocked RNG) |
  | `signature/signature001..010.json` | CoreSign/CoreVerify, valid and invalid cases (wrong key, reordered messages, no header, …) |
  | `proof/proof001..015.json` | CoreProofGen/CoreProofVerify with the mocked RNG, all-revealed / subset / none, invalid cases, no-header and no-ph variants |

- **Mocked RNG:** proof KATs require the draft's `seeded_random_scalars` in place of the
  CSPRNG; `src/bbs/bbs.ts` exposes `randFn` injection for exactly this (and the demo
  never uses the mock outside tests).

## Library versions (locked)

| Package | Version | Supplies | Explicitly NOT supplied by it |
|---|---|---|---|
| `@noble/curves` | 1.9.7 | BLS12-381 G1/G2 arithmetic, pairings (`pairingBatch`), `hash_to_curve`, `expand_message_xmd`; Ed25519 for the baseline | Anything BBS: generators, domain calculation, sign/verify, proof gen/verify — all hand-rolled in `src/bbs/` |
| `@noble/hashes` | 1.8.0 | SHA-256 | — |

Exact versions are pinned by `package-lock.json`; CI installs with `npm ci`.

## What has no external anchor

The age-predicate composition (`src/predicate/ageProof.ts`) is this lab's own
construction from standard parts (Pedersen commitments, Chaum–Pedersen OR proofs,
Schnorr proofs, sigma AND-composition). There is no official fixture set for it and no
independent implementation to differ against; its validation surface is the unit and
adversarial test suite plus the write-up in [design-note.md](design-note.md). This gap
is stated rather than papered over — it is the main reason the README says "teaching
demo, not production crypto."

## Regenerating / re-verifying fixtures

The fixtures are plain JSON committed under `src/bbs/fixtures/`. To re-verify them
against upstream, fetch the same paths from the fixture repo above and diff; to extend
coverage (e.g. more message counts), the upstream `tooling/` directory contains the
draft's fixture generator. `npm test` runs every fixture in the table on every commit
(and CI blocks deploy on it).
