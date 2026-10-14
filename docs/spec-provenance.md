# Credential Veil — Spec & Fixture Provenance

The active baseline is **draft-13-sha256-20261014**, established 14 October 2026:
a numbered BBS draft, an immutable publisher source/fixture snapshot, a
source review of the declared SHA-256 BBS operations, and executed tests.
This is a reproducible implementation baseline, not a final standard or
certification of the complete credential application.

## Specification

- **Active specification:** [draft-irtf-cfrg-bbs-signatures-13](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-13.txt), published 13 October 2026, SHA-256 `78b71f9a4bcdf57fbce694b015ed22bcf5b71ff5263b8f8d57ae2bbcf6514cd2`. This is a work-in-progress Internet-Draft, not a final RFC. The source review covers the SHA-256 ciphersuite, key generation, message mapping, generator derivation, domain/challenge calculation, signing, verification, proof generation/verification and encoding checks. See the [review and evidence matrix](bbs-baseline-review.md).
- **Active publisher snapshot:** [decentralized-identity/bbs-signature at 104bdcd85869ac05d1c621e064222441404e019b](https://github.com/decentralized-identity/bbs-signature/tree/104bdcd85869ac05d1c621e064222441404e019b), the snapshot including the domain-length and multi-exponentiation corrections present in numbered draft-13. All 30 local SHA-256 fixture files match that snapshot **byte for byte**. This commit is newly selected for validation, not claimed to be the original July download revision.
- **Integrity record:** [provenance-pins.json](provenance-pins.json) records the numbered draft hash, immutable upstream commit, five publisher source/tooling/license hashes, exact upstream paths and all 30 fixture hashes. `npm run check:provenance` checks the complete inventory, immutable metadata and local bytes. `npm run check:provenance -- --fetch-reference --fetch-upstream` additionally retrieves and hashes the numbered draft and all 35 publisher artifacts. Those remote checks were executed when establishing this baseline.
- **Ciphersuite:** `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_` (BLS12-381-SHA-256),
  `api_id = ciphersuite_id ‖ "H2G_HM2S_"`, `expand_len = 48`,
  octet_scalar_length = 32, octet_point_length = 48.
- **Interface used:** the draft's *BBS Signatures Interface* (octet-string messages
  hashed via `messages_to_scalars`) for five of six credential fields; the *core*
  operations directly for the sixth (the DOB integer-scalar deviation — documented in
  [design-note.md](design-note.md), the README, and the page itself).

## Versioned publisher test fixtures

- **Source:** [SHA-256 fixtures at the pinned publisher commit](https://github.com/decentralized-identity/bbs-signature/tree/104bdcd85869ac05d1c621e064222441404e019b/tooling/fixtures/fixture_data/bls12-381-sha-256).
  The draft's publisher distributes these values alongside its document-population
  tooling. The tooling inserts existing vector values into the document; it is
  not claimed here to regenerate their cryptographic outputs. This lab computes
  those outputs independently using its own BBS code and noble curve primitives.
  Existing local fixture bytes are retained unchanged.
- **License:** the publisher's Apache-2.0 license is retained in
  [BBS-FIXTURES-LICENSE.txt](BBS-FIXTURES-LICENSE.txt). The lab's own code remains
  under its repository license.
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
| `@noble/curves` | 2.4.0 | BLS12-381 G1/G2 arithmetic, pairings (`pairingBatch`), `hash_to_curve`, `expand_message_xmd`; Ed25519 for the baseline | Anything BBS: generators, domain calculation, sign/verify, proof gen/verify — all hand-rolled in `src/bbs/` |
| `@noble/hashes` | 2.4.0 | SHA-256 | — |

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

The fixtures are plain JSON committed under `src/bbs/fixtures/`. The remote check
above verifies their exact match to the newly pinned upstream snapshot. `npm test`
runs every fixture in the table, intermediate-trace assertions, input-boundary
controls and existing credential/age-proof adversarial tests; CI gates deployment.
Do not update expected outputs from the local implementation to make a test pass.
For a future draft upgrade, select a new numbered reference and upstream commit,
review differences and validate their publisher vectors before changing this pin.

## Brief historical note

The earlier editor snapshot and original fixture-download revision were not
established. The prior provenance record and all original fixture bytes are
preserved at [de715f85a46ceb98b7cbbf013c451e193da78e07](https://github.com/systemslibrarian/crypto-lab-credential-veil/tree/de715f85a46ceb98b7cbbf013c451e193da78e07).
The prior verified draft-12 baseline remains recorded at [51e6c70](https://github.com/systemslibrarian/crypto-lab-credential-veil/tree/51e6c70b5d44cf01d7d75d7b63034f5f71b5cf90).
The draft-13 upgrade establishes the current source and validation evidence without
rewriting that history.
