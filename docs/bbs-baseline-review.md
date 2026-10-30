# BBS baseline review — 30 October 2026

Baseline ID: `draft-14-sha256-20261030`.

The active reference is [draft-irtf-cfrg-bbs-signatures-14](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-14.txt),
published 29 October 2026, a work-in-progress Internet-Draft, not a final RFC.
Publisher source and fixtures are pinned to [434522cf17ad970707080a62ce5ac19bcdb82acd](https://github.com/decentralized-identity/bbs-signature/tree/434522cf17ad970707080a62ce5ac19bcdb82acd).
Exact hashes are in [provenance-pins.json](provenance-pins.json).
The [draft-13 review](bbs-baseline-review-draft-13.md) is retained as a historical record.

## Draft-13 to draft-14 comparison

Read both numbered IETF text publications and the publisher Markdown diff from
`104bdcd85869ac05d1c621e064222441404e019b` to `434522cf17ad970707080a62ce5ac19bcdb82acd`.
The previous draft hash is `78b71f9a4bcdf57fbce694b015ed22bcf5b71ff5263b8f8d57ae2bbcf6514cd2`;
the current hash is `ca04783ff6350eb7953d1e7fca44be8cba471742a901a9b4bb130357d06f13a4`.

- §4.2.3 removes the incorrect `L == 0` abort. Removed only that rejection
  from `calculateDomain`. With zero messages, the generator list still contains
  Q1; the public key, zero message count, generator and header still enter the
  domain. An empty generator list remains invalid at the core interface.
- §3.7 clarifies disclosed fields and the `5 + U` randomness count and corrects
  the disclosed-index upper bound to `L - 1`. The local separate helper arguments,
  `assertIndexes`, randomness count and point sums already implement these rules.
  The lab does not expose the draft's `ProofInitRes` object API verbatim.
- §4.2.4 clarifies multi-exponentiation. Local sums already iterate over every
  message exactly once. §4.2.5 corrects serialization descriptions and enumerates
  all three proof points; the local parser already checks all three. Appendix F
  corrects the reference-paper response equation and pairing notation; the local
  response and verification equations are unchanged.
- Other edits fix wording, cross-references and vector labels. A comparison of
  263 extracted hex literals (including wrapped byte strings and scalars) from
  §8 and Appendix D found identical values. More decisively for the implemented
  SHA-256 scope, all 30 local fixture files match the new publisher snapshot
  byte for byte. The publisher diff changes only its specification Markdown;
  fixture/tooling/license files are unchanged. No expected output was regenerated.

## Empty-message regression evidence

The test retains the frozen signature/proof captured before the draft-13 upgrade
at lab commit `51e6c70`, with fixed key/header/presentation header and scalars 1–5.
Draft-14 now accepts these bytes; new signing and deterministic proof generation
must reproduce them. They are local regression evidence, not publisher vectors.
Additional tests exercise normal random proofs with empty/nonempty headers and
presentation headers; wrong headers, key, encodings and index 0 are rejected.
Separate controls distinguish `[]`, `[empty bytes]`, and a populated credential
whose presentation discloses no messages. Existing malformed scalar, subgroup,
proof-slot and index tests remain. The six-field learner flow is unchanged.

## Scope and review matrix

| Draft section | Local implementation reviewed | Executed evidence |
| --- | --- | --- |
| 3.4, key generation/public key | `keyGen`, `skToPk` | Publisher keypair; reject zero, negative and modulo-r key aliases; reject a supplied PK that does not correspond to SK. |
| 4.1.1, 7.2.2, generators/suite | `createGenerators`, `interfaceGenerators`, `P1` | Fixed P1/Q1/H1–H10 bytes; SHA-256/API identifiers, scalar order, invalid counts. SHAKE is outside the implementation. |
| 4.1.2, 4.2.2, message mapping/hash | `messagesToScalars`, `hashToScalar` | Ten message/scalar cases and hash-to-scalar vector; domain separation and empty messages. |
| 4.2.1, 8.1, scalar generation | `calculateRandomScalars`, `seededRandomScalars` | Publisher seeded RNG outputs and each proof's frozen intermediates; malformed count rejection. The mocked RNG is confined to tests. |
| 3.6.1–2, 4.2.3, sign/verify/domain | `coreSign`, `coreVerify`, `calculateDomain`, `sign`, `verify` | All 10 publisher signature cases, valid signing outputs, independent `(SK+e)A=B` comparison to publisher B traces, changed headers/messages/keys and scalar bounds. |
| 3.6.3–4, 3.7.1–5, proof operations | `coreProofGen`, `coreProofVerify`, Init/Finalize/Challenge functions, `proofGen`, `proofVerify` | All 15 publisher proof cases; positive proof byte outputs; generation and verification Abar/Bbar/D/T1/T2/domain/challenge traces; empty message values and no/some/all disclosure, wrong header/PH/key/messages, index rules. |
| 4.2.5, Appendix B, encoding/subgroups | signature/proof/point parsing, serialization | Compressed encodings, exact lengths, nonidentity points, zero/out-of-range scalars in every proof slot, malformed flags/coordinates, G1 order-three point rejection, strict hex decoding. Curve/subgroup arithmetic is supplied by noble. |

The review read the numbered draft's procedures and input domains against
`src/bbs/bbs.ts`, `generators.ts` and `ciphersuite.ts`. It also read the pinned
publisher fixture-population code. That tooling populates documents from
committed values; it does not generate the cryptographic vectors. No claim is
made to have regenerated the publisher's fixtures with their original engine.

All 30 fixture files match the selected upstream commit byte for byte. The
numbered draft includes the primary SHA-256 vectors and additional cases;
the publisher repository supplies the full local 10-signature/15-proof corpus.
Tests use publisher outputs, not outputs generated by this lab as expectations.

## Verification

```
npm run check:provenance -- --fetch-reference --fetch-upstream
npm test
npm run build
npm run test:a11y
```

Local checks verify the immutable manifest and complete fixture inventory.
Remote checks additionally hash the numbered draft and all 35 publisher artifacts.
Browser checks verify the visible draft correction and the existing learner flows;
GitHub Actions gates deployment on all four browser projects. Test outcomes are
recorded with the published commit/workflow rather than inferred from source text.

## Boundaries of this evidence

This establishes the declared SHA-256 BBS core baseline and its publisher-vector
compatibility. It is not a certification of every optional ciphersuite/interface,
constant-time behavior, browser entropy, production privacy or a complete wallet.
Typed low-level helpers assume the declared point/byte input types; they are not
general untrusted-object decoders. Generator/ciphersuite assumptions and published
security-model conditions remain necessary.

The integer-DOB mapping and the additional age-predicate challenge transcript
are custom teaching extensions. Their existing adversarial tests remain in the
suite, but the BBS draft vectors do not validate that composition. They remain
clearly disclosed in the demo, README and design note.

The original July source revision remains unknown. Current fixture bytes and
previous provenance are preserved in Git at `de715f85a46ceb98b7cbbf013c451e193da78e07`;
the new active baseline is not retroactively claimed to be that original source.
