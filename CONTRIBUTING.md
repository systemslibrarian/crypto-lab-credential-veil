# Contributing

Thanks for looking under the hood. This repo is one demo in the
[Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite; it optimizes for being
**readable and reviewable**, not for feature growth.

## Ground rules

- **One concept per demo.** New exhibits belong here only if they teach BBS selective
  disclosure better; adjacent concepts (accumulators, Bulletproofs, blind signatures)
  live in sibling demos.
- **Real crypto or clearly labeled prop.** Anything presented as cryptography must
  actually run, fail closed, and be tested. Anything simulated must say so in the UI.
- **Honest framing is load-bearing.** Changes that make claims stronger than the math
  (or soften the "not production crypto" warnings) will be declined.

## Before you open a PR

```bash
npm ci
npm test           # unit tests + official spec KATs — must be 100% green
npm run build      # tsc --noEmit gates the build
npm run test:a11y  # axe WCAG 2.1 A/AA gate (build first; uses port 4351)
```

All three are CI gates; a PR that fails any of them will not deploy.

If you touch anything cryptographic, update
[docs/design-note.md](docs/design-note.md) in the same PR — the design note must
always match the code — and add a failing-case test, not just the happy path.

## Reporting problems

- Soundness / security: see [SECURITY.md](SECURITY.md) (private advisory, please).
- Everything else: a plain GitHub issue with reproduction steps is perfect.
