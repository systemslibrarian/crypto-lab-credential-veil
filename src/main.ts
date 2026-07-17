import './style.css'
import { bytesToHex, ascii } from './bbs/ciphersuite'
import {
  FIELD_KEYS,
  FIELD_LABELS,
  cutoffDays,
  type CredentialFields,
  type FieldKey,
  type Presentation,
} from './credential/credential'
import { N_BITS, type AgeProof, type AgeVerdict } from './predicate/ageProof'
import { StatusList } from './revocation/statusList'
import { CancelledError, CryptoClient } from './worker/client'
import type { SetupResult } from './worker/cryptoWorker'

// ---------------------------------------------------------------------------
// tiny DOM helpers
// ---------------------------------------------------------------------------

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v)
  node.append(...children)
  return node
}

function byId<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id)
  if (!node) throw new Error('missing #' + id)
  return node as T
}

const nextFrame = () => new Promise<void>((resolve) => requestAnimationFrame(() => setTimeout(resolve, 30)))

/** Raw cryptographic result — deliberately neutral: it is a fact, not a verdict. */
function rawIndicator(text: string): HTMLElement {
  return el('p', { class: 'indicator indicator-raw' }, [
    el('span', { class: 'ind-label' }, ['Cryptographic result']),
    text,
  ])
}

/** Security verdict — color tracks SYSTEM INTEGRITY, never the raw return value. */
function verdictIndicator(kind: 'ok' | 'alarm' | 'warn', text: string): HTMLElement {
  const icon = kind === 'ok' ? '✓' : kind === 'alarm' ? '✗' : '⚠'
  return el('p', { class: `indicator indicator-${kind}` }, [
    el('span', { class: 'ind-label' }, ['Security verdict']),
    `${icon} ${text}`,
  ])
}

function hexBlock(label: string, hex: string, html?: string): HTMLElement {
  const block = el('div', {
    class: 'hexblock',
    tabindex: '0',
    role: 'region',
    'aria-label': label,
  })
  if (html !== undefined) block.innerHTML = html
  else block.textContent = hex
  return el('div', {}, [el('h4', {}, [label]), block])
}

function verifierView(title: string, children: (Node | string)[]): HTMLElement {
  return el('div', { class: 'verifier-view' }, [el('h4', {}, [title]), ...children])
}

function setBusy(button: HTMLButtonElement, busyText: string): () => void {
  const original = button.textContent ?? ''
  button.disabled = true
  button.textContent = busyText
  return () => {
    button.disabled = false
    button.textContent = original
  }
}

function statusLine(text: string): HTMLElement {
  return el('p', { class: 'status-line', role: 'status' }, [text])
}

/**
 * Run one exhibit action with a busy button that ALWAYS recovers: cancel and
 * worker failures render into `out` instead of leaving a stuck button. The
 * crypto client self-heals (respawn + one retry) before an error reaches here.
 */
async function guarded(out: HTMLElement, button: HTMLButtonElement, busyText: string, work: () => Promise<void>): Promise<void> {
  const done = setBusy(button, busyText)
  try {
    await work()
  } catch (err) {
    if (err instanceof CancelledError) {
      out.replaceChildren(statusLine('Cancelled — the worker was stopped mid-proof; nothing was produced.'))
    } else {
      out.replaceChildren(
        statusLine(
          `The crypto worker failed (${err instanceof Error ? err.message : String(err)}). ` +
            'A fresh worker has been started — try the button again.',
        ),
      )
    }
  } finally {
    done()
  }
}

// ---------------------------------------------------------------------------
// demo state (all per-session, in memory only). The cryptography itself runs
// in a Web Worker (src/worker/) so multi-second pairing math never freezes
// this page; the state below is plain data, structured-cloned per call.
// ---------------------------------------------------------------------------

const ADULT_FIELDS: CredentialFields = {
  name: 'Avery Stone',
  dob: '1999-04-12',
  address: '12 Elm St, Springfield',
  license: 'D1234-5678',
  class: 'C',
  expiry: '2030-01-01',
}
const MINOR_FIELDS: CredentialFields = { ...ADULT_FIELDS, name: 'Riley Stone', dob: '2010-06-01' }

const todayIso = new Date().toISOString().slice(0, 10)
const CUTOFF = cutoffDays(todayIso, 18)
const cutoffIso = (() => {
  const [y, m, d] = todayIso.split('-').map(Number)
  const c = new Date(Date.UTC(y, m - 1, d))
  c.setUTCFullYear(c.getUTCFullYear() - 18)
  return c.toISOString().slice(0, 10)
})()

const client = new CryptoClient()

let state: SetupResult | null = null
let lastPresentation: Presentation | null = null

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

function renderCredentialCard(): void {
  const card = byId('credential-card')
  card.replaceChildren(
    ...FIELD_KEYS.map((k) =>
      el('div', { class: 'cred-field' }, [
        el('span', { class: 'cred-key' }, [FIELD_LABELS[k]]),
        el('span', { class: 'cred-value' }, [ADULT_FIELDS[k]]),
      ]),
    ),
  )
}

function renderFieldPicker(): void {
  const picker = byId('sd-fields')
  for (const k of FIELD_KEYS) {
    const input = el('input', { type: 'checkbox', id: `sd-field-${k}` })
    ;(input as HTMLInputElement).checked = k === 'class'
    picker.append(el('label', { for: `sd-field-${k}` }, [input, `${FIELD_LABELS[k]}: ${ADULT_FIELDS[k]}`]))
  }
}

async function setup(): Promise<void> {
  renderCredentialCard()
  renderFieldPicker()
  const status = byId('setup-status')
  await nextFrame()
  status.textContent = 'Generating issuer keys and signing the credential with BBS (six messages, one signature)…'
  state = await client.call<SetupResult>('setup', [ADULT_FIELDS, MINOR_FIELDS])
  status.textContent =
    'Ready. BBS signature (one signature over all six fields): ' +
    bytesToHex(state.adult.signature).slice(0, 32) +
    '… (80 bytes). Ed25519 baseline signature also issued. Keys live only in this tab.'
  for (const id of ['baseline-run', 'sd-run', 'sd-step', 'unlink-bbs', 'unlink-ed', 'age-adult', 'age-minor', 'age-forge']) {
    byId<HTMLButtonElement>(id).disabled = false
  }
}

// ---------------------------------------------------------------------------
// exhibit 1 — the all-or-nothing baseline
// ---------------------------------------------------------------------------

function wireBaseline(): void {
  byId<HTMLButtonElement>('baseline-run').addEventListener('click', async (ev) => {
    if (!state) return
    const out = byId('baseline-out')
    await guarded(out, ev.currentTarget as HTMLButtonElement, 'Verifying…', async () => {
    const { baseline } = state!
    const valid = await client.call<boolean>('verifyEd25519', [baseline.payload, baseline.signature, baseline.publicKey])
    out.replaceChildren(
      verifierView('What the verifier receives (Ed25519 / JWT-style)', [
        el(
          'ul',
          {},
          FIELD_KEYS.map((k) => el('li', {}, [`${FIELD_LABELS[k]}: ${baseline.fields[k]}`])),
        ),
        hexBlock('Ed25519 signature — identical on every presentation', bytesToHex(baseline.signature)),
      ]),
      el('div', { class: 'result-pair', role: 'status' }, [
        rawIndicator(`Ed25519 signature verifies: ${valid} — the credential is genuine.`),
        verdictIndicator(
          'alarm',
          'PRIVACY BROKEN — the question was one bit ("over 18?"); the answer was all six fields plus a reusable signature. This is what today’s signed credentials do.',
        ),
      ]),
      statusLine(
        'Note the two indicators disagree on purpose: the cryptography worked perfectly, and the system still failed the holder.',
      ),
    )
    })
  })
}

// ---------------------------------------------------------------------------
// exhibit 2 — selective disclosure
// ---------------------------------------------------------------------------

function chosenKeys(): FieldKey[] {
  return FIELD_KEYS.filter((k) => byId<HTMLInputElement>(`sd-field-${k}`).checked)
}

function renderPresentation(pres: Presentation, verified: boolean): HTMLElement[] {
  const revealed = Object.entries(pres.disclosedFields)
  const hiddenCount = FIELD_KEYS.length - revealed.length
  return [
    verifierView('What the verifier receives (BBS presentation)', [
      revealed.length
        ? el(
            'ul',
            {},
            revealed.map(([k, v]) => el('li', {}, [`${FIELD_LABELS[k as FieldKey]}: ${v}`])),
          )
        : el('p', {}, ['No fields revealed — the proof still shows a valid credential exists.']),
      el('p', {}, [
        `The other ${hiddenCount} field${hiddenCount === 1 ? '' : 's'}: absent. Not redacted, not encrypted — never sent. The issuer's signature: also never sent.`,
      ]),
      hexBlock(`BBS proof (${pres.proof.length} bytes, fresh randomness every time)`, bytesToHex(pres.proof)),
    ]),
    el('div', { class: 'result-pair', role: 'status' }, [
      rawIndicator(`BBS proof verifies: ${verified} — a valid issuer signature exists over messages including the revealed ones.`),
      verified
        ? verdictIndicator(
            'ok',
            `ACCEPT — the verifier learned the ${revealed.length} revealed value${revealed.length === 1 ? '' : 's'} and nothing else. "Verified" and "saw almost nothing" at the same time: that gap is the lab.`,
          )
        : verdictIndicator('alarm', 'REJECT — the presentation does not verify.'),
    ]),
  ]
}

function wireSelectiveDisclosure(): void {
  byId<HTMLButtonElement>('sd-run').addEventListener('click', async (ev) => {
    if (!state) return
    await guarded(byId('sd-out'), ev.currentTarget as HTMLButtonElement, 'Proving…', async () => {
      const keys = chosenKeys()
      const pres = await client.call<Presentation>('present', [
        state!.adult,
        keys,
        crypto.getRandomValues(new Uint8Array(16)),
      ])
      lastPresentation = pres
      const verified = await client.call<boolean>('verifyPresentation', [state!.issuer.pk, pres])
      byId('sd-out').replaceChildren(...renderPresentation(pres, verified))
      byId('sd-break').hidden = false
    })
  })

  // step-through of the headline mechanism, one real artifact per step
  let stepIndex = 0
  let stepData: { pres: Presentation; keys: FieldKey[]; verified: boolean } | null = null
  byId<HTMLButtonElement>('sd-step').addEventListener('click', async (ev) => {
    if (!state) return
    const button = ev.currentTarget as HTMLButtonElement
    if (stepIndex === 0) {
      await guarded(byId('sd-out'), button, 'Preparing…', async () => {
        const keys = chosenKeys()
        const pres = await client.call<Presentation>('present', [state!.adult, keys, ascii('step-through')])
        const verified = await client.call<boolean>('verifyPresentation', [state!.issuer.pk, pres])
        stepData = { pres, keys, verified }
        byId('sd-steps').replaceChildren()
      })
    }
    if (!stepData) return
    const sigHex = bytesToHex(state.adult.signature)
    const proofHex = bytesToHex(stepData.pres.proof)
    const steps: { label: string; text: string; viz: string }[] = [
      {
        label: 'Step 1 — issuer signs once',
        text: 'Six messages go in; ONE 80-byte signature (A, e) comes out. The signature binds all six together.',
        viz: `[name, DOB, address, license#, class, expiry] → σ = ${sigHex.slice(0, 24)}…`,
      },
      {
        label: 'Step 2 — holder chooses',
        text: `You checked: ${stepData.keys.length ? stepData.keys.map((k) => FIELD_LABELS[k]).join(', ') : 'nothing'}. Everything else stays in the wallet.`,
        viz: FIELD_KEYS.map((k) => (stepData!.keys.includes(k) ? `[reveal ${k}]` : `[hide ${k}]`)).join(' '),
      },
      {
        label: 'Step 3 — holder re-randomizes and proves',
        text: 'The signature is blinded with fresh randomness (A → Ā = A^(r₁r₂)) and a zero-knowledge proof of its validity is built over the hidden fields. Compare the bytes: the proof is not the signature.',
        viz: `σ starts ${sigHex.slice(0, 16)}…  |  proof starts ${proofHex.slice(0, 16)}… (${stepData.pres.proof.length} bytes, different every run)`,
      },
      {
        label: 'Step 4 — verifier checks a pairing',
        text: 'With only the revealed messages and the issuer public key, the verifier checks e(Ā, W)·e(B̄, −g₂) = 1. It never reconstructs the hidden fields or the signature.',
        viz: `ProofVerify(pk_issuer, proof, revealed) → ${stepData.verified}`,
      },
    ]
    const list = byId('sd-steps')
    const step = steps[stepIndex]
    const item = el('li', { class: 'step-active' }, [
      el('span', { class: 'step-label' }, [step.label]),
      step.text,
      el('span', { class: 'step-viz' }, [step.viz]),
    ])
    list.querySelectorAll('li').forEach((li) => li.classList.remove('step-active'))
    list.append(item)
    stepIndex += 1
    if (stepIndex >= steps.length) {
      stepIndex = 0
      button.textContent = 'Step through the mechanism (again)'
    } else {
      button.textContent = `Next step (${stepIndex + 1} of ${steps.length})`
    }
  })

  byId<HTMLButtonElement>('sd-tamper').addEventListener('click', async (ev) => {
    if (!state || !lastPresentation) return
    await guarded(byId('sd-break-out'), ev.currentTarget as HTMLButtonElement, 'Verifying tampered copy…', async () => {
    const tampered: Presentation = {
      ...lastPresentation!,
      disclosedFields: { ...lastPresentation!.disclosedFields, class: 'A' },
      disclosedIndexes: lastPresentation!.disclosedIndexes.includes(FIELD_KEYS.indexOf('class'))
        ? lastPresentation!.disclosedIndexes
        : [...lastPresentation!.disclosedIndexes, FIELD_KEYS.indexOf('class')].sort((a, b) => a - b),
    }
    const verified = await client.call<boolean>('verifyPresentation', [state!.issuer.pk, tampered])
    byId('sd-break-out').replaceChildren(
      el('div', { class: 'result-pair', role: 'status' }, [
        rawIndicator(`BBS proof verifies against the claim "class: A": ${verified}.`),
        verified
          ? verdictIndicator('alarm', 'FORGERY ACCEPTED — this must never happen; the primitive would be broken.')
          : verdictIndicator(
              'ok',
              'REJECT — you lied about a disclosed value and the real verifier caught it. The proof binds every revealed byte to the issuer’s one signature.',
            ),
      ]),
    )
    })
  })

  byId<HTMLButtonElement>('sd-honest').addEventListener('click', async (ev) => {
    if (!state || !lastPresentation) return
    await guarded(byId('sd-break-out'), ev.currentTarget as HTMLButtonElement, 'Verifying…', async () => {
      const verified = await client.call<boolean>('verifyPresentation', [state!.issuer.pk, lastPresentation!])
      byId('sd-break-out').replaceChildren(
        el('div', { class: 'result-pair', role: 'status' }, [
          rawIndicator(`BBS proof verifies: ${verified}.`),
          verified
            ? verdictIndicator('ok', 'ACCEPT — the untouched presentation still verifies.')
            : verdictIndicator('alarm', 'REJECT — unexpected: the honest presentation failed.'),
        ]),
      )
    })
  })
}

// ---------------------------------------------------------------------------
// exhibit 3 — unlinkability
// ---------------------------------------------------------------------------

/** Highlight every 8-byte window of `hex` that also appears in ALL `others`. */
function markCommonBytes(hex: string, others: string[]): { html: string; commonWindows: number } {
  const size = 16 // 8 bytes
  const flags = new Array<boolean>(hex.length).fill(false)
  let commonWindows = 0
  for (let i = 0; i + size <= hex.length; i += 2) {
    const w = hex.slice(i, i + size)
    if (others.every((o) => o.includes(w))) {
      commonWindows += 1
      for (let j = i; j < i + size; j++) flags[j] = true
    }
  }
  let html = ''
  let open = false
  for (let i = 0; i < hex.length; i++) {
    if (flags[i] && !open) {
      html += '<mark class="common-bytes">'
      open = true
    } else if (!flags[i] && open) {
      html += '</mark>'
      open = false
    }
    html += hex[i]
  }
  if (open) html += '</mark>'
  return { html, commonWindows }
}

function wireUnlinkability(): void {
  byId<HTMLButtonElement>('unlink-bbs').addEventListener('click', async (ev) => {
    if (!state) return
    await guarded(byId('unlink-out'), ev.currentTarget as HTMLButtonElement, 'Presenting 3× …', async () => {
    const presentations: Presentation[] = []
    for (let i = 0; i < 3; i++) {
      presentations.push(
        await client.call<Presentation>('present', [state!.adult, ['class'], crypto.getRandomValues(new Uint8Array(16))]),
      )
    }
    let allVerify = true
    for (const p of presentations) {
      allVerify = (await client.call<boolean>('verifyPresentation', [state!.issuer.pk, p])) && allVerify
    }
    const hexes = presentations.map((p) => bytesToHex(p.proof))
    let totalCommon = 0
    const blocks = hexes.map((h, i) => {
      const others = hexes.filter((_, j) => j !== i)
      const { html, commonWindows } = markCommonBytes(h, others)
      totalCommon += commonWindows
      return hexBlock(`Presentation ${i + 1} — proof bytes (shared 8-byte runs would be highlighted)`, h, html)
    })
    byId('unlink-out').replaceChildren(
      el('div', { class: 'present-grid' }, blocks),
      el('div', { class: 'result-pair', role: 'status' }, [
        rawIndicator(`All 3 proofs verify: ${allVerify}. Shared 8-byte runs found across all three: ${totalCommon}.`),
        totalCommon === 0 && allVerify
          ? verdictIndicator(
              'ok',
              'UNLINKABLE — three valid showings of ONE credential, with no common value for a verifier (or two colluding verifiers) to correlate.',
            )
          : verdictIndicator('alarm', 'Correlatable bytes found — this must not happen with fresh randomness.'),
      ]),
      statusLine(
        'Honest caveat: unlinkable at the cryptographic layer. If the value you reveal identifies you (a name, a license number), no cryptography can unlink that.',
      ),
    )
    })
  })

  byId<HTMLButtonElement>('unlink-ed').addEventListener('click', async (ev) => {
    if (!state) return
    await guarded(byId('unlink-out'), ev.currentTarget as HTMLButtonElement, 'Presenting 3× …', async () => {
    const { baseline } = state!
    const hex = bytesToHex(baseline.signature)
    const valid = await client.call<boolean>('verifyEd25519', [baseline.payload, baseline.signature, baseline.publicKey])
    const blocks = [1, 2, 3].map((i) =>
      hexBlock(`Presentation ${i} — Ed25519 signature (identical bytes highlighted)`, hex, markCommonBytes(hex, [hex]).html),
    )
    byId('unlink-out').replaceChildren(
      el('div', { class: 'present-grid' }, blocks),
      el('div', { class: 'result-pair', role: 'status' }, [
        rawIndicator(`All 3 presentations verify: ${valid}. The signature bytes are 100% identical each time.`),
        verdictIndicator(
          'alarm',
          'LINKABLE — the same 64 bytes at the bar on Friday, the pharmacy on Monday, and the bank on Tuesday. A valid signature that doubles as a perfect tracking cookie.',
        ),
      ]),
    )
    })
  })
}

// ---------------------------------------------------------------------------
// exhibit 4 — age predicate
// ---------------------------------------------------------------------------

function wireAge(): void {
  const out = byId('age-out')
  const cancelBtn = byId<HTMLButtonElement>('age-cancel')

  /** Run an age-proof workload with live progress on the button and a working
   *  cancel: terminating the worker is the only way to stop pairing math. */
  async function runAgeOp<T>(button: HTMLButtonElement, busyText: string, work: () => Promise<T>): Promise<T | null> {
    let result: T | null = null
    cancelBtn.hidden = false
    try {
      await guarded(out, button, busyText, async () => {
        result = await work()
      })
    } finally {
      cancelBtn.hidden = true
    }
    return result
  }

  const progressTo = (button: HTMLButtonElement, prefix: string) => (stage: string) => {
    button.textContent = `${prefix} — ${stage}…`
  }

  cancelBtn.addEventListener('click', () => client.cancel())

  byId<HTMLButtonElement>('age-adult').addEventListener('click', async (ev) => {
    if (!state) return
    const button = ev.currentTarget as HTMLButtonElement
    const result = await runAgeOp(button, 'Proving (real pairings, off the main thread)…', async () => {
      const proof = await client.call<AgeProof>(
        'proveAge',
        [state!.adult, CUTOFF, {}],
        progressTo(button, 'Proving'),
      )
      const verdict = await client.call<AgeVerdict>(
        'verifyAge',
        [state!.issuer.pk, proof, CUTOFF],
        progressTo(button, 'Verifying'),
      )
      return { proof, verdict }
    })
    if (!result) return
    const { proof, verdict } = result
    out.replaceChildren(
      verifierView('What the verifier receives', [
        el('p', {}, [
          `A BBS proof revealing zero fields, a Pedersen commitment to the hidden DOB, ${N_BITS} bit commitments, and the check date's cutoff (${cutoffIso}). No birth date anywhere.`,
        ]),
        hexBlock('Commitment to the hidden DOB (C)', proof.C),
      ]),
      el('div', { class: 'result-pair', role: 'status' }, [
        rawIndicator(
          `Range proof verifies: ${verdict.ok} (pairing check ${verdict.pairingOk ? 'passed' : 'failed'}, transcript ${verdict.bbsChallengeOk ? 'consistent' : 'inconsistent'}).`,
        ),
        verdict.ok
          ? verdictIndicator(
              'ok',
              `ACCEPT — the verifier learned exactly one bit: this credential's DOB is on or before ${cutoffIso}. Not the date, not the year, not "how far over 18".`,
            )
          : verdictIndicator('alarm', 'REJECT — ' + verdict.reason),
      ]),
    )
  })

  byId<HTMLButtonElement>('age-minor').addEventListener('click', async (ev) => {
    if (!state) return
    const button = ev.currentTarget as HTMLButtonElement
    const result = await runAgeOp(button, 'Attempting…', async () => {
      try {
        await client.call<AgeProof>('proveAge', [state!.minor, CUTOFF, {}], progressTo(button, 'Attempting'))
        return { threw: false }
      } catch (err) {
        if (err instanceof CancelledError) throw err
        return { threw: err instanceof RangeError }
      }
    })
    if (!result) return
    const { threw } = result
    out.replaceChildren(
      el('div', { class: 'result-pair', role: 'status' }, [
        rawIndicator(
          threw
            ? 'Proof generation threw RangeError: the bits of (cutoff − DOB) do not exist for a 2010 birth date.'
            : 'Unexpected: proof generation did not refuse.',
        ),
        threw
          ? verdictIndicator(
              'ok',
              'NO PROOF EXISTS — an honest prover cannot even construct one. To lie, you must forge; try the forge button.',
            )
          : verdictIndicator('alarm', 'The prover should have refused.'),
      ]),
    )
  })

  byId<HTMLButtonElement>('age-forge').addEventListener('click', async (ev) => {
    if (!state) return
    const button = ev.currentTarget as HTMLButtonElement
    const result = await runAgeOp(button, 'Forging + verifying (off the main thread)…', async () => {
      const forged = await client.call<AgeProof>(
        'proveAge',
        [state!.minor, CUTOFF, { forge: true }],
        progressTo(button, 'Forging'),
      )
      const verdict = await client.call<AgeVerdict>(
        'verifyAge',
        [state!.issuer.pk, forged, CUTOFF],
        progressTo(button, 'Verifying'),
      )
      return verdict
    })
    if (!result) return
    const verdict = result
    out.replaceChildren(
      verifierView('The forgery attempt', [
        el('p', {}, [
          'The under-18 wallet committed to the wrong difference (v mod 2¹⁵ instead of the negative truth) and produced otherwise-honest bit proofs. Real proof, real verifier — watch which check snaps.',
        ]),
      ]),
      el('div', { class: 'result-pair', role: 'status' }, [
        rawIndicator(
          `Pairing check: ${verdict.pairingOk ? 'PASSES — a genuine issuer signature really is behind this proof' : 'fails'}. Transcript check: ${verdict.bbsChallengeOk ? 'passes' : 'FAILS — the bit-sum cannot reach the committed DOB'}.`,
        ),
        verdict.ok
          ? verdictIndicator('alarm', 'FORGERY ACCEPTED — this must never happen; the primitive would be broken.')
          : verdictIndicator(
              'ok',
              'REJECT — a real credential is not enough: the algebra refuses to say "over 18" about a 2010 birth date. The system fails the liar; the primitive holds.',
            ),
      ]),
      statusLine(
        'The two raw results disagreeing — signature genuine, transcript impossible — is exactly what verdict separation is for.',
      ),
    )
  })
}

// ---------------------------------------------------------------------------
// exhibit 5 — revocation
// ---------------------------------------------------------------------------

function wireRevocation(): void {
  const list = new StatusList(64)
  const CRED_INDEX = 17
  const out = byId('revoke-out')

  const renderBits = (checked: boolean): HTMLElement => {
    const grid = el('div', { class: 'bit-grid', role: 'list', 'aria-label': 'Published status list, one bit per credential' })
    for (let i = 0; i < list.size; i++) {
      const revoked = list.isRevoked(i)
      const classes = ['bit', revoked ? 'bit-revoked' : '', checked && i === CRED_INDEX ? 'bit-checked' : '']
        .filter(Boolean)
        .join(' ')
      grid.append(
        el(
          'span',
          {
            class: classes,
            role: 'listitem',
            'aria-label': `credential ${i}: ${revoked ? 'revoked' : 'active'}${i === CRED_INDEX ? ' (this credential)' : ''}`,
          },
          [revoked ? '1' : '0'],
        ),
      )
    }
    return grid
  }

  const toggle = byId<HTMLButtonElement>('revoke-toggle')
  toggle.addEventListener('click', () => {
    if (list.isRevoked(CRED_INDEX)) {
      list.reinstate(CRED_INDEX)
      toggle.textContent = 'Revoke credential #17'
    } else {
      list.revoke(CRED_INDEX)
      toggle.textContent = 'Reinstate credential #17'
    }
    out.replaceChildren(
      renderBits(false),
      statusLine(`Issuer republished the status list. Bit #${CRED_INDEX} is now ${list.isRevoked(CRED_INDEX) ? '1 (revoked)' : '0 (active)'}.`),
    )
  })

  byId<HTMLButtonElement>('revoke-check').addEventListener('click', async (ev) => {
    if (!state) return
    await guarded(out, ev.currentTarget as HTMLButtonElement, 'Presenting + checking…', async () => {
    const pres =
      lastPresentation ??
      (await client.call<Presentation>('present', [state!.adult, ['class'], ascii('revocation-check')]))
    lastPresentation = pres
    const proofOk = await client.call<boolean>('verifyPresentation', [state!.issuer.pk, pres])
    const revoked = list.isRevoked(CRED_INDEX)
    out.replaceChildren(
      renderBits(true),
      el('div', { class: 'result-pair', role: 'status' }, [
        rawIndicator(`BBS proof verifies: ${proofOk} — the cryptography is satisfied either way.`),
        revoked
          ? verdictIndicator(
              'alarm',
              `REJECT — proof valid, credential revoked. And to check bit #${CRED_INDEX}, the wallet had to reveal the index — a stable identifier shown at every presentation.`,
            )
          : verdictIndicator(
              'warn',
              `ACCEPT, at a price — bit #${CRED_INDEX} is 0, but the verifier now holds your stable index. Every unlinkable proof you make is re-linkable through it.`,
            ),
      ]),
    )
    })
  })
}

// ---------------------------------------------------------------------------

wireBaseline()
wireSelectiveDisclosure()
wireUnlinkability()
wireAge()
wireRevocation()
void setup()
