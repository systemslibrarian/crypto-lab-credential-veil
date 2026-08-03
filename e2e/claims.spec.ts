import { expect, test, type Locator, type Page } from '@playwright/test'

/**
 * Functional gate for the claims this lab makes on screen.
 *
 * The a11y spec already drives every exhibit — but it only ever asserts that
 * SOMETHING rendered, never what it said. So the verdicts, the counters, the
 * byte tallies and the three break-it paths were all unasserted, in a lab
 * whose entire point is that the raw cryptographic result and the security
 * verdict deliberately disagree.
 *
 * The load-bearing assertions here are the cross-path ones — places where the
 * page states a number that the page's own output can be measured against:
 *   - the BBS proof hexblock's "(N bytes)" label == the hex it contains
 *   - "The other N fields: absent" == 6 minus the fields actually listed
 *   - the ACCEPT verdict's revealed-value count == that same list
 *   - the step-through's sigma prefix == the signature prefix in #setup-status,
 *     and its "80-byte signature" == the byte count that line states
 *   - "Shared 8-byte runs across all three: N" == the same scan run by this
 *     test over the three hex strings the page rendered
 *   - the revocation verdict's "Status bit #17 ... : 1" == the digit in cell 17
 *     of the rendered bit grid
 *   - the age cutoff date == exactly 18 years before today
 * plus the two absence claims the README leads with: the issuer's signature
 * never appears in a BBS presentation, and no birth date appears anywhere in
 * the age-predicate output.
 */

test.setTimeout(360_000)

const FIELD_COUNT = 6
const CRED_INDEX = 17
const STATUS_LIST_SIZE = 64

const DOB = '1999-04-12'
const CRED_VALUES: Record<string, string> = {
  name: 'Avery Stone',
  dob: DOB,
  address: '12 Elm St, Springfield',
  license: 'D1234-5678',
  class: 'C',
  expiry: '2030-01-01',
}

const rawOf = (page: Page, scope: string): Locator => page.locator(`${scope} .indicator-raw`)
const verdictOf = (page: Page, scope: string): Locator =>
  page.locator(`${scope} .indicator:not(.indicator-raw)`)

/** Hex content of a `.hexblock`, with any highlight markup flattened away. */
const hexIn = async (block: Locator): Promise<string> =>
  ((await block.textContent()) ?? '').replace(/\s+/g, '')

const int = (s: string | undefined): number => Number.parseInt(s ?? '', 10)

const SUPERSCRIPT = '⁰¹²³⁴⁵⁶⁷⁸⁹'
const toSuperscript = (n: number): string =>
  String(n)
    .split('')
    .map((d) => SUPERSCRIPT[Number(d)])
    .join('')

/**
 * The page's own overlap scan, re-implemented: for each hex string, count the
 * 8-byte windows that also occur in BOTH of the other two, and sum. Running it
 * here means the headline "shared runs" number is checked against the bytes the
 * page rendered rather than taken on trust.
 */
function sharedWindowTotal(hexes: string[]): number {
  let total = 0
  for (let i = 0; i < hexes.length; i++) {
    const others = hexes.filter((_, j) => j !== i)
    for (let k = 0; k + 16 <= hexes[i].length; k += 2) {
      const window = hexes[i].slice(k, k + 16)
      if (others.every((o) => o.includes(window))) total += 1
    }
  }
  return total
}

/**
 * Run an action that re-renders `scope`, and wait for output THIS action
 * produced. Marking the current render stale first matters: every handler here
 * leaves the previous result on screen while it works, so a plain
 * `toBeVisible()` on `.result-pair` returns instantly against the LAST result
 * and the assertions that follow check nothing.
 */
async function rerender(
  page: Page,
  scope: string,
  act: () => Promise<void>,
  selector = '.result-pair',
): Promise<void> {
  await page
    .locator(`${scope} ${selector}`)
    .evaluateAll((els) => els.forEach((el) => el.setAttribute('data-stale', '1')))
  await act()
  await expect(page.locator(`${scope} ${selector}:not([data-stale])`)).toBeVisible({
    timeout: 300_000,
  })
}

async function ready(page: Page): Promise<void> {
  await page.goto('.')
  // Buttons enable only once the issuer keys exist and the credential is signed.
  await expect(page.locator('#baseline-run')).toBeEnabled({ timeout: 120_000 })
  await expect(page.locator('#setup-status')).toContainText('Ready.')
}

/** The signature prefix and byte count #setup-status publishes. */
async function issuedSignature(page: Page): Promise<{ prefix: string; bytes: number }> {
  const status = (await page.locator('#setup-status').innerText()).replace(/\s+/g, ' ')
  const m = status.match(/six fields\): ([0-9a-f]+)…\s*\((\d+) bytes\)/)
  expect(m, `setup status was: ${status}`).not.toBeNull()
  return { prefix: m?.[1] ?? '', bytes: int(m?.[2]) }
}

async function setRevealed(page: Page, keys: string[]): Promise<void> {
  for (const key of Object.keys(CRED_VALUES)) {
    const box = page.locator(`#sd-field-${key}`)
    if (keys.includes(key)) await box.check()
    else await box.uncheck()
  }
}

/* ------------------------------------------- 1 — all-or-nothing baseline */

test('exhibit 1 hands over every field and a reusable signature, and says so', async ({ page }) => {
  await ready(page)

  // The card and the picker describe the same six-field credential.
  await expect(page.locator('#credential-card .cred-field')).toHaveCount(FIELD_COUNT)
  await expect(page.locator('#sd-fields input[type=checkbox]')).toHaveCount(FIELD_COUNT)

  await page.locator('#baseline-run').click()
  await expect(page.locator('#baseline-out .result-pair')).toBeVisible({ timeout: 60_000 })

  // Every field the credential holds reaches the verifier — that IS the exhibit.
  const received = await page.locator('#baseline-out .verifier-view li').allTextContents()
  expect(received).toHaveLength(FIELD_COUNT)
  for (const value of Object.values(CRED_VALUES)) {
    expect(received.join(' | ')).toContain(value)
  }

  const signature = await hexIn(page.locator('#baseline-out .hexblock'))
  expect(signature).toMatch(/^[0-9a-f]{128}$/) // Ed25519: 64 bytes
  await expect(page.locator('#baseline-out .hexblock')).toHaveAttribute(
    'aria-label',
    /identical on every presentation/i,
  )

  // The two indicators must disagree: the cryptography worked, the system failed.
  await expect(rawOf(page, '#baseline-out')).toContainText(
    'Ed25519 signature verifies: true — the credential is genuine.',
  )
  const verdict = verdictOf(page, '#baseline-out')
  await expect(verdict).toHaveClass(/indicator-alarm/)
  await expect(verdict).toContainText('PRIVACY BROKEN')
  await expect(verdict).toContainText('all six fields plus a reusable signature')
  await expect(page.locator('#baseline-out .status-line')).toContainText(
    'the two indicators disagree on purpose',
  )
})

/* ----------------------------------------------- 2 — selective disclosure */

test('exhibit 2 reveals exactly what was checked, and never the signature', async ({ page }) => {
  await ready(page)
  const { prefix: sigPrefix } = await issuedSignature(page)

  const present = async (keys: string[]): Promise<void> => {
    await setRevealed(page, keys)
    await rerender(page, '#sd-out', () => page.locator('#sd-run').click())
  }

  const checkCounts = async (keys: string[]): Promise<void> => {
    const listed = await page.locator('#sd-out .verifier-view li').allTextContents()
    expect(listed).toHaveLength(keys.length)
    for (const key of keys) {
      expect(listed.join(' | ')).toContain(CRED_VALUES[key])
    }

    const body = (await page.locator('#sd-out').innerText()).replace(/\s+/g, ' ')

    // "The other N fields: absent" must be 6 minus the fields actually listed.
    const hidden = int(body.match(/The other (\d+) fields?: absent/)?.[1])
    expect(hidden).toBe(FIELD_COUNT - keys.length)

    // The ACCEPT verdict counts the same revealed values, with plural agreement.
    const claimed = int(body.match(/the verifier learned the (\d+) revealed value/)?.[1])
    expect(claimed).toBe(keys.length)
    expect(body).toContain(`${keys.length} revealed value${keys.length === 1 ? '' : 's'} and nothing else`)

    // The hexblock's stated size must be the size of the hex inside it.
    const block = page.locator('#sd-out .hexblock')
    const declared = int(((await block.getAttribute('aria-label')) ?? '').match(/\((\d+) bytes/)?.[1])
    const hex = await hexIn(block)
    expect(hex).toMatch(/^[0-9a-f]+$/)
    expect(hex.length / 2).toBe(declared)

    // The issuer's signature is never sent — the README's headline absence claim.
    expect(sigPrefix.length).toBeGreaterThanOrEqual(16)
    expect(body).not.toContain(sigPrefix)
    expect(hex).not.toContain(sigPrefix)

    // Hidden field VALUES are absent, not redacted. Values shorter than five
    // characters are skipped: "C" occurs in ordinary page copy, so its presence
    // would say nothing about what the verifier received.
    for (const [key, value] of Object.entries(CRED_VALUES)) {
      if (!keys.includes(key) && value.length >= 5) {
        expect(body, `hidden ${key} leaked into the presentation`).not.toContain(value)
      }
    }

    await expect(rawOf(page, '#sd-out')).toContainText('BBS proof verifies: true')
    await expect(verdictOf(page, '#sd-out')).toHaveClass(/indicator-ok/)
    await expect(verdictOf(page, '#sd-out')).toContainText('ACCEPT')
  }

  // The default selection.
  await expect(page.locator('#sd-field-class')).toBeChecked()
  await present(['class'])
  await checkCounts(['class'])

  // A different selection must move every one of those numbers.
  await present(['name', 'class', 'expiry'])
  await checkCounts(['name', 'class', 'expiry'])

  // Revealing nothing still proves a credential exists, and the tamper button
  // honestly refuses because there is no disclosed value to lie about.
  await present([])
  await expect(page.locator('#sd-out .verifier-view')).toContainText(
    'No fields revealed — the proof still shows a valid credential exists.',
  )
  await expect(page.locator('#sd-out .verifier-view li')).toHaveCount(0)
  await expect(page.locator('#sd-out')).toContainText(`The other ${FIELD_COUNT} fields: absent`)
  await expect(verdictOf(page, '#sd-out')).toHaveClass(/indicator-ok/)
  const tamper = page.locator('#sd-tamper')
  await expect(tamper).toBeDisabled()
  await expect(tamper).toHaveText('Nothing revealed — no disclosed value to lie about')
})

test('exhibit 2 steps through the real artifacts, then rejects a tampered value', async ({
  page,
}) => {
  await ready(page)
  const { prefix: sigPrefix, bytes: sigBytes } = await issuedSignature(page)
  await setRevealed(page, ['class'])

  // Four steps, and the button's own counter must track the list it is building.
  for (let i = 0; i < 4; i++) {
    await page.locator('#sd-step').click()
    await expect(page.locator('#sd-steps li')).toHaveCount(i + 1, { timeout: 120_000 })
    const label = await page.locator('#sd-step').innerText()
    if (i < 3) expect(label).toBe(`Next step (${i + 2} of 4)`)
    else expect(label).toBe('Step through the mechanism (again)')
  }
  // Exactly one step is highlighted as current.
  await expect(page.locator('#sd-steps li.step-active')).toHaveCount(1)

  const steps = await page.locator('#sd-steps li').allInnerTexts()
  const flat = steps.map((s) => s.replace(/\s+/g, ' '))

  // Step 1's sigma is the signature #setup-status published, and its byte
  // count is the byte count that line states.
  expect(flat[0]).toContain(`ONE ${sigBytes}-byte signature`)
  const step1Sigma = flat[0].match(/σ = ([0-9a-f]+)…/)?.[1] ?? ''
  expect(step1Sigma.length).toBeGreaterThan(0)
  expect(sigPrefix.startsWith(step1Sigma)).toBe(true)

  // Step 2 echoes the checkbox state: one revealed, five hidden.
  expect(flat[1]).toContain('You checked: Class')
  expect((flat[1].match(/\[hide /g) ?? []).length).toBe(FIELD_COUNT - 1)
  expect((flat[1].match(/\[reveal /g) ?? []).length).toBe(1)

  // Step 3's whole point: the proof is not the signature.
  const step3 = flat[2].match(/σ starts ([0-9a-f]+)….*proof starts ([0-9a-f]+)….*\((\d+) bytes/)
  expect(step3, `step 3 read: ${flat[2]}`).not.toBeNull()
  expect(sigPrefix.startsWith(step3?.[1] ?? 'x')).toBe(true)
  expect(step3?.[2]).not.toBe(step3?.[1])
  expect(int(step3?.[3])).toBeGreaterThan(sigBytes)

  // Step 4 reports the verifier's actual return value.
  expect(flat[3]).toContain('ProofVerify(pk_issuer, proof, revealed) → true')

  // Now break it: lie about a revealed value and hand it to the real verifier.
  await rerender(page, '#sd-out', () => page.locator('#sd-run').click())
  await expect(page.locator('#sd-break')).toBeVisible()

  const tamper = page.locator('#sd-tamper')
  await expect(tamper).toBeEnabled()
  const lie = (await tamper.innerText()).match(/claim class "([^"]+)" instead/)?.[1]
  expect(lie).toBeTruthy()
  expect(lie).not.toBe(CRED_VALUES.class)

  await rerender(page, '#sd-break-out', () => tamper.click())
  // The raw result names the exact lie, and it is false.
  await expect(rawOf(page, '#sd-break-out')).toContainText(
    `BBS proof verifies against the claim "Class: ${lie}": false.`,
  )
  const tamperVerdict = verdictOf(page, '#sd-break-out')
  await expect(tamperVerdict).toHaveClass(/indicator-ok/)
  await expect(tamperVerdict).toContainText('REJECT')
  await expect(tamperVerdict).toContainText('you changed a revealed value (class) after proving')
  await expect(page.locator('#sd-break-out')).not.toContainText('FORGERY ACCEPTED')

  // And the untouched presentation still verifies, so the rejection was the lie.
  await rerender(page, '#sd-break-out', () => page.locator('#sd-honest').click())
  await expect(rawOf(page, '#sd-break-out')).toContainText('BBS proof verifies: true.')
  await expect(verdictOf(page, '#sd-break-out')).toContainText(
    'ACCEPT — the untouched presentation still verifies.',
  )
})

/* ---------------------------------------------------- 3 — unlinkability */

test('exhibit 3 measures the overlap it claims, both ways round', async ({ page }) => {
  await ready(page)
  await rerender(page, '#unlink-out', () => page.locator('#unlink-bbs').click(), '.present-grid')

  const bbsHexes = await page.locator('#unlink-out .hexblock').evaluateAll((els) =>
    els.map((el) => (el.textContent ?? '').replace(/\s+/g, '')),
  )
  expect(bbsHexes).toHaveLength(3)
  // Three showings of one credential, three different proofs.
  expect(new Set(bbsHexes).size).toBe(3)
  for (const hex of bbsHexes) expect(hex).toMatch(/^[0-9a-f]+$/)

  const bbsRaw = (await rawOf(page, '#unlink-out').innerText()).replace(/\s+/g, ' ')
  expect(bbsRaw).toContain('All 3 proofs verify: true')

  // The headline number, re-measured here from the bytes the page rendered.
  const claimedRuns = int(bbsRaw.match(/Shared 8-byte runs across all three proofs: (\d+)/)?.[1])
  expect(claimedRuns).toBe(sharedWindowTotal(bbsHexes))
  expect(claimedRuns).toBe(0)
  // Nothing highlighted, because there is nothing to highlight.
  await expect(page.locator('#unlink-out mark.common-bytes')).toHaveCount(0)

  // The honest caveat: the revealed value IS a correlator, and it is counted.
  const sharedValues = int(bbsRaw.match(/Disclosed values identical across all three: (\d+)/)?.[1])
  expect(sharedValues).toBe(1)
  expect(bbsRaw).toContain(`(Class = ${CRED_VALUES.class})`)
  const bbsVerdict = verdictOf(page, '#unlink-out')
  await expect(bbsVerdict).toHaveClass(/indicator-warn/)
  await expect(bbsVerdict).toContainText('PROOFS UNLINKABLE, DISCLOSURE IS NOT')
  await expect(bbsVerdict).toContainText(`Class = ${CRED_VALUES.class}`)
  await expect(page.locator('#unlink-out .status-line')).toContainText(
    'BBS unlinks the cryptographic layer only',
  )

  // Ed25519: the same bytes, three times.
  await rerender(page, '#unlink-out', () => page.locator('#unlink-ed').click(), '.present-grid')
  await expect(page.locator('#unlink-out .indicator-alarm')).toBeVisible({ timeout: 120_000 })

  const edHexes = await page.locator('#unlink-out .hexblock').evaluateAll((els) =>
    els.map((el) => (el.textContent ?? '').replace(/\s+/g, '')),
  )
  expect(edHexes).toHaveLength(3)
  expect(new Set(edHexes).size).toBe(1)

  const edRaw = (await rawOf(page, '#unlink-out').innerText()).replace(/\s+/g, ' ')
  expect(edRaw).toContain('3 of 3 presentations verify')
  const edRuns = int(edRaw.match(/Shared 8-byte runs across all three: (\d+)/)?.[1])
  expect(edRuns).toBe(sharedWindowTotal(edHexes))
  expect(edRuns).toBeGreaterThan(0)
  expect(edRaw).toContain('Byte-for-byte identical across all three: true')
  // A signature identical to itself overlaps in 100% of its characters.
  expect(int(edRaw.match(/\((\d+)% of the signature\)/)?.[1])).toBe(100)
  await expect(page.locator('#unlink-out mark.common-bytes')).toHaveCount(3)

  const edVerdict = verdictOf(page, '#unlink-out')
  await expect(edVerdict).toHaveClass(/indicator-alarm/)
  await expect(edVerdict).toContainText('LINKABLE')
  // The byte count in the verdict is the byte count on the wire.
  expect(int((await edVerdict.innerText()).match(/the same (\d+) bytes/)?.[1])).toBe(
    edHexes[0].length / 2,
  )
})

/* ------------------------------------------------------ 4 — age predicate */

test('exhibit 4 proves the predicate, refuses to lie, and rejects the forgery', async ({ page }) => {
  await ready(page)

  /* --- honest adult --- */
  await rerender(page, '#age-out', () => page.locator('#age-adult').click())

  const adult = (await page.locator('#age-out').innerText()).replace(/\s+/g, ' ')
  await expect(rawOf(page, '#age-out')).toContainText(
    'Range proof verifies: true (pairing check passed, transcript consistent).',
  )
  const adultVerdict = verdictOf(page, '#age-out')
  await expect(adultVerdict).toHaveClass(/indicator-ok/)
  await expect(adultVerdict).toContainText('learned exactly one bit')

  // The cutoff is stated twice; both must be the same date, and that date must
  // be exactly 18 years before today.
  const stated = adult.match(/the check date's cutoff \((\d{4}-\d{2}-\d{2})\)/)?.[1]
  const inVerdict = adult.match(/DOB is on or before (\d{4}-\d{2}-\d{2})/)?.[1]
  expect(stated, `age output read: ${adult}`).toBeTruthy()
  expect(inVerdict).toBe(stated)
  expect(Number((stated ?? '').slice(0, 4))).toBe(new Date().getUTCFullYear() - 18)

  // "No birth date anywhere" — the README's headline absence claim. The long
  // hex runs are masked out first: a random commitment can contain the digits
  // "1999" by chance, which would be noise, not a leak.
  const adultProse = adult.replace(/[0-9a-f]{32,}/g, '<hex>')
  expect(adultProse).toContain('No birth date anywhere')
  expect(adultProse).not.toContain(DOB)
  expect(adultProse).not.toContain('1999')
  expect(adultProse).not.toContain(CRED_VALUES.name)

  // The commitment is a real rendered point, not a placeholder.
  expect(await hexIn(page.locator('#age-out .hexblock'))).toMatch(/^[0-9a-f]{96}$/)
  const bits = int(adult.match(/(\d+) bit commitments/)?.[1])
  expect(bits).toBeGreaterThan(0)

  /* --- honest minor: no proof exists --- */
  await rerender(page, '#age-out', () => page.locator('#age-minor').click())
  await expect(rawOf(page, '#age-out')).toContainText('RangeError', { timeout: 300_000 })
  await expect(rawOf(page, '#age-out')).toContainText(
    'the bits of (cutoff − DOB) do not exist for a 2010 birth date',
  )
  const minorVerdict = verdictOf(page, '#age-out')
  await expect(minorVerdict).toHaveClass(/indicator-ok/)
  await expect(minorVerdict).toContainText('NO PROOF EXISTS')
  await expect(page.locator('#age-out')).not.toContainText('The prover should have refused')

  /* --- forced forgery: genuine signature, impossible transcript --- */
  await rerender(page, '#age-out', () => page.locator('#age-forge').click())
  await expect(page.locator('#age-out .verifier-view')).toBeVisible({ timeout: 300_000 })

  const forged = (await page.locator('#age-out').innerText()).replace(/\s+/g, ' ')
  // The separation is the exhibit: one check passes, the other fails.
  await expect(rawOf(page, '#age-out')).toContainText(
    'Pairing check: PASSES — a genuine issuer signature really is behind this proof',
  )
  await expect(rawOf(page, '#age-out')).toContainText(
    'Transcript check: FAILS — the bit-sum cannot reach the committed DOB',
  )
  const forgeVerdict = verdictOf(page, '#age-out')
  await expect(forgeVerdict).toHaveClass(/indicator-ok/)
  await expect(forgeVerdict).toContainText('REJECT')
  await expect(page.locator('#age-out')).not.toContainText('FORGERY ACCEPTED')

  // The forgery blurb's modulus is the same bit width the honest run reported.
  expect(forged).toContain(`v mod 2${toSuperscript(bits)}`)
})

/* ------------------------------------------------------- 5 — revocation */

test('exhibit 5 binds the status index and reads its verdict off the published bit', async ({
  page,
}) => {
  await ready(page)

  const grid = page.locator('#revoke-out .bit-grid')
  const bitAt = (i: number): Locator => grid.locator('.bit').nth(i)

  /** Every rendered bit, as its printed digit. */
  const bits = async (): Promise<string[]> =>
    grid.locator('.bit').evaluateAll((els) => els.map((el) => (el.textContent ?? '').trim()))

  await page.locator('#revoke-toggle').click()
  await expect(grid).toBeVisible()

  // The published list is a real bitstring: one cell per credential, and the
  // number of 1s is the number of revoked cells.
  let printed = await bits()
  expect(printed).toHaveLength(STATUS_LIST_SIZE)
  expect(printed.filter((b) => b === '1')).toHaveLength(1)
  expect(printed.filter((b) => b === '0')).toHaveLength(STATUS_LIST_SIZE - 1)
  expect(printed[CRED_INDEX]).toBe('1')
  await expect(page.locator('#revoke-out .bit-revoked')).toHaveCount(1)
  await expect(bitAt(CRED_INDEX)).toHaveClass(/bit-revoked/)
  await expect(bitAt(CRED_INDEX)).toHaveAttribute(
    'aria-label',
    `credential ${CRED_INDEX}: revoked (this credential)`,
  )
  await expect(page.locator('#revoke-out .status-line')).toContainText(
    `Bit #${CRED_INDEX} is now 1 (revoked)`,
  )
  await expect(page.locator('#revoke-toggle')).toHaveText(`Reinstate credential #${CRED_INDEX}`)

  await rerender(page, '#revoke-out', () => page.locator('#revoke-check').click())

  let raw = (await rawOf(page, '#revoke-out').innerText()).replace(/\s+/g, ' ')
  // The wallet had to send the index, and the header is bound to it: the proof
  // verifies against the claimed index and fails against a decoy.
  expect(raw).toContain(`status index ${CRED_INDEX}`)
  expect(raw).toContain(`Verified against the claimed index ${CRED_INDEX}: true`)
  const decoy = int(raw.match(/decoy index (\d+): (?:true|false)/)?.[1])
  expect(decoy).not.toBe(CRED_INDEX)
  expect(raw).toContain(`Same proof re-checked against decoy index ${decoy}: false.`)
  // The stated status bit is the digit the grid is showing for that index.
  expect(raw).toContain(`Status bit #${CRED_INDEX} in the published list: ${printed[CRED_INDEX]}`)
  await expect(bitAt(CRED_INDEX)).toHaveClass(/bit-checked/)
  await expect(page.locator('#revoke-out .bit-checked')).toHaveCount(1)

  let verdict = verdictOf(page, '#revoke-out')
  await expect(verdict).toHaveClass(/indicator-alarm/)
  await expect(verdict).toContainText('REJECT — proof valid, credential revoked')
  await expect(verdict).toContainText(`The verdict came from bit #${CRED_INDEX}`)

  /* --- reinstate: the other branch of the same verdict --- */
  await page.locator('#revoke-toggle').click()
  await expect(page.locator('#revoke-out .status-line')).toContainText(
    `Bit #${CRED_INDEX} is now 0 (active)`,
  )
  await expect(page.locator('#revoke-toggle')).toHaveText(`Revoke credential #${CRED_INDEX}`)

  await rerender(page, '#revoke-out', () => page.locator('#revoke-check').click())

  printed = await bits()
  expect(printed.filter((b) => b === '1')).toHaveLength(0)
  expect(printed[CRED_INDEX]).toBe('0')

  raw = (await rawOf(page, '#revoke-out').innerText()).replace(/\s+/g, ' ')
  expect(raw).toContain(`Status bit #${CRED_INDEX} in the published list: ${printed[CRED_INDEX]}`)
  expect(raw).toContain(`Verified against the claimed index ${CRED_INDEX}: true`)

  verdict = verdictOf(page, '#revoke-out')
  await expect(verdict).toHaveClass(/indicator-warn/)
  await expect(verdict).toContainText('ACCEPT, at a price')
  await expect(verdict).toContainText('the verifier now holds your stable index')
})
