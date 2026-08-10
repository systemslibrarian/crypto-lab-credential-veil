import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * The desktop half, pinned rather than inherited.
 *
 * `playwright.config.ts` runs four projects, and `devices['Pixel 7']` carries a
 * 412px viewport of its own — so without this the "desktop" configuration would
 * silently be 412px in one of the four projects and the gate would have run
 * three viewports under two labels.
 */
export const WIDE = { width: 1280, height: 900 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this replaces
 *     opened with `addStyleTag({ content: '*{animation:none;transition:none}' })`,
 *     which BYPASSES a lab's own `@media (prefers-reduced-motion: reduce)` block
 *     rather than exercising it — so it was structurally unable to see a defect
 *     in that block. It then forced every `<details>` open by setting
 *     `d.open = true` from script instead of clicking the summary. Here reduced
 *     motion is requested through `emulateMedia` and then *asserted*, and every
 *     disclosure is opened by clicking its own summary.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing — and this lab's five exhibit outputs (`#baseline-out`, `#sd-out`,
 *     `#unlink-out`, `#age-out`, `#revoke-out`) are all empty `<div>`s until a
 *     button is pressed.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The spec this replaces
 *     drove fourteen interactions and then scanned ONCE, at the end, with
 *     `violations` alone — so thirteen states were built and thrown away
 *     unmeasured, and the one that was measured was measured with a third of an
 *     oracle.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the lab's shipped defaults rather than assuming them.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is set through the same `localStorage` key the shared header's
 * toggle writes (`'theme'`) and the anti-flash script in `index.html` reads. If
 * those two ever drift apart the theme silently stops persisting, and asserting
 * `data-theme` after a seeded load is what would catch it.
 *
 * This returns while the issuer keys are still being generated: at first paint
 * every exhibit control is `disabled` and `#setup-status` reads "Generating…".
 * That pre-unlock state is a real state a visitor sees, so it is asserted and
 * scanned here BEFORE `ready()` waits it out.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<() => Promise<void>> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);

  // Hold the crypto worker's SCRIPT on the wire so the pre-unlock state can
  // actually be scanned. `setup()` blocks on the worker's first reply, so with
  // the script held the page stays in the state a visitor sees while the issuer
  // keys are being generated — every exhibit control disabled, `#setup-status`
  // reading "Generating…". Unheld, that window is ~150ms on this machine and a
  // scan (axe + the contrast walk) takes ten times that, so the state could only
  // ever be scanned by accident or half-way through.
  //
  // This is a network delay, not an injection: nothing is added to the document
  // and no style or attribute is changed. What is scanned is exactly what the
  // lab renders on a slow connection.
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route(WORKER_SCRIPT, async (route) => {
    await held;
    await route.continue();
  });

  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  // This lab stamps `data-theme` for BOTH themes from its anti-flash script, so
  // the attribute is asserted either way rather than only in light.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('#credential-card .cred-field')).toHaveCount(6);
  await expect(page.locator('#sd-fields input[type="checkbox"]')).toHaveCount(6);
  await expect(page.locator('#setup-status')).not.toBeEmpty();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);

  // Releasing resolves the held promise; the handler then continues the request
  // it is sitting on. The route stays registered on purpose — `unroute` disposes
  // routes that are still in flight, which aborts that very request ("Route is
  // already handled"), and once released the handler is a pass-through anyway.
  return async () => {
    release();
  };
}

/** The built worker chunk, whichever hash Vite gave it this build. */
const WORKER_SCRIPT = /cryptoWorker.*\.js(\?.*)?$/;

/**
 * The controls this lab ships disabled, and the one it does not.
 *
 * Asserted rather than assumed. `#revoke-toggle` is the exception and stays
 * live from first paint, because flipping a published status-list bit needs no
 * issuer key — the status list is plain local state. Everything else waits for
 * `setup()`. A gate that assumed "everything starts disabled" would stop
 * checking the moment that assumption broke, and a gate that assumed the
 * opposite would never have noticed that `#revoke-check` shipped enabled while
 * its handler opened with `if (!state) return`.
 */
export const LOCKED_AT_FIRST_PAINT = [
  '#baseline-run',
  '#sd-run',
  '#sd-step',
  '#unlink-bbs',
  '#unlink-ed',
  '#age-adult',
  '#age-minor',
  '#age-forge',
  '#revoke-check',
] as const;

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints unbroken hex blobs hundreds of characters long
 * and lays out two comparison tables at `min-width: 44rem`. It also carried a
 * real instance of exactly this until recently — `.cl-hero-why` takes
 * `width: 100%` below 640px and `1.05rem` of padding, and without a
 * `box-sizing: border-box` reset the aside came out wider than its column at
 * every phone width.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This lab does not set
    // that rule today, so this branch is currently inert here; it is kept
    // because the rule is a one-line "fix" someone reaches for the moment this
    // oracle goes red, and it would turn the oracle permanently green instead.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. Both of
    // this page's tables are exactly that shape (`min-width: 44rem` inside
    // `.table-wrap { overflow-x: auto }`), so without this filter every reflow
    // report would name a table that is not the problem.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is.
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * Both of this lab's scroller shapes rely on that: `.hexblock` and
 * `.table-wrap` hold nothing focusable, and both are given `tabindex="0"` — but
 * `.hexblock` is built in JS, so a future output that forgets the attribute
 * would ship an unreachable scroller. Only a driven state can see it.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them — and on this lab a full run is sixteen (four
 * viewport/theme configurations across four browser projects, at one worker).
 * The collection pass turns that into a single run.
 *
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set fails at the end via
 * `reportCollected`, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/** Run a throwing assertion, collecting instead of throwing when collecting. */
async function soft(run: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return run();
  try {
    await run();
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 *
 * Two classes have no oracle here at all and were measured by hand from
 * screenshot pixels instead: WCAG 1.4.11 non-text contrast, and generated
 * content. See the note at the top of `contrast.ts`.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await soft(() => expectNotBlank(page, label));
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * The shape of this lab is five independent exhibits behind one asynchronous
 * unlock, so the drive is: the locked state first (held open on the wire, see
 * `boot`), then the unlocked-but-idle state, then each exhibit through every
 * branch it can take — including the ones that only exist at an extreme of the
 * field picker (reveal nothing / reveal all six), the two break-it paths, both
 * unlinkability views, all three age-predicate outcomes, and both sides of the
 * revocation toggle. Every disclosure is opened by clicking its own summary.
 *
 * Waits are on real completion signals — a rendered `.result-pair`, a step
 * count, a status string — never on a fixed timeout. `rerender` additionally
 * marks the current output stale before acting, because every handler here
 * leaves the previous result on screen while it works: a bare wait for
 * `.result-pair` would return instantly against the PREVIOUS run's output and
 * the scan that follows would measure the state before the step, not after it.
 */
export async function driveAllStates(
  page: Page,
  theme: string,
  releaseWorker: () => Promise<void>
): Promise<void> {
  const S = (s: string): string => `${theme} / ${s}`;
  const FIELDS = ['name', 'dob', 'address', 'license', 'class', 'expiry'];

  /** Act, then wait for output THIS action produced, not the last one's. */
  const rerender = async (scope: string, act: () => Promise<void>, sel = '.result-pair') => {
    await page
      .locator(`${scope} ${sel}`)
      .evaluateAll((els) => els.forEach((e) => e.setAttribute('data-stale', '1')));
    await act();
    await expect(page.locator(`${scope} ${sel}:not([data-stale])`)).toBeVisible({
      timeout: 300_000,
    });
  };

  // ---- 1. first paint, issuer keys still being generated -------------------
  for (const sel of LOCKED_AT_FIRST_PAINT) {
    await expect(page.locator(sel), `${sel} must ship disabled`).toBeDisabled();
  }
  await expect(page.locator('#revoke-toggle'), 'the status-list toggle needs no key').toBeEnabled();
  await expect(page.locator('#setup-status')).toContainText('Generating');
  await expect(page.locator('#sd-break')).toBeHidden();
  await expect(page.locator('#age-cancel')).toBeHidden();
  // The field picker ships with exactly `class` checked. Which half of the
  // selective-disclosure exhibit a single-state gate would have measured
  // depends entirely on this default, so it is asserted rather than assumed.
  for (const f of FIELDS) {
    const box = page.locator(`#sd-field-${f}`);
    if (f === 'class') await expect(box).toBeChecked();
    else await expect(box).not.toBeChecked();
  }
  for (const out of ['#baseline-out', '#sd-out', '#unlink-out', '#age-out', '#revoke-out']) {
    await expect(page.locator(out)).toBeEmpty();
  }
  for (const d of await page.locator('details').all()) {
    await expect(d).not.toHaveAttribute('open', '');
  }
  await scan(page, S('first paint — issuer keys pending, every exhibit locked'));

  // ---- 2. keys ready, nothing run yet --------------------------------------
  await releaseWorker();
  await expect(page.locator('#setup-status')).toContainText('Ready.', { timeout: 120_000 });
  for (const sel of LOCKED_AT_FIRST_PAINT) await expect(page.locator(sel)).toBeEnabled();
  await scan(page, S('issuer keys ready, no exhibit run'));

  // ---- 3. the skip link, which is off-screen until it is focused -----------
  // Focused directly rather than by pressing Tab: WebKit's default keyboard
  // navigation moves between form controls only and never lands on a link, so
  // a Tab-driven version of this step is green on three engines and red on the
  // fourth for a reason that has nothing to do with the page. `.cl-skip-link`
  // is styled on plain `:focus`, not `:focus-visible`, so programmatic focus
  // produces exactly the rendering a keyboard user gets.
  const skip = page.locator('.cl-skip-link');
  await skip.focus();
  await expect(skip).toBeFocused();
  // The whole point of the idiom: parked at `top: -3rem`, focus brings it back.
  expect(
    await skip.evaluate((e) => e.getBoundingClientRect().top),
    'focus must bring the skip link on screen'
  ).toBeGreaterThanOrEqual(0);
  await scan(page, S('skip link focused'));
  await skip.blur();

  // ---- 4. exhibit 1 — the all-or-nothing baseline --------------------------
  await rerender('#baseline-out', () => page.click('#baseline-run'));
  await expect(page.locator('#baseline-out .indicator-alarm')).toBeVisible();
  await scan(page, S('exhibit 1 — every field handed over, PRIVACY BROKEN'));

  // ---- 5. exhibit 2 — selective disclosure, at both extremes ---------------
  for (const f of FIELDS) await page.uncheck(`#sd-field-${f}`);
  await rerender('#sd-out', () => page.click('#sd-run'));
  await expect(page.locator('#sd-out .verifier-view li')).toHaveCount(0);
  await expect(page.locator('#sd-tamper')).toBeDisabled();
  await expect(page.locator('#sd-tamper')).toHaveText(/Nothing revealed/);
  await scan(page, S('exhibit 2 — nothing revealed, tamper button locked'));

  for (const f of FIELDS) await page.check(`#sd-field-${f}`);
  await rerender('#sd-out', () => page.click('#sd-run'));
  await expect(page.locator('#sd-out .verifier-view li')).toHaveCount(6);
  await scan(page, S('exhibit 2 — all six fields revealed'));

  for (const f of FIELDS) if (f !== 'class') await page.uncheck(`#sd-field-${f}`);
  await rerender('#sd-out', () => page.click('#sd-run'));
  await expect(page.locator('#sd-out .verifier-view li')).toHaveCount(1);
  await expect(page.locator('#sd-break')).toBeVisible();
  await scan(page, S('exhibit 2 — one field revealed'));

  for (let i = 0; i < 4; i++) {
    await page.click('#sd-step');
    await expect(page.locator('#sd-steps li')).toHaveCount(i + 1, { timeout: 300_000 });
    await expect(page.locator('#sd-steps li.step-active')).toHaveCount(1);
    await scan(page, S(`exhibit 2 — mechanism step ${i + 1} of 4`));
  }

  await rerender('#sd-break-out', () => page.click('#sd-tamper'));
  await expect(page.locator('#sd-break-out .indicator-ok')).toBeVisible();
  await scan(page, S('exhibit 2 — tampered value rejected'));

  await rerender('#sd-break-out', () => page.click('#sd-honest'));
  await expect(page.locator('#sd-break-out .indicator-ok')).toBeVisible();
  await scan(page, S('exhibit 2 — honest presentation re-verified'));

  // ---- 6. exhibit 3 — both unlinkability views -----------------------------
  await rerender('#unlink-out', () => page.click('#unlink-bbs'));
  await expect(page.locator('#unlink-out .hexblock')).toHaveCount(3);
  await scan(page, S('exhibit 3 — three BBS showings'));

  await rerender('#unlink-out', () => page.click('#unlink-ed'));
  await expect(page.locator('#unlink-out .indicator-alarm')).toBeVisible();
  await expect(page.locator('#unlink-out mark.common-bytes').first()).toBeVisible();
  await scan(page, S('exhibit 3 — Ed25519 showings, every byte highlighted as common'));

  // ---- 7. exhibit 4 — all three age-predicate outcomes ---------------------
  await rerender('#age-out', () => page.click('#age-minor'));
  await expect(page.locator('#age-out .indicator-ok')).toBeVisible();
  await scan(page, S('exhibit 4 — honest prover refuses for a 2010 DOB'));

  await rerender('#age-out', () => page.click('#age-forge'));
  await expect(page.locator('#age-out .verifier-view')).toBeVisible();
  await expect(page.locator('#age-out .indicator-ok')).toBeVisible();
  await scan(page, S('exhibit 4 — forged under-18 proof rejected'));

  // The cancel affordance is asserted the instant the click returns: the button
  // is unhidden synchronously in the handler, before the first await, while the
  // proof itself takes ~200ms. It is not scanned as its own state, because a
  // scan takes several times longer than the proof and would end up measuring
  // the finished page under a mid-flight label.
  await rerender('#age-out', async () => {
    await page.click('#age-adult');
    await expect(page.locator('#age-cancel')).toBeVisible();
  });
  await expect(page.locator('#age-out .indicator-ok')).toBeVisible();
  await expect(page.locator('#age-cancel')).toBeHidden();
  await scan(page, S('exhibit 4 — over-18 proved without a birth date'));

  // ---- 8. exhibit 5 — both sides of the revocation toggle ------------------
  await page.click('#revoke-toggle');
  await expect(page.locator('#revoke-out .bit-grid .bit').nth(17)).toHaveText('1');
  await expect(page.locator('#revoke-toggle')).toHaveText(/Reinstate/);
  await scan(page, S('exhibit 5 — credential 17 revoked in the published list'));

  await rerender('#revoke-out', () => page.click('#revoke-check'));
  await expect(page.locator('#revoke-out .indicator-alarm')).toBeVisible();
  await expect(page.locator('#revoke-out .bit-checked')).toBeVisible();
  await scan(page, S('exhibit 5 — verifier rejects the revoked credential'));

  await page.click('#revoke-toggle');
  await expect(page.locator('#revoke-out .bit-grid .bit').nth(17)).toHaveText('0');
  await scan(page, S('exhibit 5 — credential 17 reinstated'));

  await rerender('#revoke-out', () => page.click('#revoke-check'));
  await expect(page.locator('#revoke-out .indicator-warn')).toBeVisible();
  await scan(page, S('exhibit 5 — accepted, at the price of a stable index'));

  // ---- 9. every disclosure, opened by clicking its own summary -------------
  const summaries = await page.locator('details > summary').all();
  expect(summaries.length, 'the page must still carry its disclosures').toBe(2);
  for (const [i, summary] of summaries.entries()) {
    await summary.click();
    await expect(page.locator('details').nth(i)).toHaveAttribute('open', '');
    await scan(page, S(`disclosure ${i + 1} of ${summaries.length} open`));
  }
}
