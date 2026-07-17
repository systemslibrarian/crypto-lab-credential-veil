/**
 * Main-thread handle on the crypto worker: promise-per-call RPC with progress
 * callbacks, hard cancellation, and self-healing. Cancel terminates the worker
 * (the only way to stop synchronous pairing math) and respawns a fresh one;
 * pending calls reject with CancelledError.
 *
 * Self-healing: a per-call watchdog catches a wedged worker (observed rarely
 * on WebKit under load) — on timeout or a worker-level error the worker is
 * respawned and the call retried once on the fresh instance before failing.
 */
import type { WorkerRequest, WorkerResponse } from './cryptoWorker'

export class CancelledError extends Error {
  constructor() {
    super('cancelled')
    this.name = 'CancelledError'
  }
}

/** Worker-side RangeError arrives as a flag; rehydrate so callers can `instanceof`. */
export class WorkerRangeError extends RangeError {}

// Generous per-call ceiling: the slowest legitimate op (age-proof verify on a
// slow engine) is a few seconds; anything near a minute is a wedged worker.
const CALL_TIMEOUT_MS = 60_000

interface Pending {
  op: WorkerRequest['op']
  args: unknown[]
  attempt: number
  resolve: (value: unknown) => void
  reject: (err: Error) => void
  onProgress?: (stage: string) => void
  watchdog: ReturnType<typeof setTimeout>
}

export class CryptoClient {
  private worker!: Worker
  private pending = new Map<number, Pending>()
  private nextId = 1

  constructor() {
    this.spawn()
  }

  private spawn(): void {
    this.worker = new Worker(new URL('./cryptoWorker.ts', import.meta.url), { type: 'module' })
    this.worker.onmessage = (ev: MessageEvent<WorkerResponse>) => {
      const msg = ev.data
      const entry = this.pending.get(msg.id)
      if (!entry) return
      if ('progress' in msg) {
        entry.onProgress?.(msg.progress)
        return
      }
      clearTimeout(entry.watchdog)
      this.pending.delete(msg.id)
      if (msg.ok) entry.resolve(msg.value)
      else entry.reject(msg.rangeError ? new WorkerRangeError(msg.error) : new Error(msg.error))
    }
    // A worker-level failure (script error, OOM-killed worker) settles every
    // in-flight call instead of leaving buttons stuck; first-attempt calls
    // get one retry on a fresh worker.
    this.worker.onerror = (ev: ErrorEvent) => this.recoverAll(`crypto worker error: ${ev.message || 'unknown'}`)
    this.worker.onmessageerror = () => this.recoverAll('crypto worker message failed to deserialize')
  }

  private recoverAll(reason: string): void {
    const stuck = [...this.pending.entries()]
    this.pending.clear()
    this.worker.terminate()
    this.spawn()
    for (const [, entry] of stuck) {
      clearTimeout(entry.watchdog)
      if (entry.attempt === 0) this.dispatch(entry.op, entry.args, entry.onProgress, 1, entry.resolve, entry.reject)
      else entry.reject(new Error(reason))
    }
  }

  private dispatch(
    op: WorkerRequest['op'],
    args: unknown[],
    onProgress: ((stage: string) => void) | undefined,
    attempt: number,
    resolve: (value: unknown) => void,
    reject: (err: Error) => void,
  ): void {
    const id = this.nextId++
    const watchdog = setTimeout(() => {
      if (!this.pending.delete(id)) return
      // wedged worker: everything else in flight is behind the same wedge
      this.recoverAll('crypto worker timed out')
      if (attempt === 0) this.dispatch(op, args, onProgress, 1, resolve, reject)
      else reject(new Error('crypto worker timed out'))
    }, CALL_TIMEOUT_MS)
    this.pending.set(id, { op, args, attempt, resolve, reject, onProgress, watchdog })
    try {
      this.worker.postMessage({ id, op, args } satisfies WorkerRequest)
    } catch (err) {
      clearTimeout(watchdog)
      this.pending.delete(id)
      reject(err instanceof Error ? err : new Error(String(err)))
    }
  }

  call<T>(op: WorkerRequest['op'], args: unknown[], onProgress?: (stage: string) => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.dispatch(op, args, onProgress, 0, resolve as (v: unknown) => void, reject)
    })
  }

  /** True while any call is in flight — used to show/hide cancel affordances. */
  get busy(): boolean {
    return this.pending.size > 0
  }

  /** Hard-stop all in-flight work and start a fresh worker. */
  cancel(): void {
    const cancelled = [...this.pending.values()]
    this.pending.clear()
    this.worker.terminate()
    this.spawn()
    for (const p of cancelled) {
      clearTimeout(p.watchdog)
      p.reject(new CancelledError())
    }
  }
}
