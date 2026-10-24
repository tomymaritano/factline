import {
  joinAdvisoryScan,
  markScanStale,
  omittedScan,
  type AdvisoryScan,
  type BatchRow,
} from "./domain/advisories.ts"
import { tiedCves } from "./domain/cve.ts"
import type { KevProjection } from "./domain/types.ts"
import { isFresh, TTL_MS } from "./policy.ts"
import type { Fetcher } from "./readers/http.ts"
import { readOsvBatch, readOsvVuln } from "./readers/osv.ts"
import { MissBudget, SingleFlight, UpstreamGate } from "./limit.ts"

const CACHE_MS = TTL_MS.osv

export function createScanner(deps: {
  fetcher: Fetcher
  gate: UpstreamGate
  flights: SingleFlight
  budget: MissBudget
  getKev: () => KevProjection | null
  refreshKev: (observedAt: string) => Promise<KevProjection | null>
}): { scan: (input: { name: string; versions: string[]; charged: boolean; ip: string; nowMs: number }) => Promise<AdvisoryScan> } {
  const cache = new Map<string, { at: number; scan: AdvisoryScan }>()

  return {
    scan: async ({ name, versions, charged, ip, nowMs }) => {
      const observedAt = new Date(nowMs).toISOString()
      if (versions.length === 0) {
        return joinAdvisoryScan({ observedAt, rows: [], records: new Map(), kev: { state: "skipped" } })
      }
      const key = `${name}\n${versions.join("\n")}`
      const cached = cache.get(key)
      if (cached && nowMs - cached.at < CACHE_MS) return cached.scan
      if (!charged && !deps.budget.allow(ip, nowMs)) {
        return cached ? markScanStale(cached.scan) : omittedScan(observedAt)
      }
      const scan = await deps.flights.run(`scan:${key}`, () =>
        loadScan(deps, name, versions, observedAt, nowMs),
      )
      if (scan.osv !== "unavailable") cache.set(key, { at: nowMs, scan })
      return scan
    },
  }
}

async function loadScan(
  deps: {
    fetcher: Fetcher
    gate: UpstreamGate
    flights: SingleFlight
    getKev: () => KevProjection | null
    refreshKev: (observedAt: string) => Promise<KevProjection | null>
  },
  name: string,
  versions: string[],
  observedAt: string,
  nowMs: number,
): Promise<AdvisoryScan> {
  const batch = await deps.flights.run(`osv-batch:${name}\n${versions.join("\n")}`, () =>
    deps.gate.run(() => readOsvBatch(deps.fetcher, name, versions)),
  )
  if (batch.state === "unavailable") {
    return joinAdvisoryScan({ observedAt, rows: null, records: new Map(), kev: { state: "skipped" } })
  }
  const records = new Map<string, Awaited<ReturnType<typeof readOsvVuln>>>()
  const ids = [...new Set(batch.rows.flatMap((row) => row.ids))].sort()
  await Promise.all(
    ids.map(async (id) => {
      const record = await deps.flights.run(`osv-vuln:${id}`, () =>
        deps.gate.run(() => readOsvVuln(deps.fetcher, id, name)),
      )
      records.set(id, record)
    }),
  )
  const kev = await kevFor(deps, batch.rows, records, observedAt, nowMs)
  return joinAdvisoryScan({ observedAt, rows: batch.rows, records, kev })
}

async function kevFor(
  deps: {
    getKev: () => KevProjection | null
    refreshKev: (observedAt: string) => Promise<KevProjection | null>
  },
  rows: BatchRow[],
  records: ReadonlyMap<string, Awaited<ReturnType<typeof readOsvVuln>>>,
  observedAt: string,
  nowMs: number,
): Promise<{ state: "skipped" } | { state: "unavailable" } | { state: "ok"; observedAt: string; entries: KevProjection["entries"] }> {
  let needsKev = false
  for (const row of rows) {
    for (const id of row.ids) {
      const record = records.get(id)
      if (record && record !== "missing" && tiedCves(record.id, record.aliases).length > 0) needsKev = true
    }
  }
  if (!needsKev) return { state: "skipped" }
  let kev = deps.getKev()
  const fresh = kev !== null && isFresh(kev.observedAt, nowMs, TTL_MS.kev)
  if (!fresh) kev = await deps.refreshKev(observedAt)
  if (!kev || !isFresh(kev.observedAt, nowMs, TTL_MS.kevUsable)) return { state: "unavailable" }
  return { state: "ok", observedAt: kev.observedAt, entries: kev.entries }
}
