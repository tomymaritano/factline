import { scannedVersions, type AdvisoryScan } from "./domain/advisories.ts"
import { parseSpec, validName } from "./domain/validate.ts"
import { MissBudget, SingleFlight, UpstreamGate } from "./limit.ts"
import { LIMITS } from "./policy.ts"
import { readCatalog, readVersionIndex, type CatalogHit, type VersionIndex } from "./readers/catalog.ts"
import type { Fetcher } from "./readers/http.ts"

export type ScanRequest = {
  name: string
  versions: string[]
  charged: boolean
  ip: string
  nowMs: number
}

const CACHE_MS = 5 * 60 * 1000

export type SuggestResult =
  | { status: 200; kind: "recent" }
  | { status: 200; kind: "open"; name: string; version: string }
  | { status: 200; kind: "hits"; hits: CatalogHit[] }
  | { status: 429; kind: "limited" }
  | { status: 502; kind: "unavailable" }

export type VersionsResult =
  | { status: 200; index: VersionIndex; scan: AdvisoryScan }
  | { status: 400; error: "invalid_name" }
  | { status: 404; error: "not_found" }
  | { status: 429; error: "rate_limited" }
  | { status: 502; error: "registry_unavailable" }

export type Catalog = {
  suggest: (query: string, ip: string, nowMs: number) => Promise<SuggestResult>
  versions: (name: string, ip: string, nowMs: number) => Promise<VersionsResult>
}

export function createCatalog(deps: {
  fetcher: Fetcher
  gate: UpstreamGate
  flights: SingleFlight
  budget: MissBudget
  scan: (input: ScanRequest) => Promise<AdvisoryScan>
}): Catalog {
  const searches = new Map<string, { at: number; hits: CatalogHit[] }>()
  const indexes = new Map<string, { at: number; value: VersionIndex | "missing" }>()

  return {
    suggest: async (query, ip, nowMs) => {
      const text = query.trim()
      if (text.length < 2) return { status: 200, kind: "recent" }
      const spec = parseSpec(text)
      if (spec?.version) return { status: 200, kind: "open", name: spec.name, version: spec.version }
      const upstream = validName(text) ? `${text} boost-exact:true` : text
      const cached = searches.get(upstream)
      if (cached && nowMs - cached.at < CACHE_MS) return { status: 200, kind: "hits", hits: cached.hits }
      if (!deps.budget.allow(ip, nowMs)) return { status: 429, kind: "limited" }
      const hits = await deps.flights.run(`catalog:${upstream}`, () =>
        deps.gate.run(() => readCatalog(deps.fetcher, upstream)),
      )
      if (!hits) return { status: 502, kind: "unavailable" }
      const ranked = rankExact(text, hits)
      searches.set(upstream, { at: nowMs, hits: ranked })
      return { status: 200, kind: "hits", hits: ranked }
    },
    versions: async (name, ip, nowMs) => {
      const trimmed = name.trim()
      if (!validName(trimmed)) return { status: 400, error: "invalid_name" }
      const cached = indexes.get(trimmed)
      const indexFresh = cached !== undefined && nowMs - cached.at < CACHE_MS
      let value: VersionIndex | "missing"
      let charged = false
      if (indexFresh && cached) {
        value = cached.value
      } else {
        if (!deps.budget.allow(ip, nowMs)) return { status: 429, error: "rate_limited" }
        charged = true
        const loaded = await deps.flights.run(`versions:${trimmed}`, () =>
          deps.gate.run(() => readVersionIndex(deps.fetcher, trimmed)),
        )
        if (loaded === null) return { status: 502, error: "registry_unavailable" }
        indexes.set(trimmed, { at: nowMs, value: loaded })
        value = loaded
      }
      if (value === "missing") return { status: 404, error: "not_found" }
      const scan = await deps.scan({ name: trimmed, versions: scannedVersions(value), charged, ip, nowMs })
      return { status: 200, index: value, scan }
    },
  }
}

function rankExact(query: string, hits: CatalogHit[]): CatalogHit[] {
  const exact = hits.filter((hit) => hit.name === query)
  if (exact.length === 0) return hits
  return [...exact, ...hits.filter((hit) => hit.name !== query)]
}

export function searchBudget(): MissBudget {
  return new MissBudget(LIMITS.searchesPerMinute, 60_000)
}
