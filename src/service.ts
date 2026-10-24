import { assembleTimeline, type AssembleInput } from "./domain/assemble.ts"
import { classifyVersion, validName } from "./domain/validate.ts"
import type { ScorecardProjection, Timeline, VersionRecord } from "./domain/types.ts"
import { MissBudget, SingleFlight, UpstreamGate } from "./limit.ts"
import { isFresh, LIMITS, TTL_MS } from "./policy.ts"
import { readDependents } from "./readers/deps.ts"
import type { Fetcher } from "./readers/http.ts"
import { readKev } from "./readers/kev.ts"
import { readOsv } from "./readers/osv.ts"
import { readRegistry } from "./readers/registry.ts"
import { readScorecard } from "./readers/scorecard.ts"
import { openStore, type Store } from "./store.ts"

export type TimelineResult =
  | { status: 200; timeline: Timeline }
  | { status: 400; error: "invalid_name" | "invalid_version" }
  | { status: 404; error: "not_found" }
  | { status: 429; error: "rate_limited" }
  | { status: 502; error: "registry_unavailable" }

export type FactlineService = {
  timeline: (name: string, version: string, ip: string) => Promise<TimelineResult>
  recent: () => { name: string; version: string; lookedUpAt: string }[]
  close: () => void
}

export function createService(options: {
  dbPath: string
  fetcher?: Fetcher
  now?: () => Date
  store?: Store
}): FactlineService {
  const store = options.store ?? openStore(options.dbPath)
  const fetcher = options.fetcher ?? fetch
  const now = options.now ?? (() => new Date())
  const gate = new UpstreamGate(LIMITS.maxInFlight)
  const flights = new SingleFlight()
  const budget = new MissBudget(LIMITS.missesPerMinute, 60_000)

  return {
    recent: () => store.recentLookups(10),
    close: () => store.close(),
    timeline: (name, version, ip) =>
      loadTimeline({ store, fetcher, now, gate, flights, budget, name, version, ip }),
  }
}

async function loadTimeline(ctx: {
  store: Store
  fetcher: Fetcher
  now: () => Date
  gate: UpstreamGate
  flights: SingleFlight
  budget: MissBudget
  name: string
  version: string
  ip: string
}): Promise<TimelineResult> {
  const name = ctx.name.trim()
  const requested = ctx.version.trim()
  if (!validName(name)) return { status: 400, error: "invalid_name" }
  const versionKind = classifyVersion(requested)
  if (versionKind === "invalid") return { status: 400, error: "invalid_version" }

  const now = ctx.now()
  const nowMs = now.getTime()
  const observedAt = now.toISOString()

  let spentUpstream = false
  const mayRefresh = (): boolean => {
    if (spentUpstream) return true
    if (!ctx.budget.allow(ctx.ip, nowMs)) return false
    spentUpstream = true
    return true
  }

  let packument = ctx.store.getPackument(name)
  const packumentFresh = packument !== null && isFresh(packument.observedAt, nowMs, TTL_MS.packument)
  if (!packumentFresh) {
    if (!mayRefresh()) {
      if (!packument || packument.notFound) return { status: 429, error: "rate_limited" }
    } else {
      packument = await refreshPackument(ctx, name, observedAt, packument)
    }
  }
  if (!packument) return { status: 502, error: "registry_unavailable" }
  if (packument.notFound) return { status: 404, error: "not_found" }

  const resolved = resolveVersion(packument.distTags, requested, versionKind)
  if (!resolved) return { status: 404, error: "not_found" }
  const subjectVersion = packument.versions.find((item) => item.version === resolved.version)
  if (!subjectVersion) return { status: 404, error: "not_found" }

  const registryStale = !isFresh(packument.observedAt, nowMs, TTL_MS.packument)

  const osvCached = ctx.store.getOsv(name, resolved.version)
  const kevCached = ctx.store.getKev()
  const depsCached = ctx.store.getDependents(name, resolved.version)
  const repo = subjectVersion.repository.ok ? subjectVersion.repository.repo : null
  const scorecardCached = repo ? ctx.store.getScorecard(repo) : null

  const osvFresh = osvCached !== null && isFresh(osvCached.observedAt, nowMs, TTL_MS.osv)
  const kevFresh = kevCached !== null && isFresh(kevCached.observedAt, nowMs, TTL_MS.kev)
  const depsFresh = depsCached !== null && isFresh(depsCached.observedAt, nowMs, TTL_MS.dependents)
  const scorecardFresh =
    !repo || (scorecardCached !== null && isFresh(scorecardCached.state === "present" ? scorecardCached.projection.observedAt : scorecardCached.observedAt, nowMs, TTL_MS.scorecard))
  const enrichmentMiss = !osvFresh || !kevFresh || !depsFresh || !scorecardFresh

  let osv = osvCached
  let kev = kevCached
  let deps = depsCached
  let scorecard = scorecardCached
  if (enrichmentMiss && mayRefresh()) {
    const refreshed = await Promise.all([
      osvFresh ? Promise.resolve(osv) : refreshOsv(ctx, name, resolved.version, observedAt, osv),
      kevFresh ? Promise.resolve(kev) : refreshKev(ctx, observedAt, kev),
      depsFresh ? Promise.resolve(deps) : refreshDeps(ctx, name, resolved.version, observedAt, deps),
      !repo || scorecardFresh
        ? Promise.resolve(scorecard)
        : refreshScorecard(ctx, repo, observedAt, scorecard),
    ])
    osv = refreshed[0]
    kev = refreshed[1]
    deps = refreshed[2]
    scorecard = refreshed[3]
  }

  const input: AssembleInput = {
    now: observedAt,
    subject: {
      name,
      version: resolved.version,
      requestedVersion: requested,
      resolvedFromTag: resolved.tag,
    },
    registry: {
      projection: { observedAt: packument.observedAt, distTags: packument.distTags, versions: packument.versions },
      stale: registryStale,
    },
    osv: osv
      ? { state: "ok", projection: osv, stale: !isFresh(osv.observedAt, nowMs, TTL_MS.osv) }
      : { state: "unavailable" },
    kev: kevWithinUse(kev, nowMs)
      ? {
          state: "ok",
          projection: kev as NonNullable<typeof kev>,
          stale: !isFresh((kev as NonNullable<typeof kev>).observedAt, nowMs, TTL_MS.kev),
        }
      : { state: "unavailable" },
    deps: deps
      ? { state: "ok", projection: deps, stale: !isFresh(deps.observedAt, nowMs, TTL_MS.dependents) }
      : { state: "unavailable" },
    scorecard: scorecardInput(subjectVersion, scorecard, nowMs),
  }

  const timeline = assembleTimeline(input)
  ctx.store.addLookup(name, resolved.version, observedAt)
  return { status: 200, timeline }
}

function kevWithinUse(kev: ReturnType<Store["getKev"]>, nowMs: number): boolean {
  if (!kev) return false
  return isFresh(kev.observedAt, nowMs, TTL_MS.kevUsable)
}

function scorecardInput(
  version: VersionRecord,
  cached: Awaited<ReturnType<Store["getScorecard"]>> | null,
  nowMs: number,
): AssembleInput["scorecard"] {
  if (!version.repository.ok) {
    return version.repository.reason === "no_repository" ? { state: "no_repository" } : { state: "not_github" }
  }
  const repo = version.repository.repo
  if (!cached) return { state: "unavailable", repo }
  if (cached.state === "absent") {
    return {
      state: "absent",
      repo,
      observedAt: cached.observedAt,
      stale: !isFresh(cached.observedAt, nowMs, TTL_MS.scorecard),
    }
  }
  return {
    state: "present",
    projection: cached.projection,
    stale: !isFresh(cached.projection.observedAt, nowMs, TTL_MS.scorecard),
  }
}

function resolveVersion(
  distTags: Record<string, string>,
  requested: string,
  kind: "semver" | "tag",
): { version: string; tag: string | null } | null {
  if (kind === "semver") return { version: requested, tag: null }
  const version = distTags[requested]
  if (!version) return null
  return { version, tag: requested }
}

async function refreshPackument(
  ctx: { store: Store; fetcher: Fetcher; gate: UpstreamGate; flights: SingleFlight },
  name: string,
  observedAt: string,
  previous: ReturnType<Store["getPackument"]>,
): Promise<ReturnType<Store["getPackument"]>> {
  return ctx.flights.run(`packument:${name}`, () =>
    ctx.gate.run(async () => {
      const read = await readRegistry(ctx.fetcher, name)
      if (read.state === "not_found") {
        ctx.store.putPackumentMissing(name, observedAt)
        return ctx.store.getPackument(name)
      }
      if (read.state === "unavailable") return previous
      ctx.store.putPackument(name, observedAt, read.projection)
      return ctx.store.getPackument(name)
    }),
  )
}

async function refreshOsv(
  ctx: { store: Store; fetcher: Fetcher; gate: UpstreamGate; flights: SingleFlight },
  name: string,
  version: string,
  observedAt: string,
  previous: ReturnType<Store["getOsv"]>,
): Promise<ReturnType<Store["getOsv"]>> {
  return ctx.flights.run(`osv:${name}@${version}`, () =>
    ctx.gate.run(async () => {
      const read = await readOsv(ctx.fetcher, name, version)
      if (read.state === "unavailable") return previous
      ctx.store.putOsv(name, version, observedAt, read.advisories)
      return ctx.store.getOsv(name, version)
    }),
  )
}

async function refreshKev(
  ctx: { store: Store; fetcher: Fetcher; gate: UpstreamGate; flights: SingleFlight },
  observedAt: string,
  previous: ReturnType<Store["getKev"]>,
): Promise<ReturnType<Store["getKev"]>> {
  return ctx.flights.run("kev", () =>
    ctx.gate.run(async () => {
      const read = await readKev(ctx.fetcher)
      if (read.state === "unavailable") return previous
      ctx.store.putKev(observedAt, read.catalogVersion, read.entries)
      return ctx.store.getKev()
    }),
  )
}

async function refreshDeps(
  ctx: { store: Store; fetcher: Fetcher; gate: UpstreamGate; flights: SingleFlight },
  name: string,
  version: string,
  observedAt: string,
  previous: ReturnType<Store["getDependents"]>,
): Promise<ReturnType<Store["getDependents"]>> {
  return ctx.flights.run(`deps:${name}@${version}`, () =>
    ctx.gate.run(async () => {
      const read = await readDependents(ctx.fetcher, name, version)
      if (read.state === "unavailable") return previous
      ctx.store.putDependents(name, version, observedAt, read.counts)
      return ctx.store.getDependents(name, version)
    }),
  )
}

async function refreshScorecard(
  ctx: { store: Store; fetcher: Fetcher; gate: UpstreamGate; flights: SingleFlight },
  repo: string,
  observedAt: string,
  previous: ReturnType<Store["getScorecard"]>,
): Promise<ReturnType<Store["getScorecard"]>> {
  return ctx.flights.run(`scorecard:${repo}`, () =>
    ctx.gate.run(async () => {
      const read = await readScorecard(ctx.fetcher, repo)
      if (read.state === "unavailable") return previous
      if (read.state === "absent") {
        ctx.store.putScorecardAbsent(repo, observedAt)
        return ctx.store.getScorecard(repo)
      }
      const report: Omit<ScorecardProjection, "observedAt" | "repo"> = read.report
      ctx.store.putScorecardPresent(repo, observedAt, report)
      return ctx.store.getScorecard(repo)
    }),
  )
}
