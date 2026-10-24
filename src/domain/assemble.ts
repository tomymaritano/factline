import { publisherWindow } from "./burst.ts"
import { diffHooks } from "./hooks.ts"
import { selectPredecessor } from "./predecessor.ts"
import {
  DEPENDENTS_WORDING,
  type DependentsProjection,
  type EventFact,
  type KevProjection,
  type Notice,
  type OsvProjection,
  type PackumentProjection,
  type Reading,
  type ScorecardProjection,
  type SourceStatus,
  type Timeline,
  type VersionRecord,
} from "./types.ts"

const CVE_ID = /^CVE-\d{4}-\d+$/
const KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
const KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

const KIND_ORDER: Record<EventFact["kind"], number> = {
  version_published: 0,
  install_hooks: 1,
  publisher_window: 2,
  osv: 3,
  kev: 4,
}

export type AssembleInput = {
  now: string
  subject: Timeline["subject"]
  registry: { projection: PackumentProjection; stale: boolean }
  osv: { state: "ok"; projection: OsvProjection; stale: boolean } | { state: "unavailable" }
  kev: { state: "ok"; projection: KevProjection; stale: boolean } | { state: "unavailable" }
  deps: { state: "ok"; projection: DependentsProjection; stale: boolean } | { state: "unavailable" }
  scorecard:
    | { state: "present"; projection: ScorecardProjection; stale: boolean }
    | { state: "absent"; repo: string; observedAt: string; stale: boolean }
    | { state: "unavailable"; repo: string }
    | { state: "no_repository" }
    | { state: "not_github" }
}

export function assembleTimeline(input: AssembleInput): Timeline {
  const subjectVersion = input.registry.projection.versions.find(
    (version) => version.version === input.subject.version,
  )
  if (!subjectVersion) {
    throw new Error(`assembleTimeline called without ${input.subject.version}`)
  }

  const events: EventFact[] = []
  const readings: Reading[] = []
  const notices: Notice[] = []
  const registryUrl = `https://registry.npmjs.org/${encodeURIComponent(input.subject.name)}`

  notices.push({
    source: "registry",
    code: "cdn_lag",
    text: "Publish times come from the npm packument. The registry CDN can lag a publish.",
  })

  events.push({
    kind: "version_published",
    id: `publish:${input.subject.name}@${input.subject.version}`,
    occurredAt: subjectVersion.publishedAt,
    precision: "instant",
    sourceUrl: registryUrl,
    observedAt: input.registry.projection.observedAt,
    stale: input.registry.stale,
    version: subjectVersion.version,
    publisher: subjectVersion.publisher,
  })

  const predecessor = selectPredecessor(input.registry.projection.versions, subjectVersion)
  const previousRecord = predecessor
    ? input.registry.projection.versions.find((version) => version.version === predecessor.version) ?? null
    : null
  const hookDiff = diffHooks(subjectVersion.hooks, previousRecord ? previousRecord.hooks : null)
  events.push({
    kind: "install_hooks",
    id: `hooks:${input.subject.name}@${input.subject.version}`,
    occurredAt: subjectVersion.publishedAt,
    precision: "instant",
    sourceUrl: registryUrl,
    observedAt: input.registry.projection.observedAt,
    stale: input.registry.stale,
    baseline: hookDiff.baseline,
    predecessor,
    differs: hookDiff.differs,
    hooks: hookDiff.hooks,
  })

  if (!subjectVersion.publisher) {
    notices.push({
      source: "registry",
      code: "publisher_unknown",
      text: "This version has no _npmUser.name on the packument, so there is no publisher window.",
    })
  } else {
    const burst = publisherWindow(input.registry.projection.versions, subjectVersion)
    if (burst) {
      events.push({
        kind: "publisher_window",
        id: `burst:${input.subject.name}@${input.subject.version}`,
        occurredAt: subjectVersion.publishedAt,
        precision: "instant",
        sourceUrl: registryUrl,
        observedAt: input.registry.projection.observedAt,
        stale: input.registry.stale,
        ...burst,
      })
    }
  }

  const tied = new Map<string, string[]>()
  if (input.osv.state === "unavailable") {
    notices.push({
      source: "osv",
      code: "osv_unavailable",
      text: "OSV did not answer. Advisory rows and KEV rows are omitted.",
    })
  } else if (input.osv.projection.advisories.length === 0) {
    notices.push({
      source: "osv",
      code: "no_advisories",
      text: "OSV returned no advisories for this version.",
    })
  } else {
    for (const advisory of input.osv.projection.advisories) {
      const cves = tiedCves(advisory.id, advisory.aliases)
      for (const cve of cves) {
        const owners = tied.get(cve) ?? []
        owners.push(advisory.id)
        tied.set(cve, owners)
      }
      const time = advisoryTime(advisory, input.osv.projection.observedAt)
      events.push({
        kind: "osv",
        id: advisory.id,
        occurredAt: time.occurredAt,
        precision: time.precision,
        sourceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`,
        observedAt: input.osv.projection.observedAt,
        stale: input.osv.stale,
        timeField: time.timeField,
        modifiedAt: advisory.modified,
        malicious: advisory.id.startsWith("MAL-"),
        summary: advisory.summary,
        ranges: advisory.ranges,
        explicitVersions: advisory.explicitVersions,
        explicitVersionCount: advisory.explicitVersionCount,
        aliases: advisory.aliases,
        tiedCves: cves,
      })
    }
    if (tied.size === 0) {
      notices.push({
        source: "osv",
        code: "no_cve_tied",
        text: "OSV advisories for this version name no CVE id, so KEV was not joined.",
      })
    }
  }

  // KEV has no version range. A row exists only when OSV already named the CVE.
  if (input.osv.state !== "unavailable" && tied.size > 0) {
    if (input.kev.state === "unavailable") {
      notices.push({
        source: "kev",
        code: "kev_unavailable",
        text: "The KEV catalog is unavailable. No KEV row is shown.",
      })
    } else {
      const catalog = new Map(input.kev.projection.entries.map((entry) => [entry.cveId, entry]))
      const missing: string[] = []
      for (const [cveId, osvIds] of tied) {
        const entry = catalog.get(cveId)
        if (!entry) {
          missing.push(cveId)
          continue
        }
        events.push({
          kind: "kev",
          id: `kev:${cveId}`,
          occurredAt: kevInstant(entry.dateAdded),
          precision: "date",
          sourceUrl: KEV_PAGE,
          observedAt: input.kev.projection.observedAt,
          stale: input.kev.stale,
          feedUrl: KEV_FEED,
          cveId,
          vulnerabilityName: entry.vulnerabilityName,
          requiredAction: entry.requiredAction,
          dueDate: entry.dueDate,
          tiedBy: osvIds,
        })
      }
      if (missing.length > 0) {
        missing.sort()
        notices.push({
          source: "kev",
          code: "tied_cves_not_in_kev",
          text: `These CVEs are tied to this version by OSV and are not in the KEV catalog loaded at ${input.kev.projection.observedAt}: ${missing.join(", ")}.`,
        })
      }
    }
  }

  if (input.deps.state === "unavailable") {
    notices.push({
      source: "deps",
      code: "dependents_unavailable",
      text: "deps.dev did not return a dependent count. No count is shown.",
    })
  } else {
    const deps = input.deps.projection
    readings.push({
      kind: "public_dependents",
      observedAt: deps.observedAt,
      stale: input.deps.stale,
      sourceUrl: dependentsUrl(input.subject.name, input.subject.version),
      dependentCount: deps.dependentCount,
      directDependentCount: deps.directDependentCount,
      indirectDependentCount: deps.indirectDependentCount,
      wording: DEPENDENTS_WORDING,
    })
  }

  pushScorecard(input, readings, notices)

  if (input.registry.stale) pushStale(notices, "registry")
  if (input.osv.state !== "unavailable" && input.osv.stale) pushStale(notices, "osv")
  if (input.kev.state !== "unavailable" && input.kev.stale && tied.size > 0) pushStale(notices, "kev")
  if (input.deps.state !== "unavailable" && input.deps.stale) pushStale(notices, "deps")
  if (input.scorecard.state === "present" && input.scorecard.stale) pushStale(notices, "scorecard")
  if (input.scorecard.state === "absent" && input.scorecard.stale) pushStale(notices, "scorecard")

  events.sort((a, b) => {
    if (a.occurredAt !== b.occurredAt) return a.occurredAt < b.occurredAt ? -1 : 1
    const kind = KIND_ORDER[a.kind] - KIND_ORDER[b.kind]
    if (kind !== 0) return kind
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
  })

  return {
    subject: input.subject,
    generatedAt: input.now,
    events,
    readings,
    notices,
    sources: sourceStatuses(input),
  }
}

export function dependentsUrl(name: string, version: string): string {
  return `https://api.deps.dev/v3alpha/systems/npm/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}:dependents`
}

function pushScorecard(input: AssembleInput, readings: Reading[], notices: Notice[]): void {
  const scorecard = input.scorecard
  if (scorecard.state === "no_repository") {
    notices.push({
      source: "scorecard",
      code: "scorecard_no_repository",
      text: "This version has no repository field. Scorecard was not asked.",
    })
    return
  }
  if (scorecard.state === "not_github") {
    notices.push({
      source: "scorecard",
      code: "scorecard_not_github",
      text: "The version repository is not a github.com URL, so there is no Scorecard lookup.",
    })
    return
  }
  if (scorecard.state === "unavailable") {
    notices.push({
      source: "scorecard",
      code: "scorecard_unavailable",
      text: `Scorecard did not answer for ${scorecard.repo}.`,
    })
    return
  }
  if (scorecard.state === "absent") {
    notices.push({
      source: "scorecard",
      code: "scorecard_absent",
      text: `No published OpenSSF Scorecard report for ${scorecard.repo}.`,
    })
    return
  }
  const report = scorecard.projection
  readings.push({
    kind: "scorecard",
    observedAt: report.observedAt,
    stale: scorecard.stale,
    sourceUrl: `https://scorecard.dev/viewer/?uri=${encodeURIComponent(report.repo)}`,
    apiUrl: `https://api.scorecard.dev/projects/${report.repo}`,
    reportedAt: report.reportedAt,
    repo: report.repo,
    score: report.score,
    commit: report.commit,
    scorecardVersion: report.scorecardVersion,
    checks: report.checks,
  })
}

function sourceStatuses(input: AssembleInput): SourceStatus[] {
  const osv: SourceStatus =
    input.osv.state === "unavailable"
      ? { source: "osv", observedAt: null, stale: false, state: "unavailable" }
      : {
          source: "osv",
          observedAt: input.osv.projection.observedAt,
          stale: input.osv.stale,
          state: "ok",
        }
  const kev: SourceStatus =
    input.kev.state === "unavailable"
      ? { source: "kev", observedAt: null, stale: false, state: "unavailable" }
      : {
          source: "kev",
          observedAt: input.kev.projection.observedAt,
          stale: input.kev.stale,
          state: "ok",
        }
  const deps: SourceStatus =
    input.deps.state === "unavailable"
      ? { source: "deps", observedAt: null, stale: false, state: "unavailable" }
      : {
          source: "deps",
          observedAt: input.deps.projection.observedAt,
          stale: input.deps.stale,
          state: "ok",
        }
  return [
    {
      source: "registry",
      observedAt: input.registry.projection.observedAt,
      stale: input.registry.stale,
      state: "ok",
    },
    osv,
    kev,
    deps,
    scorecardStatus(input),
  ]
}

function scorecardStatus(input: AssembleInput): SourceStatus {
  const scorecard = input.scorecard
  if (scorecard.state === "no_repository" || scorecard.state === "not_github") {
    return { source: "scorecard", observedAt: null, stale: false, state: "not_applicable" }
  }
  if (scorecard.state === "unavailable") {
    return { source: "scorecard", observedAt: null, stale: false, state: "unavailable" }
  }
  if (scorecard.state === "absent") {
    return {
      source: "scorecard",
      observedAt: scorecard.observedAt,
      stale: scorecard.stale,
      state: "absent",
    }
  }
  return {
    source: "scorecard",
    observedAt: scorecard.projection.observedAt,
    stale: scorecard.stale,
    state: "ok",
  }
}

function tiedCves(id: string, aliases: string[]): string[] {
  const found = new Set<string>()
  if (CVE_ID.test(id)) found.add(id)
  for (const alias of aliases) {
    if (CVE_ID.test(alias)) found.add(alias)
  }
  return [...found]
}

function kevInstant(dateAdded: string): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(dateAdded)) return `${dateAdded}T00:00:00.000Z`
  return dateAdded
}

function advisoryTime(
  advisory: { published: string | null; modified: string | null },
  observedAt: string,
): { occurredAt: string; precision: "instant" | "date"; timeField: "published" | "modified" | "observed" } {
  if (advisory.published) return { occurredAt: advisory.published, precision: "instant", timeField: "published" }
  if (advisory.modified) return { occurredAt: advisory.modified, precision: "instant", timeField: "modified" }
  return { occurredAt: observedAt, precision: "instant", timeField: "observed" }
}

function pushStale(notices: Notice[], source: Notice["source"]): void {
  notices.push({
    source,
    code: "source_stale",
    text: `The ${source} reading is older than its refresh window.`,
  })
}

export function findVersion(versions: VersionRecord[], version: string): VersionRecord | undefined {
  return versions.find((item) => item.version === version)
}
