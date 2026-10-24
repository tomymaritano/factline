export const HOOK_NAMES = ["preinstall", "install", "postinstall", "prepare"] as const

export type HookName = (typeof HOOK_NAMES)[number]

export type ShortCommand = {
  prefix: string
  truncated: boolean
  sha256: string
}

export type HookSet = Record<HookName, ShortCommand | null>

export type RepoParse =
  | { ok: true; repo: string }
  | { ok: false; reason: "no_repository" | "not_github" }

export type VersionRecord = {
  version: string
  publishedAt: string
  publisher: string | null
  hooks: HookSet
  repository: RepoParse
}

export type PackumentProjection = {
  observedAt: string
  distTags: Record<string, string>
  versions: VersionRecord[]
}

export type OsvRange = {
  type: string
  events: Array<{
    introduced?: string
    fixed?: string
    lastAffected?: string
    limit?: string
  }>
}

export type OsvAdvisory = {
  id: string
  published: string | null
  modified: string | null
  summary: string
  aliases: string[]
  ranges: OsvRange[]
  explicitVersions: string[]
  explicitVersionCount: number
}

export type OsvProjection = {
  observedAt: string
  advisories: OsvAdvisory[]
}

export type KevEntry = {
  cveId: string
  vulnerabilityName: string
  dateAdded: string
  dueDate: string
  requiredAction: string
}

export type KevProjection = {
  observedAt: string
  catalogVersion: string | null
  entries: KevEntry[]
}

export type DependentsProjection = {
  observedAt: string
  dependentCount: number
  directDependentCount: number
  indirectDependentCount: number
}

export type ScorecardCheck = {
  name: string
  score: number
  reason: string
}

export type ScorecardProjection = {
  observedAt: string
  repo: string
  reportedAt: string
  score: number
  commit: string | null
  scorecardVersion: string | null
  checks: ScorecardCheck[]
}

export type SourceName = "registry" | "osv" | "kev" | "deps" | "scorecard"

export type NoticeCode =
  | "cdn_lag"
  | "no_advisories"
  | "osv_unavailable"
  | "no_cve_tied"
  | "tied_cves_not_in_kev"
  | "kev_unavailable"
  | "dependents_unavailable"
  | "scorecard_absent"
  | "scorecard_not_github"
  | "scorecard_no_repository"
  | "scorecard_unavailable"
  | "publisher_unknown"
  | "source_stale"

export type Notice = {
  source: SourceName
  code: NoticeCode
  text: string
}

export type SourceState = "ok" | "absent" | "unavailable" | "not_applicable"

export type SourceStatus = {
  source: SourceName
  observedAt: string | null
  stale: boolean
  state: SourceState
}

type FactBase = {
  id: string
  occurredAt: string
  precision: "instant" | "date"
  sourceUrl: string
  observedAt: string
  stale: boolean
}

export type VersionPublished = FactBase & {
  kind: "version_published"
  version: string
  publisher: string | null
}

export type InstallHooks = FactBase & {
  kind: "install_hooks"
  baseline: "predecessor" | "none"
  predecessor: { version: string; publishedAt: string } | null
  differs: boolean
  hooks: Array<{
    hook: HookName
    change: "added" | "removed" | "modified" | "unchanged"
    command: ShortCommand | null
    previousCommand: ShortCommand | null
  }>
}

export type PublisherWindow = FactBase & {
  kind: "publisher_window"
  publisher: string
  windowMinutes: number
  notableMinimum: number
  count: number
  versions: string[]
  notable: boolean
}

export type OsvFact = FactBase & {
  kind: "osv"
  timeField: "published" | "modified" | "observed"
  modifiedAt: string | null
  malicious: boolean
  summary: string
  ranges: OsvRange[]
  explicitVersions: string[]
  explicitVersionCount: number
  aliases: string[]
  tiedCves: string[]
}

export type KevFact = FactBase & {
  kind: "kev"
  feedUrl: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  cveId: string
  vulnerabilityName: string
  requiredAction: string
  dueDate: string
  tiedBy: string[]
}

export type EventFact = VersionPublished | InstallHooks | PublisherWindow | OsvFact | KevFact

export const DEPENDENTS_WORDING =
  "Public count of packages known to deps.dev. Not a census of the web or of private repositories."

export type DependentsReading = {
  kind: "public_dependents"
  observedAt: string
  stale: boolean
  sourceUrl: string
  dependentCount: number
  directDependentCount: number
  indirectDependentCount: number
  wording: typeof DEPENDENTS_WORDING
}

export type ScorecardReading = {
  kind: "scorecard"
  observedAt: string
  stale: boolean
  sourceUrl: string
  apiUrl: string
  reportedAt: string
  repo: string
  score: number
  commit: string | null
  scorecardVersion: string | null
  checks: ScorecardCheck[]
}

export type Reading = DependentsReading | ScorecardReading

export type Timeline = {
  subject: {
    name: string
    version: string
    requestedVersion: string
    resolvedFromTag: string | null
  }
  generatedAt: string
  events: EventFact[]
  readings: Reading[]
  notices: Notice[]
  sources: SourceStatus[]
}
