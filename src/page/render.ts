import type { SuggestResult, VersionsResult } from "../catalog.ts"
import type { AdvisoryScan, ScannedAdvisory } from "../domain/advisories.ts"
import { validName } from "../domain/validate.ts"
import type { EventFact, Reading, Timeline } from "../domain/types.ts"
import type { VersionIndex } from "../readers/catalog.ts"
import { escapeHtml } from "./escape.ts"
import { markSvg } from "./mark.ts"

const OSV_VULN = "https://osv.dev/vulnerability/"
const KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

const SOURCE_PREFIXES = [
  "https://registry.npmjs.org/",
  OSV_VULN,
  KEV_CATALOG,
  "https://api.deps.dev/",
  "https://scorecard.dev/viewer/",
]

const ERRORS = {
  invalid_name: "Package names are lowercase npm names, with an optional scope.",
  invalid_version: "Use an exact version or a dist-tag. Ranges stay out.",
  not_found: "The registry has no such package or version.",
  registry_unavailable: "The registry did not answer, and there is no cached copy.",
  rate_limited: "Too many new lookups from this address. A page already cached on the server still opens.",
  internal: "Factline failed before it could build the timeline.",
} as const

export type RecentRow = {
  kind: "version" | "package" | "search"
  name: string
  version: string
  query: string
  lookedUpAt: string
}

export function renderEmpty(recent: RecentRow[]): string {
  return shell({
    title: "Factline",
    query: "",
    status: "",
    home: true,
    main: `${stand("Nothing on the line yet.")}${recentBlock(recent)}`,
  })
}

export function renderError(error: keyof typeof ERRORS, recent: RecentRow[]): string {
  return shell({
    title: "Factline",
    query: "",
    status: "",
    main: `${stand(ERRORS[error])}${recentBlock(recent)}`,
  })
}

export function renderTimeline(timeline: Timeline, recent: RecentRow[]): string {
  const subject = `${timeline.subject.name}@${timeline.subject.version}`
  const notices = timeline.notices.map((notice) => `<li>${escapeHtml(notice.text)}</li>`).join("")
  const events = timeline.events.map(renderEvent).join("")
  const readings = timeline.readings.length === 0
    ? `<p class="wording">No repository or popularity reading for this version.</p>`
    : timeline.readings.map(renderReading).join("")
  const sources = timeline.sources
    .map((source) => {
      const when = source.observedAt ? source.observedAt : "not observed"
      const stale = source.stale ? ", older than its refresh window" : ""
      return `<li><span class="paste">${escapeHtml(source.source)}</span><span class="quiet">${escapeHtml(source.state)}${escapeHtml(stale)}</span><time>${escapeHtml(when)}</time></li>`
    })
    .join("")
  return shell({
    title: `${subject} · Factline`,
    query: "",
    status: "",
    main: `
      <h1 class="paste subject">${escapeHtml(subject)}</h1>
      <p class="quiet subject-meta"><span class="paste">Generated ${escapeHtml(timeline.generatedAt)}</span></p>
      <p class="quiet subject-links"><a href="${href(versionsHref(timeline.subject.name))}">All versions</a> · ${npmLink(timeline.subject.name)}</p>
      <ul class="notices">${notices}</ul>
      <div class="sheet">
        <ol class="events">${events}</ol>
        <aside class="readings">
          <h2>Off the line</h2>
          ${readings}
        </aside>
      </div>
      <section class="sources">
        <h2>Sources</h2>
        <ul>${sources}</ul>
      </section>
      ${recentBlock(recent)}
    `,
  })
}

export function renderVersions(name: string, index: VersionIndex, scan: AdvisoryScan, recent: RecentRow[]): string {
  const named = advisoryIdsByVersion(scan)
  const tags = index.distTags
    .map(
      (tag) =>
        `<li><span class="version-label"><a class="paste" href="${href(timelineHref(name, tag.version))}">${escapeHtml(tag.tag)}</a> <span class="paste quiet">${escapeHtml(tag.version)}</span></span>${versionMark(named, tag.version)}</li>`,
    )
    .join("")
  const versions = index.versions
    .map((version) => `<li><a class="paste" href="${href(timelineHref(name, version))}">${escapeHtml(version)}</a>${versionMark(named, version)}</li>`)
    .join("")
  const more = index.truncated
    ? `<p class="quiet">Showing the newest ${index.versions.length} of ${index.total} versions. Search ${escapeHtml(name)}@ and the exact version to open an older one.</p>`
    : ""
  return shell({
    title: `${name} · Factline`,
    query: name,
    status: "",
    main: `
      <h1 class="paste subject">${escapeHtml(name)}</h1>
      <p class="quiet subject-meta">${npmLink(name)} · ${index.total} versions in the registry.</p>
      ${renderAdvisories(name, scan)}
      <h2>Dist-tags</h2>
      <ul class="versions">${tags}</ul>
      <h2>Versions</h2>
      <ul class="versions">${versions}</ul>
      ${more}
      ${recentBlock(recent)}
    `,
  })
}

export function renderResults(query: string, result: SuggestResult, recent: RecentRow[]): string {
  return shell({
    title: query ? `${query} · Factline` : "Factline",
    query,
    status: result.kind === "limited" ? ERRORS.rate_limited : result.kind === "unavailable" ? ERRORS.registry_unavailable : "",
    heading: query,
    suggest: suggestMarkup(query, result, recent),
    main: recentBlock(recent),
  })
}

export function renderSuggest(query: string, result: SuggestResult, recent: RecentRow[]): string {
  return suggestMarkup(query, result, recent)
}

function suggestMarkup(query: string, result: SuggestResult, recent: RecentRow[]): string {
  if (result.kind === "recent") {
    if (query.length === 1) return `<p class="quiet">Type at least two characters. The search covers the public npm registry.</p>`
    return recent.length === 0
      ? `<p class="quiet">Search covers every public npm package.</p>`
      : `<ul class="hits">${recent.map(recentItem).join("")}</ul>`
  }
  if (result.kind === "open") {
    return `<ul class="hits"><li><a class="paste" href="${href(timelineHref(result.name, result.version))}">Open ${escapeHtml(`${result.name}@${result.version}`)}</a></li></ul>`
  }
  if (result.kind === "limited") return `<p class="quiet">${escapeHtml(ERRORS.rate_limited)}</p>`
  if (result.kind === "unavailable") return `<p class="quiet">${escapeHtml(ERRORS.registry_unavailable)}</p>`
  if (result.hits.length === 0) return `<p class="quiet">The registry returned no packages for that search.</p>`
  return `<ul class="hits">${result.hits.map(hitItem).join("")}</ul>`
}

function hitItem(hit: { name: string; description: string; version: string }): string {
  return `<li class="hit">
    <a class="paste hit-name" href="${href(versionsHref(hit.name))}">${escapeHtml(hit.name)}</a>
    <p class="meta hit-meta"><a class="paste" href="${href(timelineHref(hit.name, hit.version))}">${escapeHtml(hit.version)}</a> · ${npmLink(hit.name)}</p>
    <p class="hit-desc">${escapeHtml(hit.description)}</p>
  </li>`
}

function recentItem(row: RecentRow): string {
  if (row.kind === "search") {
    const searchHref = `/search?${new URLSearchParams({ q: row.query }).toString()}`
    return `<li class="recent-row"><a class="paste" href="${href(searchHref)}">${escapeHtml(row.query)}</a><time>${escapeHtml(row.lookedUpAt)}</time></li>`
  }
  if (row.kind === "package") {
    return `<li class="recent-row"><a class="paste" href="${href(versionsHref(row.name))}">${escapeHtml(row.name)}</a><time>${escapeHtml(row.lookedUpAt)}</time></li>`
  }
  return `<li class="recent-row"><a class="paste" href="${href(timelineHref(row.name, row.version))}">${escapeHtml(`${row.name}@${row.version}`)}</a><time>${escapeHtml(row.lookedUpAt)}</time></li>`
}

function renderEvent(fact: EventFact): string {
  const when = hourParts(fact.occurredAt, fact.precision)
  const time = when.time ? `<span>${escapeHtml(when.time)} UTC</span>` : ""
  return `<li class="event">
    <p class="hour">${escapeHtml(when.date)}${time}</p>
    <div class="body">
      <i class="marker"></i>
      ${eventBody(fact)}
      <p class="meta">${sourceLink(fact.sourceUrl)} · observed ${escapeHtml(fact.observedAt)}${fact.stale ? " · stale" : ""}</p>
    </div>
  </li>`
}

function eventBody(fact: EventFact): string {
  switch (fact.kind) {
    case "version_published":
      return `<h3>Published</h3><p class="fact-statement">${escapeHtml(fact.publisher ? `Publisher ${fact.publisher}` : "No publisher name on this version.")}</p>`
    case "install_hooks": {
      const statement = fact.baseline === "none"
        ? "These hooks are listed, not compared."
        : `${fact.differs ? "Hooks differ from" : "Hooks match"} ${fact.predecessor?.version ?? ""}`.trim()
      const rows = fact.hooks
        .map((hook) => {
          const command = hook.command
            ? `<div class="paste">${escapeHtml(hook.command.prefix)}${hook.command.truncated ? "…" : ""}</div><div class="paste quiet">${escapeHtml(hook.command.sha256)}</div>`
            : ""
          const previous = hook.previousCommand && hook.change === "modified"
            ? `<span class="quiet"> Previous prefix differs by hash.</span>`
            : ""
          return `<li><span class="paste">${escapeHtml(`${hook.hook}: ${hook.change}`)}</span>${command}${previous}</li>`
        })
        .join("")
      return `<h3>Install hooks</h3><p class="fact-statement">${escapeHtml(statement)}</p><ul>${rows}</ul>`
    }
    case "publisher_window": {
      const count = `${fact.count} ${fact.count === 1 ? "version" : "versions"} by ${fact.publisher}, including this one.`
      const rule = `Same _npmUser.name, ${fact.windowMinutes} minutes either side, versions still in the packument. Notable means the count is at least ${fact.notableMinimum}. The count is the fact.`
      const notable = fact.notable ? `<p>Notable</p>` : ""
      const versions = fact.versions.map((version) => `<li class="paste">${escapeHtml(version)}</li>`).join("")
      return `<h3>Publisher window</h3><p class="fact-statement">${escapeHtml(count)}</p><p class="quiet">${escapeHtml(rule)}</p>${notable}<ul>${versions}</ul>`
    }
    case "osv": {
      const statement = [fact.malicious ? "Malicious-package record." : "", fact.summary].filter(Boolean).join(" ")
      const aliases = fact.aliases.length > 0 ? `<p class="paste quiet">Aliases ${escapeHtml(fact.aliases.join(", "))}</p>` : ""
      const ranges = fact.ranges
        .map((range) => {
          const bits = range.events.map((event) => {
            const [key, value] = Object.entries(event)[0] ?? ["event", ""]
            return `${key} ${value}`
          })
          return `<li>${escapeHtml(`${range.type}: ${bits.join(", ")}`)}</li>`
        })
        .join("")
      const rangeList = fact.ranges.length > 0 ? `<ul>${ranges}</ul>` : ""
      const explicit = fact.explicitVersionCount > 0
        ? `<p class="quiet">${fact.explicitVersionCount} explicit versions. Showing ${fact.explicitVersions.length}.</p>`
        : ""
      return `<h3 class="paste">${escapeHtml(fact.id)}</h3><p class="fact-statement">${escapeHtml(statement)}</p>${aliases}${rangeList}${explicit}`
    }
    case "kev":
      return `<h3 class="paste">${escapeHtml(fact.cveId)}</h3><p class="fact-statement">${escapeHtml(fact.vulnerabilityName)}</p><p>Required action: ${escapeHtml(fact.requiredAction)}</p><p class="quiet">Due ${escapeHtml(fact.dueDate)}. Tied by ${escapeHtml(fact.tiedBy.join(", "))}.</p>`
  }
}

function renderReading(reading: Reading): string {
  if (reading.kind === "public_dependents") {
    return `<section class="reading">
      <h3>Public dependents</h3>
      <p class="count">${reading.dependentCount}</p>
      <p class="quiet">${reading.directDependentCount} direct, ${reading.indirectDependentCount} indirect</p>
      <p class="wording">${escapeHtml(reading.wording)}</p>
    </section>`
  }
  const checks = reading.checks
    .map(
      (check) =>
        `<li><span class="check-name">${escapeHtml(check.name)}</span><span class="paste check-score">${check.score}</span><span class="check-reason">${escapeHtml(check.reason)}</span></li>`,
    )
    .join("")
  return `<section class="reading">
    <h3>Scorecard ${reading.score}</h3>
    <p class="paste">${escapeHtml(reading.repo)}</p>
    <p class="wording">This is the repository Scorecard scanned, not the commit npm packed for this version.</p>
    <p class="quiet">Report ${escapeHtml(reading.reportedAt)}</p>
    <ul class="checks">${checks}</ul>
  </section>`
}

function renderAdvisories(name: string, scan: AdvisoryScan): string {
  const notices = scan.notices.map((notice) => `<p class="quiet">${escapeHtml(notice.text)}</p>`).join("")
  const articles = scan.advisories.map((advisory) => renderAdvisory(name, advisory)).join("")
  return `<section class="advisories"><h2>Advisories</h2>${notices}${articles}</section>`
}

function renderAdvisory(name: string, advisory: ScannedAdvisory): string {
  const statement = [advisory.malicious ? "Malicious-package record." : "", advisory.summary].filter(Boolean).join(" ")
  const statementHtml = statement ? `<p class="fact-statement">${escapeHtml(statement)}</p>` : ""
  const aliases = advisory.aliases.length > 0 ? `<p class="paste quiet">Aliases ${escapeHtml(advisory.aliases.join(", "))}</p>` : ""
  const versions = advisory.versions
    .map((version) => `<li><a class="paste" href="${href(timelineHref(name, version))}">${escapeHtml(version)}</a></li>`)
    .join("")
  const kev = advisory.kev
    .map(
      (row) =>
        `<h3 class="paste">${escapeHtml(row.cveId)}</h3><p class="fact-statement">${escapeHtml(row.vulnerabilityName)}</p><p>Required action: ${escapeHtml(row.requiredAction)}</p><p class="quiet">Added ${escapeHtml(row.dateAdded)}. Due ${escapeHtml(row.dueDate)}. <a href="${escapeHtml(KEV_CATALOG)}">Catalog</a></p>`,
    )
    .join("")
  const url = `${OSV_VULN}${encodeURIComponent(advisory.id)}`
  return `<article class="advisory"><h3 class="paste"><a href="${escapeHtml(url)}">${escapeHtml(advisory.id)}</a></h3>${statementHtml}${aliases}<ul class="advisory-versions">${versions}</ul>${kev}</article>`
}

function advisoryIdsByVersion(scan: AdvisoryScan): Map<string, string[]> {
  const named = new Map<string, string[]>()
  if (scan.osv !== "ok") return named
  for (const advisory of scan.advisories) {
    for (const version of advisory.versions) {
      const ids = named.get(version) ?? []
      if (!ids.includes(advisory.id)) ids.push(advisory.id)
      named.set(version, ids)
    }
  }
  return named
}

function versionMark(named: Map<string, string[]>, version: string): string {
  const ids = named.get(version)
  if (!ids || ids.length === 0) return ""
  return `<span class="advisory-ids paste fact-statement">${escapeHtml(ids.join(" "))}</span>`
}

function stand(text: string): string {
  return `<p class="stand">${escapeHtml(text)}</p>`
}

function recentBlock(recent: RecentRow[]): string {
  const items = recent.length === 0
    ? `<li class="quiet">No searches yet from this server.</li>`
    : recent.map(recentItem).join("")
  return `<section class="recent-block"><h2>Recent searches on this server</h2><ul class="recent">${items}</ul></section>`
}

function shell(options: {
  title: string
  query: string
  status: string
  main: string
  suggest?: string
  home?: boolean
  heading?: string
}): string {
  const thesis = options.home
    ? `<h1 class="sentence">Everything public that happened to one npm version, in order, with sources.</h1>
    <p class="lede">Publish, install hooks, advisories, and KEV stay on the line. The repository report and the public dependent count stay off it.</p>
    <p class="hint"><a href="${href(timelineHref("ms", "2.1.3"))}">ms@2.1.3</a> · Exact versions and dist-tags. Ranges stay out.</p>`
    : ""
  const heading = options.heading ? `<h1 class="paste page-title">${escapeHtml(options.heading)}</h1>` : ""
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(options.title)}</title>
  <link rel="icon" href="/mark.svg">
  <link rel="stylesheet" href="/color.css">
  <link rel="stylesheet" href="/type.css">
  <link rel="stylesheet" href="/page.css">
</head>
<body>
  <div class="wrap">
    <header class="mast">
      <a class="brand" href="/">
        ${markSvg()}
        <span class="brand-name">
          <span class="wordmark">Factline</span>
          <span class="lane">npm · one version</span>
        </span>
      </a>
      <form class="lookup" method="get" action="/search">
        <label class="field">
          <span class="label">Package</span>
          <input class="paste" name="q" value="${escapeHtml(options.query)}" autocomplete="off" spellcheck="false" placeholder="ms or @scope/pkg" hx-get="/api/v1/suggest" hx-trigger="input changed delay:250ms" hx-target="#suggest" hx-swap="innerHTML" hx-push-url="false">
        </label>
        <button type="submit">Search the registry</button>
      </form>
    </header>
    ${thesis}
    ${heading}
    <div id="suggest">${options.suggest ?? ""}</div>
    <p id="status" role="status">${escapeHtml(options.status)}</p>
    <main>${options.main}</main>
  </div>
  <script src="/htmx-4.0.0.min.js" defer></script>
</body>
</html>`
}

function hourParts(occurredAt: string, precision: "instant" | "date"): { date: string; time: string | null } {
  if (precision === "date") return { date: occurredAt.slice(0, 10), time: null }
  const parsed = new Date(occurredAt)
  if (Number.isNaN(parsed.getTime())) return { date: occurredAt, time: null }
  const month = String(parsed.getUTCMonth() + 1).padStart(2, "0")
  const day = String(parsed.getUTCDate()).padStart(2, "0")
  const hours = String(parsed.getUTCHours()).padStart(2, "0")
  const minutes = String(parsed.getUTCMinutes()).padStart(2, "0")
  return { date: `${parsed.getUTCFullYear()}-${month}-${day}`, time: `${hours}:${minutes}` }
}

function sourceLink(url: string): string {
  if (!SOURCE_PREFIXES.some((prefix) => url.startsWith(prefix))) return "Source"
  return `<a href="${escapeHtml(url)}">Source</a>`
}

function npmLink(name: string): string {
  if (!validName(name)) return "npm"
  const hrefValue = `https://www.npmjs.com/package/${name.split("/").map(encodeURIComponent).join("/")}`
  return `<a href="${escapeHtml(hrefValue)}">npm</a>`
}

function timelineHref(name: string, version: string): string {
  return `/?${new URLSearchParams({ name, version }).toString()}`
}

function versionsHref(name: string): string {
  return `/?${new URLSearchParams({ name }).toString()}`
}

function href(value: string): string {
  return escapeHtml(value)
}

export function versionsResultPage(name: string, result: VersionsResult, recent: RecentRow[]): { status: number; html: string } {
  if (result.status === 200) return { status: 200, html: renderVersions(name, result.index, result.scan, recent) }
  const error = result.status === 400 ? "invalid_name" : result.status === 404 ? "not_found" : result.status === 429 ? "rate_limited" : "registry_unavailable"
  return { status: result.status, html: renderError(error, recent) }
}
