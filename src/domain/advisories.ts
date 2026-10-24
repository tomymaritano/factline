import type { KevEntry, OsvAdvisory } from "./types.ts"
import { maliciousAdvisory, tiedCves } from "./cve.ts"

export const SCAN_EMPTY = "OSV returned no advisories for the versions in this scan."
export const SCAN_DOWN = "OSV did not answer. No advisory list."
export const SCAN_OMITTED = "The advisory list was not loaded."
export const SCAN_STALE = "The osv reading is older than its refresh window."
export const SCAN_KEV_DOWN = "The KEV catalog is unavailable. No KEV row is shown."

export type AdvisoryKev = {
  cveId: string
  vulnerabilityName: string
  dateAdded: string
  dueDate: string
  requiredAction: string
}

export type ScannedAdvisory = {
  id: string
  summary: string
  aliases: string[]
  malicious: boolean
  versions: string[]
  kev: AdvisoryKev[]
}

export type AdvisoryScan = {
  observedAt: string
  stale: boolean
  osv: "ok" | "unavailable" | "omitted"
  incompleteVersions: string[]
  advisories: ScannedAdvisory[]
  notices: Array<{ text: string }>
}

export type BatchRow = { version: string; ids: string[]; incomplete: boolean }

export function scannedVersions(index: { versions: string[]; distTags: Array<{ version: string }> }): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  const add = (version: string) => {
    if (seen.has(version)) return
    seen.add(version)
    out.push(version)
  }
  for (const version of index.versions) add(version)
  for (const tag of index.distTags) add(tag.version)
  return out
}

export function omittedScan(observedAt: string): AdvisoryScan {
  return {
    observedAt,
    stale: false,
    osv: "omitted",
    incompleteVersions: [],
    advisories: [],
    notices: [{ text: SCAN_OMITTED }],
  }
}

export function markScanStale(scan: AdvisoryScan): AdvisoryScan {
  if (scan.notices.some((notice) => notice.text === SCAN_STALE)) return { ...scan, stale: true }
  return { ...scan, stale: true, notices: [...scan.notices, { text: SCAN_STALE }] }
}

export function joinAdvisoryScan(input: {
  observedAt: string
  rows: BatchRow[] | null
  records: ReadonlyMap<string, OsvAdvisory | "missing">
  kev: { state: "skipped" } | { state: "unavailable" } | { state: "ok"; observedAt: string; entries: KevEntry[] }
}): AdvisoryScan {
  if (input.rows === null) {
    return {
      observedAt: input.observedAt,
      stale: false,
      osv: "unavailable",
      incompleteVersions: [],
      advisories: [],
      notices: [{ text: SCAN_DOWN }],
    }
  }

  const incompleteVersions = input.rows.filter((row) => row.incomplete).map((row) => row.version)
  const byId = new Map<string, string[]>()
  for (const row of input.rows) {
    const seen = new Set<string>()
    for (const id of row.ids) {
      if (seen.has(id)) continue
      seen.add(id)
      const versions = byId.get(id) ?? []
      if (!versions.includes(row.version)) versions.push(row.version)
      byId.set(id, versions)
    }
  }

  const notices: Array<{ text: string }> = []
  if (incompleteVersions.length > 0) {
    notices.push({
      text: `OSV did not finish the advisory list for ${incompleteVersions.join(", ")}. Those versions are not an empty result.`,
    })
  }

  const missing: string[] = []
  const advisories: ScannedAdvisory[] = []
  for (const id of [...byId.keys()].sort()) {
    const record = input.records.get(id)
    const versions = byId.get(id) ?? []
    if (!record || record === "missing") {
      missing.push(id)
      advisories.push({ id, summary: "", aliases: [], malicious: maliciousAdvisory(id), versions, kev: [] })
      continue
    }
    advisories.push({
      id: record.id,
      summary: record.summary,
      aliases: record.aliases,
      malicious: maliciousAdvisory(record.id),
      versions,
      kev: [],
    })
  }
  if (missing.length > 0) notices.push({ text: `OSV named ${missing.join(", ")} and did not return their records.` })
  if (advisories.length === 0 && incompleteVersions.length === 0) notices.push({ text: SCAN_EMPTY })

  const tied = new Map<string, string[]>()
  for (const advisory of advisories) {
    const record = input.records.get(advisory.id)
    if (!record || record === "missing") continue
    for (const cve of tiedCves(record.id, record.aliases)) {
      const owners = tied.get(cve) ?? []
      owners.push(advisory.id)
      tied.set(cve, owners)
    }
  }

  if (tied.size > 0 && input.kev.state === "ok") {
    const catalog = new Map(input.kev.entries.map((entry) => [entry.cveId, entry]))
    const absent: string[] = []
    for (const advisory of advisories) {
      const record = input.records.get(advisory.id)
      if (!record || record === "missing") continue
      for (const cve of tiedCves(record.id, record.aliases)) {
        const entry = catalog.get(cve)
        if (!entry) {
          absent.push(cve)
          continue
        }
        advisory.kev.push({
          cveId: entry.cveId,
          vulnerabilityName: entry.vulnerabilityName,
          dateAdded: entry.dateAdded,
          dueDate: entry.dueDate,
          requiredAction: entry.requiredAction,
        })
      }
    }
    if (absent.length > 0) {
      const unique = [...new Set(absent)].sort()
      notices.push({
        text: `These CVEs are tied to a scanned version by OSV and are not in the KEV catalog loaded at ${input.kev.observedAt}: ${unique.join(", ")}.`,
      })
    }
  } else if (tied.size > 0) {
    notices.push({ text: SCAN_KEV_DOWN })
  }

  return {
    observedAt: input.observedAt,
    stale: false,
    osv: "ok",
    incompleteVersions,
    advisories,
    notices,
  }
}
