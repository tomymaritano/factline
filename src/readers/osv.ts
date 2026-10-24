import type { OsvAdvisory, OsvRange } from "../domain/types.ts"
import { fetchJson, type Fetcher } from "./http.ts"

const SUMMARY_CODE_POINTS = 240
const EXPLICIT_VERSION_CAP = 50

export type OsvRead =
  | { state: "ok"; advisories: OsvAdvisory[] }
  | { state: "unavailable" }

export type OsvBatchRow = { version: string; ids: string[]; incomplete: boolean }

export async function readOsvBatch(
  fetcher: Fetcher,
  name: string,
  versions: string[],
): Promise<{ state: "ok"; rows: OsvBatchRow[] } | { state: "unavailable" }> {
  const rows = new Map<string, OsvBatchRow>(versions.map((version) => [version, { version, ids: [], incomplete: false }]))
  let pending = versions.map((version) => ({ version, pageToken: "" }))
  for (let round = 0; round < 2 && pending.length > 0; round++) {
    const result = await fetchJson(fetcher, "https://api.osv.dev/v1/querybatch", {
      method: "POST",
      body: JSON.stringify({
        queries: pending.map((item) => ({
          package: { ecosystem: "npm", name },
          version: item.version,
          ...(item.pageToken ? { page_token: item.pageToken } : {}),
        })),
      }),
      maxBytes: 2 * 1024 * 1024,
    })
    if (!result.ok || !result.body || typeof result.body !== "object") return { state: "unavailable" }
    const results = (result.body as { results?: unknown }).results
    if (!Array.isArray(results) || results.length !== pending.length) return { state: "unavailable" }
    const next: Array<{ version: string; pageToken: string }> = []
    for (let index = 0; index < pending.length; index++) {
      const item = pending[index]
      if (!item) return { state: "unavailable" }
      const row = rows.get(item.version)
      const resultRow = results[index]
      if (!row || !resultRow || typeof resultRow !== "object") return { state: "unavailable" }
      const vulns = (resultRow as { vulns?: unknown }).vulns
      if (vulns !== undefined && !Array.isArray(vulns)) return { state: "unavailable" }
      if (Array.isArray(vulns)) {
        for (const vuln of vulns) {
          if (!vuln || typeof vuln !== "object") continue
          const id = (vuln as { id?: unknown }).id
          if (typeof id === "string" && id.length > 0 && !row.ids.includes(id)) row.ids.push(id)
        }
      }
      const token = (resultRow as { next_page_token?: unknown }).next_page_token
      if (typeof token === "string" && token.length > 0) {
        if (round === 0) next.push({ version: item.version, pageToken: token })
        else row.incomplete = true
      }
    }
    pending = next
  }
  return { state: "ok", rows: versions.map((version) => rows.get(version) ?? { version, ids: [], incomplete: false }) }
}

export async function readOsvVuln(fetcher: Fetcher, id: string, packageName: string): Promise<OsvAdvisory | "missing"> {
  const result = await fetchJson(fetcher, `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
    maxBytes: 2 * 1024 * 1024,
  })
  if (!result.ok) return "missing"
  return projectAdvisory(result.body, packageName) ?? "missing"
}

export async function readOsv(fetcher: Fetcher, name: string, version: string): Promise<OsvRead> {
  const result = await fetchJson(fetcher, "https://api.osv.dev/v1/query", {
    method: "POST",
    body: JSON.stringify({ package: { ecosystem: "npm", name }, version }),
    maxBytes: 2 * 1024 * 1024,
  })
  if (!result.ok || !result.body || typeof result.body !== "object") return { state: "unavailable" }
  const vulns = (result.body as { vulns?: unknown }).vulns
  if (vulns === undefined) return { state: "ok", advisories: [] }
  if (!Array.isArray(vulns)) return { state: "unavailable" }
  const advisories: OsvAdvisory[] = []
  for (const vuln of vulns) {
    const projected = projectAdvisory(vuln, name)
    if (projected) advisories.push(projected)
  }
  return { state: "ok", advisories }
}

export function projectAdvisory(vuln: unknown, packageName: string): OsvAdvisory | null {
  if (!vuln || typeof vuln !== "object") return null
  const record = vuln as Record<string, unknown>
  if (typeof record.id !== "string" || record.id.length === 0) return null
  const explicit: string[] = []
  const ranges: OsvRange[] = []
  if (Array.isArray(record.affected)) {
    for (const affected of record.affected) {
      if (!matchesPackage(affected, packageName)) continue
      const block = affected as { ranges?: unknown; versions?: unknown }
      if (Array.isArray(block.versions)) {
        for (const version of block.versions) {
          if (typeof version === "string") explicit.push(version)
        }
      }
      if (Array.isArray(block.ranges)) {
        for (const range of block.ranges) ranges.push(projectRange(range))
      }
    }
  }
  return {
    id: record.id,
    published: typeof record.published === "string" ? record.published : null,
    modified: typeof record.modified === "string" ? record.modified : null,
    summary: clip(typeof record.summary === "string" ? record.summary : "", SUMMARY_CODE_POINTS),
    aliases: stringList(record.aliases),
    ranges,
    explicitVersions: explicit.slice(0, EXPLICIT_VERSION_CAP),
    explicitVersionCount: explicit.length,
  }
}

function matchesPackage(affected: unknown, packageName: string): boolean {
  if (!affected || typeof affected !== "object") return false
  const pkg = (affected as { package?: unknown }).package
  if (!pkg || typeof pkg !== "object") return false
  const ecosystem = (pkg as { ecosystem?: unknown }).ecosystem
  const name = (pkg as { name?: unknown }).name
  return ecosystem === "npm" && name === packageName
}

function projectRange(range: unknown): OsvRange {
  if (!range || typeof range !== "object") return { type: "", events: [] }
  const record = range as { type?: unknown; events?: unknown }
  const events: OsvRange["events"] = []
  if (Array.isArray(record.events)) {
    for (const event of record.events) {
      if (!event || typeof event !== "object") continue
      const item = event as Record<string, unknown>
      const projected: OsvRange["events"][number] = {}
      for (const key of ["introduced", "fixed", "lastAffected", "limit"] as const) {
        if (typeof item[key] === "string") projected[key] = item[key]
      }
      events.push(projected)
    }
  }
  return { type: typeof record.type === "string" ? record.type : "", events }
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === "string")
}

function clip(value: string, maxPoints: number): string {
  const points = Array.from(value)
  if (points.length <= maxPoints) return value
  return points.slice(0, maxPoints).join("")
}
