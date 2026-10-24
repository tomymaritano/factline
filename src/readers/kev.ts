import type { KevEntry } from "../domain/types.ts"
import { LIMITS } from "../policy.ts"
import { fetchJson, type Fetcher } from "./http.ts"

export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

export type KevRead =
  | { state: "ok"; catalogVersion: string | null; entries: KevEntry[] }
  | { state: "unavailable" }

export async function readKev(fetcher: Fetcher): Promise<KevRead> {
  const result = await fetchJson(fetcher, KEV_URL, { maxBytes: LIMITS.documentBytes })
  if (!result.ok || !result.body || typeof result.body !== "object") return { state: "unavailable" }
  const record = result.body as { catalogVersion?: unknown; vulnerabilities?: unknown }
  if (!Array.isArray(record.vulnerabilities)) return { state: "unavailable" }
  const entries: KevEntry[] = []
  for (const item of record.vulnerabilities) {
    const entry = projectEntry(item)
    if (entry) entries.push(entry)
  }
  return {
    state: "ok",
    catalogVersion: typeof record.catalogVersion === "string" ? record.catalogVersion : null,
    entries,
  }
}

function projectEntry(item: unknown): KevEntry | null {
  if (!item || typeof item !== "object") return null
  const record = item as Record<string, unknown>
  if (typeof record.cveID !== "string") return null
  if (typeof record.dateAdded !== "string" || typeof record.dueDate !== "string") return null
  return {
    cveId: record.cveID,
    vulnerabilityName: typeof record.vulnerabilityName === "string" ? record.vulnerabilityName : "",
    dateAdded: record.dateAdded,
    dueDate: record.dueDate,
    requiredAction: typeof record.requiredAction === "string" ? record.requiredAction : "",
  }
}
