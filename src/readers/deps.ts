import { dependentsUrl } from "../domain/assemble.ts"
import type { DependentsProjection } from "../domain/types.ts"
import { fetchJson, type Fetcher } from "./http.ts"

export type DepsRead =
  | { state: "ok"; counts: Omit<DependentsProjection, "observedAt"> }
  | { state: "unavailable" }

export async function readDependents(fetcher: Fetcher, name: string, version: string): Promise<DepsRead> {
  const result = await fetchJson(fetcher, dependentsUrl(name, version), { maxBytes: 64 * 1024 })
  if (!result.ok || !result.body || typeof result.body !== "object") return { state: "unavailable" }
  const record = result.body as Record<string, unknown>
  const dependentCount = record.dependentCount
  const directDependentCount = record.directDependentCount
  const indirectDependentCount = record.indirectDependentCount
  if (!isCount(dependentCount) || !isCount(directDependentCount) || !isCount(indirectDependentCount)) {
    return { state: "unavailable" }
  }
  return {
    state: "ok",
    counts: { dependentCount, directDependentCount, indirectDependentCount },
  }
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
}
