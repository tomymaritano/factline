import type { ScorecardCheck, ScorecardProjection } from "../domain/types.ts"
import { fetchJson, type Fetcher } from "./http.ts"

const REASON_CODE_POINTS = 180

export type ScorecardRead =
  | { state: "present"; report: Omit<ScorecardProjection, "observedAt" | "repo"> }
  | { state: "absent" }
  | { state: "unavailable" }

export function scorecardApiUrl(repo: string): string {
  return `https://api.scorecard.dev/projects/${repo}`
}

export async function readScorecard(fetcher: Fetcher, repo: string): Promise<ScorecardRead> {
  const result = await fetchJson(fetcher, scorecardApiUrl(repo), { maxBytes: 1024 * 1024 })
  if (!result.ok) {
    if (result.status === 404) return { state: "absent" }
    return { state: "unavailable" }
  }
  const report = projectReport(result.body)
  if (!report) return { state: "unavailable" }
  return { state: "present", report }
}

export function projectReport(body: unknown): Omit<ScorecardProjection, "observedAt" | "repo"> | null {
  if (!body || typeof body !== "object") return null
  const record = body as Record<string, unknown>
  if (typeof record.date !== "string" || typeof record.score !== "number" || !Number.isFinite(record.score)) {
    return null
  }
  const repo = record.repo
  const scorecard = record.scorecard
  let commit: string | null = null
  if (repo && typeof repo === "object" && typeof (repo as { commit?: unknown }).commit === "string") {
    commit = (repo as { commit: string }).commit
  }
  let scorecardVersion: string | null = null
  if (scorecard && typeof scorecard === "object" && typeof (scorecard as { version?: unknown }).version === "string") {
    scorecardVersion = (scorecard as { version: string }).version
  }
  const checks: ScorecardCheck[] = []
  if (Array.isArray(record.checks)) {
    for (const check of record.checks) {
      if (!check || typeof check !== "object") continue
      const item = check as Record<string, unknown>
      if (typeof item.name !== "string" || typeof item.score !== "number") continue
      checks.push({
        name: item.name,
        score: item.score,
        reason: clip(typeof item.reason === "string" ? item.reason : "", REASON_CODE_POINTS),
      })
    }
  }
  return {
    reportedAt: record.date,
    score: record.score,
    commit,
    scorecardVersion,
    checks,
  }
}

function clip(value: string, maxPoints: number): string {
  const points = Array.from(value)
  if (points.length <= maxPoints) return value
  return points.slice(0, maxPoints).join("")
}
