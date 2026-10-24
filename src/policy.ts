export const TTL_MS = {
  packument: 15 * 60 * 1000,
  osv: 60 * 60 * 1000,
  kev: 12 * 60 * 60 * 1000,
  kevUsable: 7 * 24 * 60 * 60 * 1000,
  dependents: 24 * 60 * 60 * 1000,
  scorecard: 24 * 60 * 60 * 1000,
} as const

export const LIMITS = {
  missesPerMinute: 30,
  searchesPerMinute: 60,
  maxInFlight: 8,
  packumentBytes: 20 * 1024 * 1024,
  documentBytes: 20 * 1024 * 1024,
  timeoutMs: 10_000,
  browserMaxAgeSeconds: 60,
} as const

export function isFresh(observedAt: string, nowMs: number, ttlMs: number): boolean {
  const observed = Date.parse(observedAt)
  if (Number.isNaN(observed)) return false
  return nowMs - observed < ttlMs
}
