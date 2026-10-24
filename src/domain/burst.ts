/** Same-package publisher window. Both numbers are the rule the page prints. */
export const BURST_WINDOW_MINUTES = 60
export const BURST_NOTABLE_COUNT = 3
export const BURST_VERSION_CAP = 20

const WINDOW_MS = BURST_WINDOW_MINUTES * 60 * 1000

export type BurstVersion = {
  version: string
  publishedAt: string
  publisher: string | null
}

export type BurstResult = {
  publisher: string
  windowMinutes: number
  notableMinimum: number
  count: number
  versions: string[]
  notable: boolean
}

export function publisherWindow(versions: BurstVersion[], subject: BurstVersion): BurstResult | null {
  if (!subject.publisher) return null
  const subjectMs = Date.parse(subject.publishedAt)
  if (Number.isNaN(subjectMs)) return null

  const inside = versions.filter((version) => {
    if (version.publisher !== subject.publisher) return false
    const ms = Date.parse(version.publishedAt)
    if (Number.isNaN(ms)) return false
    return Math.abs(ms - subjectMs) <= WINDOW_MS
  })
  inside.sort((a, b) => {
    if (a.publishedAt !== b.publishedAt) return a.publishedAt < b.publishedAt ? -1 : 1
    return a.version < b.version ? -1 : a.version > b.version ? 1 : 0
  })

  return {
    publisher: subject.publisher,
    windowMinutes: BURST_WINDOW_MINUTES,
    notableMinimum: BURST_NOTABLE_COUNT,
    count: inside.length,
    versions: inside.slice(0, BURST_VERSION_CAP).map((version) => version.version),
    notable: inside.length >= BURST_NOTABLE_COUNT,
  }
}
