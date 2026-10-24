export type TimedVersion = {
  version: string
  publishedAt: string
}

/**
 * The other still-present version with the greatest publishedAt strictly
 * earlier than the subject. Equal timestamps break by ascending version
 * string, not by semver precedence.
 */
export function selectPredecessor(versions: TimedVersion[], subject: TimedVersion): TimedVersion | null {
  const earlier = versions.filter(
    (version) => version.version !== subject.version && version.publishedAt < subject.publishedAt,
  )
  earlier.sort((a, b) => {
    if (a.publishedAt !== b.publishedAt) return a.publishedAt < b.publishedAt ? 1 : -1
    return a.version < b.version ? -1 : a.version > b.version ? 1 : 0
  })
  return earlier[0] ?? null
}
