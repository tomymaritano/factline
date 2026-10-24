const CVE_ID = /^CVE-\d{4}-\d+$/

export function tiedCves(id: string, aliases: string[]): string[] {
  const found = new Set<string>()
  if (CVE_ID.test(id)) found.add(id)
  for (const alias of aliases) {
    if (CVE_ID.test(alias)) found.add(alias)
  }
  return [...found]
}

export function maliciousAdvisory(id: string): boolean {
  return id.startsWith("MAL-")
}
