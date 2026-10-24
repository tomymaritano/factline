import { validName } from "../domain/validate.ts"
import { fetchJson, type Fetcher } from "./http.ts"

export type CatalogHit = {
  name: string
  description: string
  version: string
}

export type VersionIndex = {
  distTags: Array<{ tag: string; version: string }>
  versions: string[]
  truncated: boolean
  total: number
}

const DESCRIPTION = 180
const VERSION_CAP = 40

export async function readCatalog(fetcher: Fetcher, text: string): Promise<CatalogHit[] | null> {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(text)}&size=8`
  const result = await fetchJson(fetcher, url, { maxBytes: 1_000_000 })
  if (!result.ok || !isRecord(result.body) || !Array.isArray(result.body.objects)) return null
  const hits: CatalogHit[] = []
  for (const item of result.body.objects) {
    if (!isRecord(item) || !isRecord(item.package)) continue
    const name = item.package.name
    const version = item.package.version
    const description = item.package.description
    if (typeof name !== "string" || typeof version !== "string" || !validName(name)) continue
    hits.push({
      name,
      version,
      description: typeof description === "string" ? clip(description, DESCRIPTION) : "",
    })
  }
  return hits
}

export async function readVersionIndex(fetcher: Fetcher, name: string): Promise<VersionIndex | "missing" | null> {
  const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`
  const result = await fetchJson(fetcher, url, {
    maxBytes: 2_000_000,
    accept: "application/vnd.npm.install-v1+json",
  })
  if (!result.ok) return result.status === 404 ? "missing" : null
  if (!isRecord(result.body) || !isRecord(result.body.versions)) return null
  const all = Object.keys(result.body.versions)
  const tags = result.body["dist-tags"]
  const distTags: Array<{ tag: string; version: string }> = []
  if (isRecord(tags)) {
    if (typeof tags.latest === "string") distTags.push({ tag: "latest", version: tags.latest })
    for (const [tag, version] of Object.entries(tags)) {
      if (tag === "latest" || typeof version !== "string") continue
      distTags.push({ tag, version })
    }
  }
  const tail = all.length > VERSION_CAP ? all.slice(-VERSION_CAP) : all
  return {
    distTags,
    versions: [...tail].reverse(),
    truncated: all.length > VERSION_CAP,
    total: all.length,
  }
}

function clip(value: string, max: number): string {
  const chars = Array.from(value)
  return chars.length <= max ? value : chars.slice(0, max).join("")
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}
