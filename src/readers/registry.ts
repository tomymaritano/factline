import { projectCommand } from "../domain/commands.ts"
import { parseRepository } from "../domain/repository.ts"
import { HOOK_NAMES, type HookSet, type PackumentProjection, type VersionRecord } from "../domain/types.ts"
import { LIMITS } from "../policy.ts"
import { fetchJson, type Fetcher } from "./http.ts"

export type RegistryRead =
  | { state: "ok"; projection: Omit<PackumentProjection, "observedAt"> }
  | { state: "not_found" }
  | { state: "unavailable" }

export function registryUrl(name: string): string {
  return `https://registry.npmjs.org/${encodeURIComponent(name)}`
}

export async function readRegistry(fetcher: Fetcher, name: string): Promise<RegistryRead> {
  const result = await fetchJson(fetcher, registryUrl(name), { maxBytes: LIMITS.packumentBytes })
  if (!result.ok) {
    if (result.status === 404) return { state: "not_found" }
    return { state: "unavailable" }
  }
  const projected = projectPackument(result.body)
  if (!projected) return { state: "unavailable" }
  return { state: "ok", projection: projected }
}

export function projectPackument(body: unknown): Omit<PackumentProjection, "observedAt"> | null {
  if (!body || typeof body !== "object") return null
  const record = body as Record<string, unknown>
  const versions = record.versions
  const time = record.time
  if (!versions || typeof versions !== "object" || !time || typeof time !== "object") return null

  const distTags: Record<string, string> = {}
  const tags = record["dist-tags"]
  if (tags && typeof tags === "object") {
    for (const [tag, version] of Object.entries(tags)) {
      if (typeof version === "string") distTags[tag] = version
    }
  }

  const projected: VersionRecord[] = []
  for (const [version, document] of Object.entries(versions)) {
    if (!document || typeof document !== "object") continue
    const publishedAt = (time as Record<string, unknown>)[version]
    if (typeof publishedAt !== "string" || Number.isNaN(Date.parse(publishedAt))) continue
    const doc = document as Record<string, unknown>
    const npmUser = doc._npmUser
    let publisher: string | null = null
    if (npmUser && typeof npmUser === "object" && typeof (npmUser as { name?: unknown }).name === "string") {
      const name = (npmUser as { name: string }).name
      publisher = name.length > 0 ? name : null
    }
    projected.push({
      version,
      publishedAt,
      publisher,
      hooks: projectHooks(doc.scripts),
      repository: parseRepository(doc.repository),
    })
  }

  return { distTags, versions: projected }
}

function projectHooks(scripts: unknown): HookSet {
  const source = scripts && typeof scripts === "object" ? (scripts as Record<string, unknown>) : {}
  return {
    preinstall: projectCommand(source[HOOK_NAMES[0]]),
    install: projectCommand(source[HOOK_NAMES[1]]),
    postinstall: projectCommand(source[HOOK_NAMES[2]]),
    prepare: projectCommand(source[HOOK_NAMES[3]]),
  }
}
