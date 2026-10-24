const NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/
const DIST_TAG = /^[A-Za-z0-9._-]{1,32}$/

export function validName(name: string): boolean {
  return name.length > 0 && name.length <= 214 && NAME.test(name)
}

export function classifyVersion(version: string): "semver" | "tag" | "invalid" {
  if (version.length === 0 || version.length > 128) return "invalid"
  if (/[\^~*><=\s|]/.test(version)) return "invalid"
  if (/(^|\.)x($|\.)/i.test(version)) return "invalid"
  if (SEMVER.test(version)) return "semver"
  if (/^\d+(\.\d+){0,2}$/.test(version)) return "invalid"
  if (DIST_TAG.test(version)) return "tag"
  return "invalid"
}
