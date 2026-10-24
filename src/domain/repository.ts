import type { RepoParse } from "./types.ts"

const SAFE_SEGMENT = /^[A-Za-z0-9_.-]+$/

export function parseRepository(field: unknown): RepoParse {
  const raw = repositoryString(field)
  if (raw === null || raw === "") return { ok: false, reason: "no_repository" }

  let text = raw.trim()
  if (text.startsWith("git+")) text = text.slice(4)
  const hash = text.indexOf("#")
  if (hash >= 0) text = text.slice(0, hash)
  if (text.endsWith(".git")) text = text.slice(0, -4)
  if (text === "") return { ok: false, reason: "no_repository" }

  const short = /^github:([^/]+)\/([^/]+)$/.exec(text)
  const scp = /^(?:ssh:\/\/)?git@github\.com:([^/]+)\/([^/]+)$/.exec(text)
  if (short) return finish(short[1] ?? "", short[2] ?? "")
  if (scp) return finish(scp[1] ?? "", scp[2] ?? "")

  let url: URL
  try {
    url = new URL(text)
  } catch {
    return { ok: false, reason: "not_github" }
  }
  const host = url.hostname.toLowerCase()
  if (host !== "github.com" && host !== "www.github.com") return { ok: false, reason: "not_github" }
  const parts = url.pathname.split("/").filter((part) => part.length > 0)
  const owner = parts[0] ?? ""
  let repo = parts[1] ?? ""
  if (repo.endsWith(".git")) repo = repo.slice(0, -4)
  if (!owner || !repo) return { ok: false, reason: "not_github" }
  return finish(owner, repo)
}

function finish(owner: string, repo: string): RepoParse {
  if (!SAFE_SEGMENT.test(owner) || !SAFE_SEGMENT.test(repo)) return { ok: false, reason: "not_github" }
  return { ok: true, repo: `github.com/${owner}/${repo}` }
}

function repositoryString(field: unknown): string | null {
  if (typeof field === "string") return field
  if (field && typeof field === "object" && "url" in field) {
    const url = (field as { url: unknown }).url
    if (typeof url === "string") return url
  }
  return null
}
