import { LIMITS } from "../policy.ts"

export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>

export type JsonResult =
  | { ok: true; status: number; body: unknown }
  | { ok: false; status: number | null; reason: "http" | "timeout" | "too_large" | "bad_json" | "not_json" }

export async function fetchJson(
  fetcher: Fetcher,
  url: string,
  init: { method?: string; body?: string; maxBytes: number; accept?: string },
): Promise<JsonResult> {
  const timeout = AbortSignal.timeout(LIMITS.timeoutMs)
  let response: Response
  try {
    response = await fetcher(url, {
      method: init.method ?? "GET",
      body: init.body,
      redirect: "follow",
      signal: timeout,
      headers: {
        accept: init.accept ?? "application/json",
        "user-agent": "factline",
        ...(init.body ? { "content-type": "application/json" } : {}),
      },
    })
  } catch {
    return { ok: false, status: null, reason: "timeout" }
  }

  if (response.status === 404) {
    await response.body?.cancel()
    return { ok: false, status: 404, reason: "http" }
  }
  if (!response.ok) {
    await response.body?.cancel()
    return { ok: false, status: response.status, reason: "http" }
  }

  const type = response.headers.get("content-type") ?? ""
  if (!type.includes("json")) return { ok: false, status: response.status, reason: "not_json" }

  const declared = Number(response.headers.get("content-length") ?? "0")
  if (Number.isFinite(declared) && declared > init.maxBytes) {
    await response.body?.cancel()
    return { ok: false, status: response.status, reason: "too_large" }
  }

  const bytes = await readCapped(response, init.maxBytes)
  if (bytes === null) return { ok: false, status: response.status, reason: "too_large" }

  try {
    return { ok: true, status: response.status, body: JSON.parse(new TextDecoder().decode(bytes)) }
  } catch {
    return { ok: false, status: response.status, reason: "bad_json" }
  }
}

async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array | null> {
  const reader = response.body?.getReader()
  if (!reader) {
    const buffer = new Uint8Array(await response.arrayBuffer())
    return buffer.byteLength > maxBytes ? null : buffer
  }
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const step = await reader.read()
    if (step.done) break
    total += step.value.byteLength
    if (total > maxBytes) {
      await reader.cancel()
      return null
    }
    chunks.push(step.value)
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}
