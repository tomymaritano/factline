import { getConnInfo } from "@hono/node-server/conninfo"
import { Hono } from "hono"
import { serveStatic } from "@hono/node-server/serve-static"
import { fileURLToPath } from "node:url"
import { parseSpec } from "./domain/validate.ts"
import { markSvg } from "./page/mark.ts"
import { renderEmpty, renderError, renderResults, renderSuggest, renderTimeline, versionsResultPage } from "./page/render.ts"
import { LIMITS } from "./policy.ts"
import type { AdvisoryScan } from "./domain/advisories.ts"
import type { VersionIndex } from "./readers/catalog.ts"
import type { FactlineService } from "./service.ts"

const publicRoot = fileURLToPath(new URL("../public/", import.meta.url))

const CSP = [
  "default-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self'",
  "script-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "connect-src 'self'",
].join("; ")

export function createApp(getService: () => FactlineService): Hono {
  const app = new Hono()

  app.use("*", async (c, next) => {
    await next()
    c.header("x-content-type-options", "nosniff")
    c.header("referrer-policy", "no-referrer")
  })

  app.on(["POST", "PUT", "PATCH", "DELETE"], "*", (c) => json(c, 405, { error: "method_not_allowed" }))

  app.get("/api/v1/timeline", async (c) => {
    const result = await getService().timeline(c.req.query("name") ?? "", c.req.query("version") ?? "", clientAddress(c))
    if (result.status === 200) return json(c, 200, result.timeline, `public, max-age=${LIMITS.browserMaxAgeSeconds}`)
    return json(c, result.status, { error: result.error })
  })

  app.get("/api/v1/advisories", async (c) => {
    const name = (c.req.query("name") ?? "").trim()
    const result = await getService().versions(name, clientAddress(c))
    if (result.status !== 200) return json(c, result.status, { error: result.error })
    return json(c, 200, advisoryDocument(name, result.index, result.scan), `public, max-age=${LIMITS.browserMaxAgeSeconds}`)
  })

  app.get("/api/v1/recent", (c) => json(c, 200, getService().recent()))

  app.get("/api/v1/suggest", async (c) => {
    const query = (c.req.query("q") ?? "").trim()
    const service = getService()
    const result = await service.suggest(query, clientAddress(c))
    const status = result.status === 200 ? 200 : result.status
    const extra: Record<string, string> = {}
    if (query.length >= 2) extra["HX-Replace-Url"] = `/search?${new URLSearchParams({ q: query }).toString()}`
    return html(c, status, renderSuggest(query, result, service.recent()), true, extra)
  })

  app.get("/search", async (c) => {
    const query = (c.req.query("q") ?? "").trim()
    const spec = parseSpec(query)
    if (spec?.version) return c.redirect(target(spec.name, spec.version), 302)
    if (!query) return c.redirect("/", 302)
    const service = getService()
    const result = await service.suggest(query, clientAddress(c))
    if (!c.req.header("HX-Request") && query.length >= 2) service.rememberSearch(query)
    const status = result.status === 200 ? 200 : result.status
    return html(c, status, renderResults(query, result, service.recent()))
  })

  app.get("/", async (c) => {
    const name = (c.req.query("name") ?? "").trim()
    const version = (c.req.query("version") ?? "").trim()
    const service = getService()
    const recent = () => service.recent()
    if (!name && !version) return html(c, 200, renderEmpty(recent()))
    if (!version) {
      const result = await service.versions(name, clientAddress(c))
      const page = versionsResultPage(name, result, recent())
      return html(c, page.status, page.html)
    }
    const result = await service.timeline(name, version, clientAddress(c))
    if (result.status === 200 && result.timeline.subject.resolvedFromTag) {
      return c.redirect(target(result.timeline.subject.name, result.timeline.subject.version), 302)
    }
    if (result.status === 200) return html(c, 200, renderTimeline(result.timeline, recent()))
    return html(c, result.status, renderError(result.error, recent()))
  })

  app.get("/mark.svg", (c) =>
    c.body(markSvg(), 200, {
      "content-type": "image/svg+xml; charset=utf-8",
      "cache-control": "public, max-age=86400",
    }),
  )

  app.use(
    "/*",
    serveStatic({
      root: publicRoot,
      onFound: (path, c) => {
        c.header("cache-control", path.endsWith(".woff2") ? "public, max-age=86400" : "no-cache")
      },
    }),
  )

  app.notFound((c) => json(c, 404, { error: "not_found" }))
  app.onError((error, c) => {
    console.error(error instanceof Error ? error.message : "request failed")
    return json(c, 500, { error: "internal" })
  })

  return app
}

function html(
  c: { body: (data: string, status: number, headers: Record<string, string>) => Response },
  status: number,
  body: string,
  fragment = false,
  extra: Record<string, string> = {},
): Response {
  return c.body(body, status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    ...(fragment ? {} : { "content-security-policy": CSP }),
    ...extra,
  })
}

function advisoryDocument(name: string, index: VersionIndex, scan: AdvisoryScan) {
  return {
    name,
    distTags: index.distTags,
    versions: index.versions,
    truncated: index.truncated,
    total: index.total,
    observedAt: scan.observedAt,
    osv: scan.osv,
    stale: scan.stale,
    incompleteVersions: scan.incompleteVersions,
    advisories: scan.advisories,
    notices: scan.notices,
  }
}

function json(c: { json: (data: unknown, status: number, headers: Record<string, string>) => Response }, status: number, body: unknown, cache = "no-store"): Response {
  return c.json(body, status, { "cache-control": cache })
}

function target(name: string, version: string): string {
  return `/?${new URLSearchParams({ name, version }).toString()}`
}

function clientAddress(c: { req: { header: (name: string) => string | undefined } }): string {
  if (process.env.VERCEL) {
    const forwarded = c.req.header("x-forwarded-for")
    if (forwarded) return forwarded.split(",")[0]?.trim() || "unknown"
  }
  try {
    return getConnInfo(c as never).remote.address ?? "unknown"
  } catch {
    return "unknown"
  }
}
