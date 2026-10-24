import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { DatabaseSync } from "node:sqlite"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { startServer } from "../src/http.ts"
import { projectAdvisory } from "../src/readers/osv.ts"
import { projectPackument } from "../src/readers/registry.ts"
import { createService } from "../src/service.ts"
import { openStore } from "../src/store.ts"
import type { Fetcher } from "../src/readers/http.ts"

const TAIL = "TAIL_MARKER_XYZ"
const DETAILS = "DETAILS_MUST_NOT_LEAK"
const TARBALL = "TARBALL_MUST_NOT_STORE"

describe("lookup history", () => {
  it("collapses old duplicate version rows and keeps distinct searches", () => {
    const path = join(mkdtempSync(join(tmpdir(), "factline-")), "old.db")
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE lookups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      looked_up_at TEXT NOT NULL
    )`)
    const insert = db.prepare("INSERT INTO lookups (name, version, looked_up_at) VALUES (?, ?, ?)")
    insert.run("ms", "2.1.3", "2026-01-01T00:00:00.000Z")
    insert.run("ms", "2.1.3", "2026-01-02T00:00:00.000Z")
    db.close()

    const store = openStore(path)
    store.addLookup({ kind: "search", name: "", version: "", query: "lodash", lookedUpAt: "2026-01-03T00:00:00.000Z" })
    for (let index = 0; index < 12; index += 1) {
      store.addLookup({
        kind: "search",
        name: "",
        version: "",
        query: `q${index}`,
        lookedUpAt: "2026-01-04T00:00:00.000Z",
      })
    }
    const rows = store.recentLookups(10)
    assert.equal(rows.length, 10)
    assert.equal(rows[0]?.query, "q11")
    assert.equal(rows.some((row) => row.query === "q0" || row.query === "lodash" || row.version === "2.1.3"), false)
    store.addLookup({ kind: "version", name: "ms", version: "2.1.3", query: "", lookedUpAt: "2026-01-05T00:00:00.000Z" })
    store.addLookup({ kind: "version", name: "ms", version: "2.1.3", query: "", lookedUpAt: "2026-01-06T00:00:00.000Z" })
    const again = store.recentLookups(10)
    assert.equal(again.filter((row) => row.kind === "version" && row.version === "2.1.3").length, 1)
    assert.equal(again[0]?.kind, "version")
    store.close()
  })
})

describe("readers", () => {
  it("drops tarball URLs and the tail of an install script", () => {
    const command = `node ${"A".repeat(155)}${TAIL}`
    const projected = projectPackument(packumentBody(command))
    assert.ok(projected)
    const encoded = JSON.stringify(projected)
    assert.equal(encoded.includes(TAIL), false)
    assert.equal(encoded.includes(TARBALL), false)
    const hook = projected.versions.find((version) => version.version === "1.0.1")?.hooks.postinstall
    assert.equal(hook?.truncated, true)
    assert.equal(Array.from(hook?.prefix ?? "").length, 160)
  })

  it("drops advisory details and affected blocks for other packages", () => {
    const advisory = projectAdvisory(
      {
        id: "GHSA-test",
        summary: "Short",
        details: DETAILS,
        published: "2024-02-01T00:00:00.000Z",
        aliases: ["CVE-2024-1111"],
        affected: [
          {
            package: { ecosystem: "npm", name: "demo" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
            versions: ["1.0.1"],
          },
          { package: { ecosystem: "npm", name: "other" }, versions: ["9.9.9"] },
        ],
      },
      "demo",
    )
    assert.ok(advisory)
    const encoded = JSON.stringify(advisory)
    assert.equal(encoded.includes(DETAILS), false)
    assert.equal(encoded.includes("9.9.9"), false)
    assert.deepEqual(advisory.explicitVersions, ["1.0.1"])
  })
})

describe("timeline service", () => {
  it("builds a timeline from public documents and then serves it from cache", async () => {
    let calls = 0
    const fetcher: Fetcher = async (url, init) => {
      calls += 1
      return documents(url, init)
    }
    const service = createService({ dbPath: ":memory:", fetcher, now: () => new Date("2026-01-01T00:00:00.000Z") })
    const first = await service.timeline("demo", "1.0.1", "10.0.0.1")
    assert.equal(first.status, 200)
    if (first.status !== 200) return
    const body = JSON.stringify(first.timeline)
    assert.equal(body.includes(TAIL), false)
    assert.equal(body.includes(DETAILS), false)
    assert.equal(body.includes(TARBALL), false)
    assert.equal(first.timeline.events.some((event) => event.kind === "kev"), true)
    assert.equal(first.timeline.readings.some((reading) => reading.kind === "scorecard"), true)
    const callsAfterFirst = calls
    const second = await service.timeline("demo", "1.0.1", "10.0.0.1")
    assert.equal(second.status, 200)
    assert.equal(calls, callsAfterFirst)
    assert.equal(service.recent()[0]?.version, "1.0.1")
    assert.equal(service.recent()[0]?.kind, "version")
    assert.equal(service.recent().length, 1)
    service.close()
  })

  it("suppresses KEV when OSV does not answer", async () => {
    const service = createService({
      dbPath: ":memory:",
      fetcher: async (url, init) => {
        if (url.includes("osv.dev")) return json({ error: "down" }, 503)
        return documents(url, init)
      },
      now: () => new Date("2026-01-01T00:00:00.000Z"),
    })
    const result = await service.timeline("demo", "1.0.1", "10.0.0.2")
    assert.equal(result.status, 200)
    if (result.status !== 200) return
    assert.equal(result.timeline.events.some((event) => event.kind === "kev"), false)
    assert.equal(result.timeline.notices.some((notice) => notice.code === "osv_unavailable"), true)
    service.close()
  })

  it("resolves a dist-tag, rejects a range, and reports an unknown package", async () => {
    const service = createService({
      dbPath: ":memory:",
      fetcher: async (url, init) => {
        if (url.endsWith("missing")) return json({}, 404)
        return documents(url, init)
      },
      now: () => new Date("2026-01-01T00:00:00.000Z"),
    })
    const tagged = await service.timeline("demo", "latest", "10.0.0.3")
    assert.equal(tagged.status, 200)
    if (tagged.status === 200) {
      assert.equal(tagged.timeline.subject.version, "1.0.2")
      assert.equal(tagged.timeline.subject.resolvedFromTag, "latest")
    }
    assert.deepEqual(await service.timeline("demo", "^1.0.0", "10.0.0.3"), {
      status: 400,
      error: "invalid_version",
    })
    assert.deepEqual(await service.timeline("missing", "1.0.0", "10.0.0.3"), { status: 404, error: "not_found" })
    service.close()
  })

  it("stops cold lookups after 30 in a minute", async () => {
    const service = createService({
      dbPath: ":memory:",
      fetcher: async () => json({}, 404),
      now: () => new Date("2026-01-01T00:00:00.000Z"),
    })
    for (let index = 0; index < 30; index += 1) {
      const result = await service.timeline(`pkg${index}`, "1.0.0", "10.9.9.9")
      assert.equal(result.status, 404)
    }
    assert.deepEqual(await service.timeline("pkg30", "1.0.0", "10.9.9.9"), { status: 429, error: "rate_limited" })
    service.close()
  })

  it("forgets a version that the next packument no longer lists", async () => {
    let hide = false
    let now = new Date("2026-01-01T00:00:00.000Z")
    const service = createService({
      dbPath: ":memory:",
      now: () => now,
      fetcher: async (url, init) => {
        if (url.startsWith("https://registry.npmjs.org/") && hide) {
          const body = packumentBody(`node ${"A".repeat(155)}${TAIL}`)
          delete body.versions["1.0.0"]
          delete body.time["1.0.0"]
          return json(body)
        }
        return documents(url, init)
      },
    })
    assert.equal((await service.timeline("demo", "1.0.0", "10.0.0.4")).status, 200)
    hide = true
    now = new Date("2026-01-01T00:20:00.000Z")
    assert.deepEqual(await service.timeline("demo", "1.0.0", "10.0.0.4"), { status: 404, error: "not_found" })
    service.close()
  })
})

describe("http", () => {
  it("serves the branded page, the registry search, and a timeline", async () => {
    const seen: string[] = []
    const server = await startServer({
      port: 0,
      dbPath: ":memory:",
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      fetcher: (url, init) => {
        seen.push(url)
        if (url.startsWith("https://registry.npmjs.org/-/v1/search")) {
          return Promise.resolve(
            json({
              objects: [
                {
                  score: { final: 0.99 },
                  package: { name: "not-demo", version: "9.0.0", description: "other" },
                },
                {
                  score: { final: 0.1 },
                  package: { name: "demo", version: "1.0.1", description: `safe <script>${"x".repeat(5)}` },
                },
              ],
            }),
          )
        }
        return documents(url, init)
      },
    })
    const page = await fetch(`http://127.0.0.1:${server.port}/`)
    const html = await page.text()
    assert.equal(page.status, 200)
    assert.match(html, /Everything public that happened to one npm version/)
    assert.equal(html.includes("fact-statement"), false)
    assert.match(html, /Search the registry/)
    const color = await fetch(`http://127.0.0.1:${server.port}/color.css`)
    const css = await color.text()
    assert.match(css, /#f1f1ec/)
    assert.match(css, /#1b1d1f/)
    assert.match(css, /#5c6166/)
    assert.match(css, /#2b4c9b/)
    assert.match(css, /#b3321f/)
    const suggest = await fetch(`http://127.0.0.1:${server.port}/api/v1/suggest?q=demo`)
    const fragment = await suggest.text()
    assert.match(fragment, /demo/)
    assert.match(fragment, /&lt;script&gt;/)
    assert.equal(fragment.includes("0.99"), false)
    const demoAt = fragment.indexOf('href="/?name=demo"')
    const otherAt = fragment.indexOf('href="/?name=not-demo"')
    assert.ok(demoAt !== -1 && otherAt > demoAt)
    assert.equal(seen.some((url) => url.includes("osv.dev")), false)
    const timeline = await fetch(`http://127.0.0.1:${server.port}/api/v1/timeline?name=demo&version=1.0.1`)
    assert.equal(timeline.headers.get("cache-control"), "public, max-age=60")
    const body = await timeline.json()
    assert.equal(body.subject.version, "1.0.1")
    assert.equal(Object.hasOwn(body, "score"), false)
    const painted = await fetch(`http://127.0.0.1:${server.port}/?name=demo&version=1.0.1`)
    const paintedHtml = await painted.text()
    assert.match(paintedHtml, /fact-statement/)
    assert.match(paintedHtml, /Publisher ada/)
    await server.close()
  })

  it("keeps a refreshed search and ignores suggestion keystrokes", async () => {
    const server = await startServer({
      port: 0,
      dbPath: ":memory:",
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      fetcher: (url) => {
        if (url.startsWith("https://registry.npmjs.org/-/v1/search")) {
          return Promise.resolve(json({ objects: [{ package: { name: "demo", version: "1.0.1", description: "d" } }] }))
        }
        if (url.startsWith("https://registry.npmjs.org/")) return Promise.resolve(json(packumentBody("node ok")))
        return Promise.resolve(json({ error: "down" }, 500))
      },
    })
    const partial = await fetch(`http://127.0.0.1:${server.port}/api/v1/suggest?q=de`, {
      headers: { "HX-Request": "true" },
    })
    assert.equal(partial.headers.get("hx-replace-url"), "/search?q=de")
    const typed = await fetch(`http://127.0.0.1:${server.port}/api/v1/suggest?q=d`)
    assert.equal(typed.headers.get("hx-replace-url"), null)
    const before = await (await fetch(`http://127.0.0.1:${server.port}/`)).text()
    assert.equal(before.includes("/search?q=de"), false)
    assert.match(before, /No searches yet from this server/)

    const search = await fetch(`http://127.0.0.1:${server.port}/search?q=demo`)
    assert.equal(search.status, 200)
    const searchHtml = await search.text()
    assert.match(searchHtml, /value="demo"/)
    assert.match(searchHtml, /href="\/search\?q=demo"/)
    await fetch(`http://127.0.0.1:${server.port}/search?q=demo`)
    const packagePage = await fetch(`http://127.0.0.1:${server.port}/?name=demo`)
    assert.equal(packagePage.status, 200)

    const rows = (await (await fetch(`http://127.0.0.1:${server.port}/api/v1/recent`)).json()) as Array<{
      kind: string
      name: string
      query: string
    }>
    assert.equal(rows.filter((row) => row.kind === "search" && row.query === "demo").length, 1)
    assert.equal(rows.filter((row) => row.kind === "package" && row.name === "demo").length, 1)
    assert.equal(rows.some((row) => row.query === "de"), false)
    const home = await (await fetch(`http://127.0.0.1:${server.port}/`)).text()
    assert.match(home, /Recent searches on this server/)
    assert.match(home, /href="\/search\?q=demo"/)
    assert.match(home, /href="\/\?name=demo"/)
    await server.close()
  })

  it("lists advisories for the versions on the package page", async () => {
    const seen: string[] = []
    const server = await startServer({
      port: 0,
      dbPath: ":memory:",
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      fetcher: (url, init) => {
        seen.push(url)
        if (url.endsWith("/v1/querybatch")) {
          const body = JSON.parse(String(init?.body)) as { queries: Array<{ version: string }> }
          return Promise.resolve(
            json({
              results: body.queries.map((query) =>
                query.version === "1.0.1" ? { vulns: [{ id: "GHSA-test" }] } : { vulns: [] },
              ),
            }),
          )
        }
        if (url.endsWith("/v1/vulns/GHSA-test")) {
          return Promise.resolve(
            json({
              id: "GHSA-test",
              summary: "Example",
              details: DETAILS,
              aliases: ["CVE-2024-1111"],
              affected: [{ package: { ecosystem: "npm", name: "demo" }, versions: ["1.0.1"] }],
            }),
          )
        }
        if (url.startsWith("https://registry.npmjs.org/")) return Promise.resolve(json(packumentBody("node ok.js")))
        return documents(url, init)
      },
    })
    const page = await fetch(`http://127.0.0.1:${server.port}/?name=demo`)
    const html = await page.text()
    assert.equal(page.status, 200)
    assert.ok(html.indexOf(">Advisories<") < html.indexOf(">Dist-tags<"))
    assert.match(html, /Example/)
    assert.match(html, /Demo/)
    assert.match(html, /version=1\.0\.1">1\.0\.1<\/a><span class="advisory-ids paste fact-statement">GHSA-test<\/span>/)
    assert.match(html, /version=1\.0\.2">1\.0\.2<\/a><\/li>/)
    assert.equal(html.includes(DETAILS), false)
    assert.equal(html.includes("Everything public that happened"), false)
    const doc = await fetch(`http://127.0.0.1:${server.port}/api/v1/advisories?name=demo`)
    assert.equal(doc.headers.get("cache-control"), "public, max-age=60")
    const body = await doc.json()
    assert.equal(body.osv, "ok")
    assert.equal(body.advisories[0].id, "GHSA-test")
    assert.equal(body.advisories[0].summary, "Example")
    assert.deepEqual(body.advisories[0].versions, ["1.0.1"])
    assert.equal(body.advisories[0].kev[0].vulnerabilityName, "Demo")
    assert.equal(body.advisories[0].kev[0].dateAdded, "2024-04-01")
    assert.equal(Object.hasOwn(body, "score"), false)
    assert.equal(Object.hasOwn(body, "safe"), false)
    assert.equal(JSON.stringify(body).includes("ranges"), false)
    assert.equal(JSON.stringify(body).includes(DETAILS), false)
    assert.equal(seen.filter((url) => url.endsWith("/v1/querybatch")).length, 1)
    assert.equal(seen.filter((url) => url.includes("/v1/vulns/")).length, 1)
    assert.equal(seen.filter((url) => url.endsWith("/v1/query")).length, 0)
    assert.equal(seen.some((url) => url.includes("deps.dev")), false)
    assert.equal(seen.some((url) => url.includes("scorecard.dev")), false)
    assert.equal(seen.some((url) => url.includes("known_exploited")), true)
    const rejected = await fetch(`http://127.0.0.1:${server.port}/api/v1/advisories?name=NotValid`)
    assert.equal(rejected.status, 400)
    await server.close()
  })

  it("says when OSV returned no advisories for the scan", async () => {
    const seen: string[] = []
    const server = await startServer({
      port: 0,
      dbPath: ":memory:",
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      fetcher: (url, init) => {
        seen.push(url)
        if (url.endsWith("/v1/querybatch")) {
          const body = JSON.parse(String(init?.body)) as { queries: unknown[] }
          return Promise.resolve(json({ results: body.queries.map(() => ({ vulns: [] })) }))
        }
        if (url.startsWith("https://registry.npmjs.org/")) return Promise.resolve(json(packumentBody("node ok.js")))
        return Promise.resolve(json({ error: "unexpected" }, 500))
      },
    })
    const page = await fetch(`http://127.0.0.1:${server.port}/?name=demo`)
    const html = await page.text()
    assert.equal(page.status, 200)
    assert.match(html, /OSV returned no advisories for the versions in this scan/)
    assert.match(html, />Dist-tags</)
    assert.equal(html.includes("fact-statement"), false)
    assert.equal(seen.some((url) => url.includes("known_exploited")), false)
    await server.close()
  })

  it("keeps the version list when OSV does not answer", async () => {
    const seen: string[] = []
    const server = await startServer({
      port: 0,
      dbPath: ":memory:",
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      fetcher: (url) => {
        seen.push(url)
        if (url.includes("osv.dev")) return Promise.resolve(json({ error: "down" }, 500))
        if (url.startsWith("https://registry.npmjs.org/")) return Promise.resolve(json(packumentBody("node ok.js")))
        return Promise.resolve(json({ error: "unexpected" }, 500))
      },
    })
    const page = await fetch(`http://127.0.0.1:${server.port}/?name=demo`)
    const html = await page.text()
    assert.equal(page.status, 200)
    assert.match(html, /OSV did not answer\. No advisory list\./)
    assert.equal(html.includes("OSV returned no advisories"), false)
    assert.match(html, /1\.0\.2/)
    assert.equal(html.includes("fact-statement"), false)
    assert.equal(seen.some((url) => url.includes("known_exploited")), false)
    assert.equal(seen.some((url) => url.includes("/v1/vulns/")), false)
    await server.close()
  })
})

function documents(url: string, init?: RequestInit): Promise<Response> {
  if (url.startsWith("https://registry.npmjs.org/")) return Promise.resolve(json(packumentBody(`node ${"A".repeat(155)}${TAIL}`)))
  if (url === "https://api.osv.dev/v1/query") {
    assert.equal(init?.method, "POST")
    return Promise.resolve(
      json({
        vulns: [
          {
            id: "GHSA-test",
            summary: "Example",
            details: DETAILS,
            published: "2024-02-01T00:00:00.000Z",
            aliases: ["CVE-2024-1111"],
            affected: [
              {
                package: { ecosystem: "npm", name: "demo" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.0.0" }] }],
              },
            ],
          },
        ],
      }),
    )
  }
  if (url.includes("known_exploited_vulnerabilities.json")) {
    return Promise.resolve(
      json({
        catalogVersion: "2026.01.01",
        vulnerabilities: [
          {
            cveID: "CVE-2024-1111",
            vulnerabilityName: "Demo",
            dateAdded: "2024-04-01",
            dueDate: "2024-04-22",
            requiredAction: "Apply updates.",
          },
        ],
      }),
    )
  }
  if (url.includes("api.deps.dev")) {
    return Promise.resolve(json({ dependentCount: 4, directDependentCount: 1, indirectDependentCount: 3 }))
  }
  if (url.startsWith("https://api.scorecard.dev/projects/")) {
    return Promise.resolve(
      json({
        date: "2025-01-02T03:04:05Z",
        score: 6.5,
        repo: { name: "github.com/ada/demo", commit: "abc" },
        scorecard: { version: "v5" },
        checks: [{ name: "Maintained", score: -1, reason: "no data" }],
      }),
    )
  }
  return Promise.resolve(json({ error: "unexpected" }, 500))
}

function packumentBody(command: string): {
  "dist-tags": Record<string, string>
  time: Record<string, string>
  versions: Record<string, unknown>
} {
  const version = (name: string, scripts: Record<string, string>) => ({
    version: name,
    _npmUser: { name: "ada" },
    repository: { type: "git", url: "git+https://github.com/ada/demo.git" },
    scripts,
    dist: { tarball: `https://registry.npmjs.org/demo/-/demo-${name}.tgz`, integrity: TARBALL },
  })
  return {
    "dist-tags": { latest: "1.0.2" },
    time: {
      created: "2020-01-01T00:00:00.000Z",
      modified: "2024-01-01T00:50:00.000Z",
      "1.0.0": "2024-01-01T00:00:00.000Z",
      "1.0.1": "2024-01-01T00:20:00.000Z",
      "1.0.2": "2024-01-01T00:50:00.000Z",
    },
    versions: {
      "1.0.0": version("1.0.0", { postinstall: "node good.js" }),
      "1.0.1": version("1.0.1", { postinstall: command }),
      "1.0.2": version("1.0.2", { postinstall: command }),
    },
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}
