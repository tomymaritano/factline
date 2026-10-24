import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { describe, it } from "node:test"
import { startServer } from "../src/http.ts"
import { projectAdvisory } from "../src/readers/osv.ts"
import { projectPackument } from "../src/readers/registry.ts"
import { createService } from "../src/service.ts"
import type { Fetcher } from "../src/readers/http.ts"

const TAIL = "TAIL_MARKER_XYZ"
const DETAILS = "DETAILS_MUST_NOT_LEAK"
const TARBALL = "TARBALL_MUST_NOT_STORE"

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
  it("serves the page and a timeline without innerHTML", async () => {
    const script = readFileSync(new URL("../web/app.js", import.meta.url), "utf8")
    assert.equal(script.includes("innerHTML"), false)
    const server = await startServer({
      port: 0,
      dbPath: ":memory:",
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      fetcher: (url, init) => documents(url, init),
    })
    const page = await fetch(`http://127.0.0.1:${server.port}/`)
    const html = await page.text()
    assert.equal(page.status, 200)
    assert.match(html, /What happened to this version/)
    const timeline = await fetch(`http://127.0.0.1:${server.port}/api/v1/timeline?name=demo&version=1.0.1`)
    assert.equal(timeline.headers.get("cache-control"), "public, max-age=60")
    const body = await timeline.json()
    assert.equal(body.subject.version, "1.0.1")
    assert.equal(Object.hasOwn(body, "score"), false)
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
