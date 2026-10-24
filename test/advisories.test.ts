import assert from "node:assert/strict"
import { describe, it } from "node:test"
import {
  SCAN_DOWN,
  SCAN_EMPTY,
  SCAN_KEV_DOWN,
  SCAN_OMITTED,
  SCAN_STALE,
  joinAdvisoryScan,
  markScanStale,
  scannedVersions,
} from "../src/domain/advisories.ts"
import type { OsvAdvisory } from "../src/domain/types.ts"
import { MissBudget, SingleFlight, UpstreamGate } from "../src/limit.ts"
import { TTL_MS } from "../src/policy.ts"
import type { Fetcher } from "../src/readers/http.ts"
import { readOsvBatch } from "../src/readers/osv.ts"
import { createScanner } from "../src/scan.ts"

function advisory(id: string, aliases: string[] = [], summary = "Example"): OsvAdvisory {
  return {
    id,
    published: "2024-02-01T00:00:00.000Z",
    modified: null,
    summary,
    aliases,
    ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
    explicitVersions: ["1.0.0"],
    explicitVersionCount: 1,
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

describe("advisory join", () => {
  it("names the scanned versions and joins KEV only for a CVE on that advisory", () => {
    const scan = joinAdvisoryScan({
      observedAt: "2026-01-01T00:00:00.000Z",
      rows: [
        { version: "2.0.0", ids: ["GHSA-b", "GHSA-a"], incomplete: false },
        { version: "1.0.0", ids: ["GHSA-a"], incomplete: false },
      ],
      records: new Map([
        ["GHSA-a", advisory("GHSA-a", ["CVE-2024-1111"], "First")],
        ["GHSA-b", advisory("GHSA-b", [], "Second")],
      ]),
      kev: {
        state: "ok",
        observedAt: "2026-01-01T00:00:00.000Z",
        entries: [
          {
            cveId: "CVE-2024-1111",
            vulnerabilityName: "Demo",
            dateAdded: "2024-04-01",
            dueDate: "2024-04-22",
            requiredAction: "Apply updates.",
          },
        ],
      },
    })
    assert.equal(scan.osv, "ok")
    assert.deepEqual(scan.advisories.map((item) => item.id), ["GHSA-a", "GHSA-b"])
    assert.deepEqual(scan.advisories[0]?.versions, ["2.0.0", "1.0.0"])
    assert.equal(scan.advisories[0]?.kev[0]?.vulnerabilityName, "Demo")
    assert.equal(scan.advisories[0]?.kev[0]?.dateAdded, "2024-04-01")
    assert.deepEqual(scan.advisories[1]?.kev, [])
    assert.equal(scan.notices.some((notice) => notice.text === SCAN_EMPTY), false)
    assert.equal(scan.notices.some((notice) => notice.text === SCAN_KEV_DOWN), false)
    assert.equal(Object.hasOwn(scan, "score"), false)
    assert.equal(JSON.stringify(scan).includes("ranges"), false)
  })

  it("drops KEV when OSV did not answer", () => {
    const scan = joinAdvisoryScan({
      observedAt: "2026-01-01T00:00:00.000Z",
      rows: null,
      records: new Map(),
      kev: {
        state: "ok",
        observedAt: "2026-01-01T00:00:00.000Z",
        entries: [
          {
            cveId: "CVE-2024-1111",
            vulnerabilityName: "Demo",
            dateAdded: "2024-04-01",
            dueDate: "2024-04-22",
            requiredAction: "Apply updates.",
          },
        ],
      },
    })
    assert.equal(scan.osv, "unavailable")
    assert.deepEqual(scan.advisories, [])
    assert.deepEqual(scan.notices, [{ text: SCAN_DOWN }])
    assert.equal(JSON.stringify(scan).includes("Demo"), false)
  })

  it("uses the empty sentence only when the finished list has no ids", () => {
    const empty = joinAdvisoryScan({
      observedAt: "2026-01-01T00:00:00.000Z",
      rows: [{ version: "1.0.0", ids: [], incomplete: false }],
      records: new Map(),
      kev: { state: "skipped" },
    })
    assert.deepEqual(empty.notices, [{ text: SCAN_EMPTY }])

    const unfinished = joinAdvisoryScan({
      observedAt: "2026-01-01T00:00:00.000Z",
      rows: [{ version: "1.0.0", ids: [], incomplete: true }],
      records: new Map(),
      kev: { state: "skipped" },
    })
    assert.equal(unfinished.notices.some((notice) => notice.text === SCAN_EMPTY), false)
    assert.match(unfinished.notices[0]?.text ?? "", /OSV did not finish the advisory list for 1\.0\.0/)
    assert.match(unfinished.notices[0]?.text ?? "", /not an empty result/)
  })

  it("keeps a named id when its record is missing, including a malicious id", () => {
    const scan = joinAdvisoryScan({
      observedAt: "2026-01-01T00:00:00.000Z",
      rows: [{ version: "1.0.0", ids: ["GHSA-missing", "MAL-2024-1"], incomplete: false }],
      records: new Map<string, OsvAdvisory | "missing">([
        ["GHSA-missing", "missing"],
        ["MAL-2024-1", advisory("MAL-2024-1", [], "")],
      ]),
      kev: { state: "skipped" },
    })
    assert.equal(scan.advisories[0]?.id, "GHSA-missing")
    assert.equal(scan.advisories[0]?.summary, "")
    assert.equal(scan.advisories[0]?.malicious, false)
    assert.equal(scan.advisories[1]?.malicious, true)
    assert.match(scan.notices.map((notice) => notice.text).join(" "), /OSV named GHSA-missing and did not return their records/)
    assert.equal(scan.notices.some((notice) => notice.text === SCAN_KEV_DOWN), false)
  })

  it("says the catalog is down when a tied CVE cannot be checked, and names CVEs the catalog does not list", () => {
    const down = joinAdvisoryScan({
      observedAt: "2026-01-01T00:00:00.000Z",
      rows: [{ version: "1.0.0", ids: ["GHSA-a"], incomplete: false }],
      records: new Map([["GHSA-a", advisory("GHSA-a", ["CVE-2024-1111"])]]),
      kev: { state: "unavailable" },
    })
    assert.deepEqual(down.advisories[0]?.kev, [])
    assert.equal(down.notices.some((notice) => notice.text === SCAN_KEV_DOWN), true)

    const absent = joinAdvisoryScan({
      observedAt: "2026-01-01T00:00:00.000Z",
      rows: [{ version: "1.0.0", ids: ["GHSA-a"], incomplete: false }],
      records: new Map([["GHSA-a", advisory("GHSA-a", ["CVE-2024-2222"])]]),
      kev: { state: "ok", observedAt: "2025-12-01T00:00:00.000Z", entries: [] },
    })
    assert.match(absent.notices.map((notice) => notice.text).join(" "), /2025-12-01T00:00:00.000Z/)
    assert.match(absent.notices.map((notice) => notice.text).join(" "), /CVE-2024-2222/)
    assert.equal(absent.notices.some((notice) => notice.text === SCAN_KEV_DOWN), false)
  })

  it("orders the scan as the page versions, then dist-tags that were not already listed", () => {
    assert.deepEqual(
      scannedVersions({
        versions: ["2.0.0", "1.0.0"],
        distTags: [{ version: "2.0.0" }, { version: "1.5.0" }],
      }),
      ["2.0.0", "1.0.0", "1.5.0"],
    )
  })

  it("marks a stale scan once", () => {
    const once = markScanStale({
      observedAt: "2026-01-01T00:00:00.000Z",
      stale: false,
      osv: "ok",
      incompleteVersions: [],
      advisories: [],
      notices: [{ text: SCAN_EMPTY }],
    })
    assert.equal(once.stale, true)
    const twice = markScanStale(once)
    assert.deepEqual(twice.notices.map((notice) => notice.text), [SCAN_EMPTY, SCAN_STALE])
  })
})

describe("OSV querybatch", () => {
  it("follows one page and marks a leftover token incomplete", async () => {
    const calls: Array<{ queries: Array<{ version: string; page_token?: string }> }> = []
    const fetcher: Fetcher = async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as { queries: Array<{ version: string; page_token?: string }> }
      calls.push(body)
      if (calls.length === 1) {
        return json({
          results: [
            { vulns: [{ id: "GHSA-a" }], next_page_token: "page-2" },
            { vulns: [{ id: "GHSA-b" }] },
          ],
        })
      }
      return json({
        results: [{ vulns: [{ id: "GHSA-a" }, { id: "GHSA-c" }], next_page_token: "page-3" }],
      })
    }
    const result = await readOsvBatch(fetcher, "demo", ["1.0.0", "1.0.1"])
    assert.equal(result.state, "ok")
    if (result.state !== "ok") return
    assert.equal(calls.length, 2)
    assert.equal(calls[1]?.queries.length, 1)
    assert.equal(calls[1]?.queries[0]?.version, "1.0.0")
    assert.equal(calls[1]?.queries[0]?.page_token, "page-2")
    assert.deepEqual(result.rows[0], { version: "1.0.0", ids: ["GHSA-a", "GHSA-c"], incomplete: true })
    assert.deepEqual(result.rows[1], { version: "1.0.1", ids: ["GHSA-b"], incomplete: false })
  })

  it("treats a short page or a non-array vuln list as no answer", async () => {
    const short = await readOsvBatch(async () => json({ results: [] }), "demo", ["1.0.0"])
    assert.deepEqual(short, { state: "unavailable" })
    const bad = await readOsvBatch(async () => json({ results: [{ vulns: {} }] }), "demo", ["1.0.0"])
    assert.deepEqual(bad, { state: "unavailable" })
  })
})

describe("advisory scanner", () => {
  it("omits the list without a token, scans when the index already paid, and does not cache an outage", async () => {
    let calls = 0
    let down = true
    const fetcher: Fetcher = async () => {
      calls += 1
      if (down) return json({ error: "down" }, 503)
      return json({ results: [{ vulns: [] }] })
    }
    const budget = new MissBudget(0, 60_000)
    const scanner = createScanner({
      fetcher,
      gate: new UpstreamGate(8),
      flights: new SingleFlight(),
      budget,
      getKev: () => null,
      refreshKev: async () => null,
    })
    const empty = await scanner.scan({ name: "demo", versions: [], charged: false, ip: "10.0.0.8", nowMs: 1_000 })
    assert.equal(empty.notices[0]?.text, SCAN_EMPTY)
    assert.equal(calls, 0)

    const omitted = await scanner.scan({ name: "demo", versions: ["1.0.0"], charged: false, ip: "10.0.0.8", nowMs: 1_000 })
    assert.equal(omitted.osv, "omitted")
    assert.equal(omitted.notices[0]?.text, SCAN_OMITTED)
    assert.equal(calls, 0)

    const failed = await scanner.scan({ name: "demo", versions: ["1.0.0"], charged: true, ip: "10.0.0.8", nowMs: 1_000 })
    assert.equal(failed.osv, "unavailable")
    assert.equal(calls, 1)

    down = false
    const loaded = await scanner.scan({ name: "demo", versions: ["1.0.0"], charged: true, ip: "10.0.0.8", nowMs: 1_000 })
    assert.equal(loaded.osv, "ok")
    assert.equal(loaded.notices.some((notice) => notice.text === SCAN_EMPTY), true)
    assert.equal(calls, 2)

    const cached = await scanner.scan({ name: "demo", versions: ["1.0.0"], charged: false, ip: "10.0.0.8", nowMs: 2_000 })
    assert.equal(cached.stale, false)
    assert.equal(calls, 2)

    const stale = await scanner.scan({
      name: "demo",
      versions: ["1.0.0"],
      charged: false,
      ip: "10.0.0.8",
      nowMs: 1_000 + TTL_MS.osv,
    })
    assert.equal(stale.stale, true)
    assert.equal(stale.notices.some((notice) => notice.text === SCAN_STALE), true)
    assert.equal(calls, 2)
  })
})
