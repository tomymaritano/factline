import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { assembleTimeline, type AssembleInput } from "../src/domain/assemble.ts"
import { BURST_NOTABLE_COUNT, BURST_WINDOW_MINUTES, publisherWindow } from "../src/domain/burst.ts"
import { projectCommand } from "../src/domain/commands.ts"
import { diffHooks } from "../src/domain/hooks.ts"
import { selectPredecessor } from "../src/domain/predecessor.ts"
import { parseRepository } from "../src/domain/repository.ts"
import type { HookSet, VersionRecord } from "../src/domain/types.ts"
import { classifyVersion, validName } from "../src/domain/validate.ts"

const emptyHooks = (): HookSet => ({
  preinstall: null,
  install: null,
  postinstall: null,
  prepare: null,
})

describe("version input", () => {
  it("accepts an exact version or a dist-tag and rejects ranges", () => {
    assert.equal(classifyVersion("1.2.3"), "semver")
    assert.equal(classifyVersion("1.2.3-beta.1"), "semver")
    assert.equal(classifyVersion("1.2.3+build.5"), "semver")
    assert.equal(classifyVersion("latest"), "tag")
    assert.equal(classifyVersion("^1.2.3"), "invalid")
    assert.equal(classifyVersion("~1.2.3"), "invalid")
    assert.equal(classifyVersion("1.2"), "invalid")
    assert.equal(classifyVersion("1.x"), "invalid")
    assert.equal(classifyVersion("*"), "invalid")
    assert.equal(classifyVersion("1.2.3 || 2.0.0"), "invalid")
    assert.equal(validName("@scope/pkg"), true)
    assert.equal(validName("Pkg"), false)
  })
})

describe("commands", () => {
  it("keeps a prefix and a hash and drops the rest of the string", () => {
    const full = `${"a".repeat(159)}😀TAIL`
    const projected = projectCommand(full)
    assert.ok(projected)
    assert.equal(projected.truncated, true)
    assert.equal(Array.from(projected.prefix).length, 160)
    assert.equal(projected.prefix.includes("TAIL"), false)
    assert.equal(JSON.stringify(projected).includes("TAIL"), false)
    assert.equal(projectCommand(""), null)
    assert.equal(projectCommand(1), null)
  })
})

describe("predecessor", () => {
  it("picks the greatest earlier timestamp and breaks ties by the smaller version string", () => {
    const versions = [
      { version: "9.0.0", publishedAt: "2024-01-01T00:00:00.000Z" },
      { version: "8.0.0", publishedAt: "2024-01-01T00:00:00.000Z" },
      { version: "1.0.0", publishedAt: "2023-01-01T00:00:00.000Z" },
      { version: "9.1.0", publishedAt: "2024-06-01T00:00:00.000Z" },
    ]
    const picked = selectPredecessor(versions, versions[3]!)
    assert.equal(picked?.version, "8.0.0")
  })
})

describe("hooks", () => {
  it("calls a hash change modified even when the visible prefix matches", () => {
    const current = emptyHooks()
    const previous = emptyHooks()
    current.postinstall = { prefix: "same", truncated: true, sha256: "aaa" }
    previous.postinstall = { prefix: "same", truncated: true, sha256: "bbb" }
    const diff = diffHooks(current, previous)
    assert.equal(diff.differs, true)
    assert.equal(diff.hooks.find((hook) => hook.hook === "postinstall")?.change, "modified")
  })

  it("does not call the first published hooks a change", () => {
    const current = emptyHooks()
    current.install = { prefix: "node setup.js", truncated: false, sha256: "abc" }
    const diff = diffHooks(current, null)
    assert.equal(diff.baseline, "none")
    assert.equal(diff.differs, false)
    assert.equal(diff.hooks.find((hook) => hook.hook === "install")?.change, "unchanged")
  })
})

describe("publisher window", () => {
  it("counts the same publisher inside 60 minutes, including the exact boundary", () => {
    const subject = { version: "1.0.1", publishedAt: "2024-01-01T01:00:00.000Z", publisher: "ada" }
    const result = publisherWindow(
      [
        subject,
        { version: "1.0.0", publishedAt: "2024-01-01T00:00:00.000Z", publisher: "ada" },
        { version: "1.0.2", publishedAt: "2023-12-31T23:59:59.999Z", publisher: "ada" },
        { version: "1.0.3", publishedAt: "2024-01-01T01:10:00.000Z", publisher: "bea" },
      ],
      subject,
    )
    assert.ok(result)
    assert.equal(result.count, 2)
    assert.deepEqual(result.versions, ["1.0.0", "1.0.1"])
    assert.equal(result.windowMinutes, BURST_WINDOW_MINUTES)
    assert.equal(result.notable, false)
    assert.equal(result.notableMinimum, BURST_NOTABLE_COUNT)
    assert.equal(publisherWindow([subject], { ...subject, publisher: null }), null)
  })
})

describe("repository", () => {
  it("reads only a github.com repository from the version field", () => {
    assert.deepEqual(parseRepository({ url: "git+https://github.com/vercel/ms.git" }), {
      ok: true,
      repo: "github.com/vercel/ms",
    })
    assert.deepEqual(parseRepository("git@github.com:lodash/lodash.git"), {
      ok: true,
      repo: "github.com/lodash/lodash",
    })
    assert.deepEqual(parseRepository("github:ada/demo"), { ok: true, repo: "github.com/ada/demo" })
    assert.deepEqual(parseRepository("https://www.github.com/ada/demo#readme"), {
      ok: true,
      repo: "github.com/ada/demo",
    })
    assert.deepEqual(parseRepository("https://gitlab.com/ada/demo"), { ok: false, reason: "not_github" })
    assert.deepEqual(parseRepository(undefined), { ok: false, reason: "no_repository" })
    assert.deepEqual(parseRepository("https://github.com/not safe/demo"), { ok: false, reason: "not_github" })
  })
})

describe("assembler", () => {
  it("joins KEV only through a CVE that OSV named, and keeps snapshots off the event list", () => {
    const timeline = assembleTimeline(sampleInput())
    assert.equal("score" in timeline, false)
    assert.equal(timeline.events.some((event) => event.kind === "kev" && event.cveId === "CVE-2024-1111"), true)
    assert.equal(timeline.events.some((event) => event.kind === "kev" && event.cveId === "CVE-1999-0001"), false)
    assert.equal(timeline.readings.some((reading) => reading.kind === "public_dependents"), true)
    assert.equal(timeline.readings.some((reading) => reading.kind === "scorecard"), false)
    assert.equal(timeline.events.some((event) => "dependentCount" in event || "score" in event), false)
    assert.equal(timeline.notices.some((notice) => notice.code === "scorecard_absent"), true)
    const dependents = timeline.readings.find((reading) => reading.kind === "public_dependents")
    assert.equal(dependents && dependents.kind === "public_dependents" ? dependents.dependentCount : null, 0)
  })

  it("omits KEV when OSV did not answer", () => {
    const input = sampleInput()
    input.osv = { state: "unavailable" }
    const timeline = assembleTimeline(input)
    assert.equal(timeline.events.some((event) => event.kind === "kev"), false)
    assert.equal(timeline.events.some((event) => event.kind === "osv"), false)
    assert.equal(timeline.notices.some((notice) => notice.code === "osv_unavailable"), true)
  })

  it("does not invent a zero score when Scorecard has no report", () => {
    const timeline = assembleTimeline(sampleInput())
    assert.equal(JSON.stringify(timeline).includes('"score":0'), false)
    assert.equal(JSON.stringify(timeline).includes('"score":'), false)
  })
})

function sampleInput(): AssembleInput {
  const version = (name: string, publishedAt: string, command: string | null): VersionRecord => ({
    version: name,
    publishedAt,
    publisher: "ada",
    hooks: { ...emptyHooks(), postinstall: command ? projectCommand(command) : null },
    repository: { ok: true, repo: "github.com/ada/demo" },
  })
  return {
    now: "2024-06-01T00:00:00.000Z",
    subject: { name: "demo", version: "1.0.1", requestedVersion: "1.0.1", resolvedFromTag: null },
    registry: {
      stale: false,
      projection: {
        observedAt: "2024-06-01T00:00:00.000Z",
        distTags: { latest: "1.0.1" },
        versions: [
          version("1.0.0", "2024-01-01T00:00:00.000Z", "node good.js"),
          version("1.0.1", "2024-01-01T00:20:00.000Z", "node other.js"),
        ],
      },
    },
    osv: {
      state: "ok",
      stale: false,
      projection: {
        observedAt: "2024-06-01T00:00:00.000Z",
        advisories: [
          {
            id: "GHSA-test",
            published: "2024-02-01T00:00:00.000Z",
            modified: "2024-03-01T00:00:00.000Z",
            summary: "Example",
            aliases: ["CVE-2024-1111"],
            ranges: [{ type: "SEMVER", events: [{ introduced: "0.0.0" }, { fixed: "1.0.2" }] }],
            explicitVersions: [],
            explicitVersionCount: 0,
          },
        ],
      },
    },
    kev: {
      state: "ok",
      stale: false,
      projection: {
        observedAt: "2024-06-01T00:00:00.000Z",
        catalogVersion: "2024.06.01",
        entries: [
          {
            cveId: "CVE-2024-1111",
            vulnerabilityName: "Demo",
            dateAdded: "2024-04-01",
            dueDate: "2024-04-22",
            requiredAction: "Apply updates.",
          },
          {
            cveId: "CVE-1999-0001",
            vulnerabilityName: "Unrelated",
            dateAdded: "1999-01-01",
            dueDate: "1999-02-01",
            requiredAction: "None.",
          },
        ],
      },
    },
    deps: {
      state: "ok",
      stale: false,
      projection: {
        observedAt: "2024-06-01T00:00:00.000Z",
        dependentCount: 0,
        directDependentCount: 0,
        indirectDependentCount: 0,
      },
    },
    scorecard: {
      state: "absent",
      repo: "github.com/ada/demo",
      observedAt: "2024-06-01T00:00:00.000Z",
      stale: false,
    },
  }
}

