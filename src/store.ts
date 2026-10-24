import { DatabaseSync } from "node:sqlite"
import type {
  DependentsProjection,
  HookSet,
  KevEntry,
  KevProjection,
  OsvAdvisory,
  OsvProjection,
  PackumentProjection,
  RepoParse,
  ScorecardProjection,
  VersionRecord,
} from "./domain/types.ts"

export type StoredPackument = PackumentProjection & { notFound: boolean }

export type StoredScorecard =
  | { state: "present"; projection: ScorecardProjection }
  | { state: "absent"; observedAt: string; repo: string }

export type LookupKind = "version" | "package" | "search"

export type LookupRow = {
  kind: LookupKind
  name: string
  version: string
  query: string
  lookedUpAt: string
}

export type LookupEntry = {
  kind: LookupKind
  name: string
  version: string
  query: string
  lookedUpAt: string
}

export type Store = {
  close: () => void
  getPackument: (name: string) => StoredPackument | null
  putPackument: (name: string, observedAt: string, projection: Omit<PackumentProjection, "observedAt">) => void
  putPackumentMissing: (name: string, observedAt: string) => void
  getOsv: (name: string, version: string) => OsvProjection | null
  putOsv: (name: string, version: string, observedAt: string, advisories: OsvAdvisory[]) => void
  getKev: () => KevProjection | null
  putKev: (observedAt: string, catalogVersion: string | null, entries: KevEntry[]) => void
  getDependents: (name: string, version: string) => DependentsProjection | null
  putDependents: (name: string, version: string, observedAt: string, counts: Omit<DependentsProjection, "observedAt">) => void
  getScorecard: (repo: string) => StoredScorecard | null
  putScorecardPresent: (repo: string, observedAt: string, report: Omit<ScorecardProjection, "observedAt" | "repo">) => void
  putScorecardAbsent: (repo: string, observedAt: string) => void
  addLookup: (entry: LookupEntry) => void
  recentLookups: (limit: number) => LookupRow[]
}

export function openStore(path: string): Store {
  const db = new DatabaseSync(path)
  db.exec("PRAGMA busy_timeout = 5000")
  if (path !== ":memory:") db.exec("PRAGMA journal_mode = WAL")
  db.exec(`
    CREATE TABLE IF NOT EXISTS packument_sync (
      name TEXT PRIMARY KEY,
      observed_at TEXT NOT NULL,
      not_found INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dist_tags (
      name TEXT NOT NULL,
      tag TEXT NOT NULL,
      version TEXT NOT NULL,
      PRIMARY KEY (name, tag)
    );
    CREATE TABLE IF NOT EXISTS versions (
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      published_at TEXT NOT NULL,
      publisher TEXT,
      hooks_json TEXT NOT NULL,
      repository_json TEXT NOT NULL,
      PRIMARY KEY (name, version)
    );
    CREATE TABLE IF NOT EXISTS osv_sync (
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      PRIMARY KEY (name, version)
    );
    CREATE TABLE IF NOT EXISTS osv_advisories (
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      id TEXT NOT NULL,
      body_json TEXT NOT NULL,
      PRIMARY KEY (name, version, id)
    );
    CREATE TABLE IF NOT EXISTS kev_sync (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      observed_at TEXT NOT NULL,
      catalog_version TEXT
    );
    CREATE TABLE IF NOT EXISTS kev_cves (
      cve_id TEXT PRIMARY KEY,
      vulnerability_name TEXT NOT NULL,
      date_added TEXT NOT NULL,
      due_date TEXT NOT NULL,
      required_action TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dependents_sync (
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      dependent_count INTEGER NOT NULL,
      direct_dependent_count INTEGER NOT NULL,
      indirect_dependent_count INTEGER NOT NULL,
      PRIMARY KEY (name, version)
    );
    CREATE TABLE IF NOT EXISTS scorecard_sync (
      repo TEXT PRIMARY KEY,
      observed_at TEXT NOT NULL,
      state TEXT NOT NULL,
      body_json TEXT
    );
    CREATE TABLE IF NOT EXISTS lookups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      looked_up_at TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'version',
      query TEXT NOT NULL DEFAULT ''
    );
  `)
  const lookupColumns = new Set(
    (db.prepare("PRAGMA table_info(lookups)").all() as Array<{ name: string }>).map((column) => column.name),
  )
  if (!lookupColumns.has("kind")) db.exec("ALTER TABLE lookups ADD COLUMN kind TEXT NOT NULL DEFAULT 'version'")
  if (!lookupColumns.has("query")) db.exec("ALTER TABLE lookups ADD COLUMN query TEXT NOT NULL DEFAULT ''")

  return {
    close: () => db.close(),
    getPackument: (name) => readPackument(db, name),
    putPackument: (name, observedAt, projection) => writePackument(db, name, observedAt, projection),
    putPackumentMissing: (name, observedAt) => writePackumentMissing(db, name, observedAt),
    getOsv: (name, version) => readOsv(db, name, version),
    putOsv: (name, version, observedAt, advisories) => writeOsv(db, name, version, observedAt, advisories),
    getKev: () => readKev(db),
    putKev: (observedAt, catalogVersion, entries) => writeKev(db, observedAt, catalogVersion, entries),
    getDependents: (name, version) => readDependents(db, name, version),
    putDependents: (name, version, observedAt, counts) => writeDependents(db, name, version, observedAt, counts),
    getScorecard: (repo) => readScorecard(db, repo),
    putScorecardPresent: (repo, observedAt, report) => writeScorecard(db, repo, observedAt, "present", report),
    putScorecardAbsent: (repo, observedAt) => writeScorecard(db, repo, observedAt, "absent", null),
    addLookup: (entry) => rememberLookup(db, entry),
    recentLookups: (limit) =>
      db
        .prepare(
          `SELECT kind, name, version, query, looked_up_at AS lookedUpAt
           FROM lookups
           WHERE id IN (SELECT MAX(id) FROM lookups GROUP BY kind, name, version, query)
           ORDER BY id DESC
           LIMIT ?`,
        )
        .all(limit) as LookupRow[],
  }
}

function rememberLookup(db: DatabaseSync, entry: LookupEntry): void {
  if (entry.kind !== "version" && entry.kind !== "package" && entry.kind !== "search") return
  transaction(db, () => {
    db.prepare("DELETE FROM lookups WHERE kind = ? AND name = ? AND version = ? AND query = ?").run(
      entry.kind,
      entry.name,
      entry.version,
      entry.query,
    )
    db.prepare("INSERT INTO lookups (kind, name, version, query, looked_up_at) VALUES (?, ?, ?, ?, ?)").run(
      entry.kind,
      entry.name,
      entry.version,
      entry.query,
      entry.lookedUpAt,
    )
    db.exec(
      `DELETE FROM lookups WHERE id NOT IN (
         SELECT id FROM (
           SELECT MAX(id) AS id FROM lookups GROUP BY kind, name, version, query ORDER BY 1 DESC LIMIT 10
         )
       )`,
    )
  })
}

function transaction(db: DatabaseSync, fn: () => void): void {
  db.exec("BEGIN")
  try {
    fn()
    db.exec("COMMIT")
  } catch (error) {
    db.exec("ROLLBACK")
    throw error
  }
}

function readPackument(db: DatabaseSync, name: string): StoredPackument | null {
  const sync = db.prepare("SELECT observed_at, not_found FROM packument_sync WHERE name = ?").get(name) as
    | { observed_at: string; not_found: number }
    | undefined
  if (!sync) return null
  const tagRows = db.prepare("SELECT tag, version FROM dist_tags WHERE name = ?").all(name) as Array<{
    tag: string
    version: string
  }>
  const distTags: Record<string, string> = {}
  for (const row of tagRows) distTags[row.tag] = row.version
  const versionRows = db
    .prepare(
      "SELECT version, published_at, publisher, hooks_json, repository_json FROM versions WHERE name = ?",
    )
    .all(name) as Array<{
    version: string
    published_at: string
    publisher: string | null
    hooks_json: string
    repository_json: string
  }>
  const versions: VersionRecord[] = versionRows.map((row) => ({
    version: row.version,
    publishedAt: row.published_at,
    publisher: row.publisher,
    hooks: JSON.parse(row.hooks_json) as HookSet,
    repository: JSON.parse(row.repository_json) as RepoParse,
  }))
  return { observedAt: sync.observed_at, notFound: sync.not_found === 1, distTags, versions }
}

function writePackument(
  db: DatabaseSync,
  name: string,
  observedAt: string,
  projection: Omit<PackumentProjection, "observedAt">,
): void {
  transaction(db, () => {
    db.prepare("DELETE FROM versions WHERE name = ?").run(name)
    db.prepare("DELETE FROM dist_tags WHERE name = ?").run(name)
    const insertVersion = db.prepare(
      "INSERT INTO versions (name, version, published_at, publisher, hooks_json, repository_json) VALUES (?, ?, ?, ?, ?, ?)",
    )
    for (const version of projection.versions) {
      insertVersion.run(
        name,
        version.version,
        version.publishedAt,
        version.publisher,
        JSON.stringify(version.hooks),
        JSON.stringify(version.repository),
      )
    }
    const insertTag = db.prepare("INSERT INTO dist_tags (name, tag, version) VALUES (?, ?, ?)")
    for (const [tag, version] of Object.entries(projection.distTags)) insertTag.run(name, tag, version)
    db.prepare(
      "INSERT INTO packument_sync (name, observed_at, not_found) VALUES (?, ?, 0) ON CONFLICT(name) DO UPDATE SET observed_at = excluded.observed_at, not_found = 0",
    ).run(name, observedAt)
  })
}

function writePackumentMissing(db: DatabaseSync, name: string, observedAt: string): void {
  transaction(db, () => {
    db.prepare("DELETE FROM versions WHERE name = ?").run(name)
    db.prepare("DELETE FROM dist_tags WHERE name = ?").run(name)
    db.prepare(
      "INSERT INTO packument_sync (name, observed_at, not_found) VALUES (?, ?, 1) ON CONFLICT(name) DO UPDATE SET observed_at = excluded.observed_at, not_found = 1",
    ).run(name, observedAt)
  })
}

function readOsv(db: DatabaseSync, name: string, version: string): OsvProjection | null {
  const sync = db
    .prepare("SELECT observed_at FROM osv_sync WHERE name = ? AND version = ?")
    .get(name, version) as { observed_at: string } | undefined
  if (!sync) return null
  const rows = db
    .prepare("SELECT body_json FROM osv_advisories WHERE name = ? AND version = ? ORDER BY id")
    .all(name, version) as Array<{ body_json: string }>
  return {
    observedAt: sync.observed_at,
    advisories: rows.map((row) => JSON.parse(row.body_json) as OsvAdvisory),
  }
}

function writeOsv(db: DatabaseSync, name: string, version: string, observedAt: string, advisories: OsvAdvisory[]): void {
  transaction(db, () => {
    db.prepare("DELETE FROM osv_advisories WHERE name = ? AND version = ?").run(name, version)
    const insert = db.prepare(
      "INSERT INTO osv_advisories (name, version, id, body_json) VALUES (?, ?, ?, ?)",
    )
    for (const advisory of advisories) insert.run(name, version, advisory.id, JSON.stringify(advisory))
    db.prepare(
      "INSERT INTO osv_sync (name, version, observed_at) VALUES (?, ?, ?) ON CONFLICT(name, version) DO UPDATE SET observed_at = excluded.observed_at",
    ).run(name, version, observedAt)
  })
}

function readKev(db: DatabaseSync): KevProjection | null {
  const sync = db.prepare("SELECT observed_at, catalog_version FROM kev_sync WHERE id = 1").get() as
    | { observed_at: string; catalog_version: string | null }
    | undefined
  if (!sync) return null
  const rows = db
    .prepare(
      "SELECT cve_id, vulnerability_name, date_added, due_date, required_action FROM kev_cves",
    )
    .all() as Array<{
    cve_id: string
    vulnerability_name: string
    date_added: string
    due_date: string
    required_action: string
  }>
  return {
    observedAt: sync.observed_at,
    catalogVersion: sync.catalog_version,
    entries: rows.map((row) => ({
      cveId: row.cve_id,
      vulnerabilityName: row.vulnerability_name,
      dateAdded: row.date_added,
      dueDate: row.due_date,
      requiredAction: row.required_action,
    })),
  }
}

function writeKev(db: DatabaseSync, observedAt: string, catalogVersion: string | null, entries: KevEntry[]): void {
  transaction(db, () => {
    db.exec("DELETE FROM kev_cves")
    const insert = db.prepare(
      "INSERT INTO kev_cves (cve_id, vulnerability_name, date_added, due_date, required_action) VALUES (?, ?, ?, ?, ?)",
    )
    for (const entry of entries) {
      insert.run(entry.cveId, entry.vulnerabilityName, entry.dateAdded, entry.dueDate, entry.requiredAction)
    }
    db.prepare(
      "INSERT INTO kev_sync (id, observed_at, catalog_version) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET observed_at = excluded.observed_at, catalog_version = excluded.catalog_version",
    ).run(observedAt, catalogVersion)
  })
}

function readDependents(db: DatabaseSync, name: string, version: string): DependentsProjection | null {
  const row = db
    .prepare(
      "SELECT observed_at, dependent_count, direct_dependent_count, indirect_dependent_count FROM dependents_sync WHERE name = ? AND version = ?",
    )
    .get(name, version) as
    | {
        observed_at: string
        dependent_count: number
        direct_dependent_count: number
        indirect_dependent_count: number
      }
    | undefined
  if (!row) return null
  return {
    observedAt: row.observed_at,
    dependentCount: row.dependent_count,
    directDependentCount: row.direct_dependent_count,
    indirectDependentCount: row.indirect_dependent_count,
  }
}

function writeDependents(
  db: DatabaseSync,
  name: string,
  version: string,
  observedAt: string,
  counts: Omit<DependentsProjection, "observedAt">,
): void {
  db.prepare(
    `INSERT INTO dependents_sync (name, version, observed_at, dependent_count, direct_dependent_count, indirect_dependent_count)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(name, version) DO UPDATE SET
       observed_at = excluded.observed_at,
       dependent_count = excluded.dependent_count,
       direct_dependent_count = excluded.direct_dependent_count,
       indirect_dependent_count = excluded.indirect_dependent_count`,
  ).run(
    name,
    version,
    observedAt,
    counts.dependentCount,
    counts.directDependentCount,
    counts.indirectDependentCount,
  )
}

function readScorecard(db: DatabaseSync, repo: string): StoredScorecard | null {
  const row = db.prepare("SELECT observed_at, state, body_json FROM scorecard_sync WHERE repo = ?").get(repo) as
    | { observed_at: string; state: string; body_json: string | null }
    | undefined
  if (!row) return null
  if (row.state === "absent") return { state: "absent", observedAt: row.observed_at, repo }
  if (!row.body_json) return null
  const report = JSON.parse(row.body_json) as Omit<ScorecardProjection, "observedAt" | "repo">
  return { state: "present", projection: { ...report, observedAt: row.observed_at, repo } }
}

function writeScorecard(
  db: DatabaseSync,
  repo: string,
  observedAt: string,
  state: "present" | "absent",
  report: Omit<ScorecardProjection, "observedAt" | "repo"> | null,
): void {
  db.prepare(
    `INSERT INTO scorecard_sync (repo, observed_at, state, body_json) VALUES (?, ?, ?, ?)
     ON CONFLICT(repo) DO UPDATE SET observed_at = excluded.observed_at, state = excluded.state, body_json = excluded.body_json`,
  ).run(repo, observedAt, state, report ? JSON.stringify(report) : null)
}
