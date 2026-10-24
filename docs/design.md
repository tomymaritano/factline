# Factline design

Factline shows one npm version moving through public records. The caller pastes a package name and a version. The product is the timeline of sourced facts. It is not a hygiene score and it is not a CVE search box.

Two structures were compared. They are not small variations: one stores projections fetched when someone asks, and the other owns a live cursor of the whole registry. The cursor design is recorded here so it does not get rebuilt by accident.

## Chosen design

One process. The browser talks only to its own origin. SQLite stores projections, not upstream documents. Each reader understands one document and does not know the others. A pure function, `assembleTimeline`, is the only place that decides whether a fact exists.

```
GET /api/v1/timeline?name={npm name}&version={semver or dist-tag}
GET /api/v1/recent
```

The page is `/?name=@scope/pkg&version=1.2.3`. Scoped names stay in the query string. A dist-tag is resolved through the packument and the address is replaced with the exact version. A range (`^`, `~`, `x`, `*`, a space, or a partial version like `1.2`) is `400 invalid_version`. An unknown package or version is `404`. If the packument cannot be fetched and nothing is cached, the response is `502`. Any other upstream failure leaves that fact out. It is never rendered as zero.

`GET /api/v1/recent` is this server's lookup history, at most 10 rows. It is not a feed of publishes.

The response has two collections:

- `events` are things that happened to the version: publication, the install-hook diff, the publisher window, an OSV advisory, a KEV row.
- `readings` are observations with no place on that axis: the deps.dev public dependent count, and a Scorecard report when one exists.

Putting the Scorecard report date next to the publish time reads as a sequence that did not happen. The report dates the repository Scorecard scanned, not the commit npm packed. The count from deps.dev is a snapshot taken when we asked. The type split is what stops the page from sorting those two onto the line.

There is no top-level score, grade, or rollup field.

### Who owns which rule

The registry reader owns the packument. It keeps `time[version]`, `_npmUser.name`, the four lifecycle hooks, and that version's `repository` field. It never requests `dist.tarball`. Publish time ignores `time.created` and `time.modified`. The predecessor is the other version still present with the greatest `publishedAt` strictly earlier than this one. Equal timestamps break by ascending version string, not by semver precedence. A refresh replaces that package's version rows in one transaction, so a version that disappeared from the packument disappears from the next lookup.

The command projector owns script text. For `preinstall`, `install`, `postinstall`, and `prepare`, a non-empty string becomes `{ prefix, truncated, sha256 }`. `prefix` is the first 160 code points. `sha256` is the hash of the exact string. The full string is dropped before insert, before logging, and before the response. Diffs compare hashes, so two long commands that share a prefix still show as modified. Empty strings and non-strings are no hook. No other `scripts` keys are kept. When there is no earlier version, the hooks are listed and `differs` is false. They are not described as added.

The publisher window lives in `src/domain/burst.ts`. The publisher is `_npmUser.name` only. Maintainers are not a fallback. The window is 60 minutes either side of this publish, same name, versions still in the packument, including this version. `notable` means the count is at least 3. Both constants are returned on the fact, and the page prints them. The count is the fact. A missing publisher produces a notice and no window.

The OSV reader owns the query response. It keeps id, published, modified, a 240-code-point summary, aliases, and the ranges and explicit versions whose package ecosystem is npm and whose name is this package. It drops `details`. Membership is OSV's answer for the queried version. Explicit versions on the fact are capped at 50; `explicitVersionCount` is the full number.

The KEV rule lives only in the assembler. A KEV row is emitted when an OSV id or alias matches `^CVE-\d{4}-\d+$` and that CVE is in the catalog. `tiedBy` lists the OSV ids. The catalog is not indexed by package name, and deps.dev advisories are not read. If OSV is unavailable, KEV rows are omitted even when the catalog is loaded. If OSV named CVEs and some are absent from the loaded catalog, a notice lists those CVE ids. `dateAdded` is a calendar date. The due date stays inside the fact.

The Scorecard reader is the only code that turns a repository field into `github.com/{owner}/{repo}`. It accepts a string or `{ url }`, strips `git+`, a fragment, and a `.git` suffix, and accepts `github:owner/repo` and `git@github.com:owner/repo`. The host must be `github.com` or `www.github.com`. The first two safe path segments are the owner and the repo. A missing field does not fall back to the packument's top-level repository, homepage, or bugs URL. A 404 is an absence notice, not a score. A network failure is a different notice. Check reasons are capped at 180 code points. A check score of `-1` stays `-1`.

The dependents reader stores the three counts deps.dev returns. Zero is a real reading. A failure omits the reading. The wording on the reading says the number is a public count of packages known to deps.dev, not a census.

### Cache, limits, and clocks

| Source | Refresh | If the refresh fails |
| --- | --- | --- |
| Packument | 15 minutes | Serve the cached projection and mark it stale. No cache: `502`, or `404` when a cached miss is still fresh. |
| OSV | 60 minutes | Serve the cached advisories stale, or omit them. |
| KEV | 12 hours | A cached catalog remains usable for 7 days, marked stale. Older than that, or never cached: no KEV rows. |
| Dependents | 24 hours | Serve stale, or omit. |
| Scorecard, including a 404 | 24 hours | Serve stale, or say it did not answer. |

Identical in-flight work for the same packument, the same `name@version` query, the global KEV catalog, or the same repository is one upstream call. At most 8 upstream calls run at once. A lookup that has to leave the cache costs one of 30 misses per minute per client address. The address is the socket address. If the budget is spent and a packument is already cached, the page is assembled from cache and the stale sources say so. If there is no usable packument, the response is `429`.

A standing notice says publish times come from the packument and the registry CDN can lag. The changes feed is not consulted to close that gap.

Browser cache for a timeline response is 60 seconds. The server cache is the real cache.

### Module shape

`loadTimeline(name, version)` is the deep module. It hides five document formats, the cache, and the join. Callers see a timeline or a named error.

The pure pieces (`selectPredecessor`, `diffHooks`, `publisherWindow`, `projectCommand`, `parseRepository`, `assembleTimeline`) do not touch the network. Policy tests run against them directly.

## Rejected design: a registry witness

Assume the on-demand timeline shipped and failed. The failure is structural. The packument plus four current documents are enough when someone already knows the version. They are not a history of publishes nobody asked about, they do not remember a version that was unpublished before the next refresh, and they cannot group a campaign across package names. The publisher window above is only inside one packument.

The other structure is a witness. A long-running process stores the sequence number from `https://replicate.npmjs.com/registry/_changes?since={seq}&limit=100`. For each change it re-reads the packument, diffs versions, and writes a compact row: name, version, sequence, time seen, publisher, hook hashes. The sequence advances only after that page commits. `timeline` prefers a witnessed row (`witnessed: true`) and otherwise uses the packument path (`witnessed: false`). `recent` becomes what the process saw, not what someone looked up. A cross-package campaign is a query over those rows: same publisher, hook hash different from that package's previous witnessed version, inside the same window. The page would show that query, not a hand-edited campaign file.

That design depends on the cursor being a cheap and complete log. The continuous feed is gone, the registry CDN can lag the changes feed, and a gap while the process is down is a gap in the homepage. Catch-up is part of the product, not a cron afterthought.

| Criterion | On-demand timeline | Witness |
| --- | --- | --- |
| Caller | One URL. The process exists to answer it. | The same URL, plus a process that must stay caught up. A late cursor makes the homepage a hole. |
| Interface | Events, readings, notices, sources. | Those, plus `witnessed`, cursor health, and a second meaning of `recent`. |
| Cases covered | Any version still in the packument, including one from years ago. The publisher window is inside one package. | A homepage and a cross-package campaign, and a version unpublished after it was seen. History starts when the process starts. |
| What has to be right | Cache windows, single-flight, and the KEV join. These are testable without a firehose. | Those, plus sequence advance, a retry when the CDN is behind, and catch-up. |
| Cost | Proportional to lookups. A cold page is a handful of upstream reads. | Proportional to every npm publish, including when nobody is looking. |

The witness does not make `timeline(name, version)` easier for the caller. It adds a whole-registry cursor for a homepage and for cross-package campaigns. Those are a later system. If they are built, they should write the same events this page already returns. The page should not grow a second join.

## Implementation

Node, one process, `node:sqlite`. The isolated design was already specified as TypeScript projections, and the approved shape was one process plus a database file. No native addon. The language is recorded here so a later change is a deliberate swap, not an unmade choice.

Out of this version: the changes feed, the OSV zip, BigQuery dependent names, a lockfile command, PyPI, crates.io, and the Go index.
