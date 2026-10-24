# Factline

A public timeline for one npm package version. You paste `package@version`. Factline lines up what the public records say about that version: when it was published, whether its install hooks changed, whether the same publisher shipped several versions in the same hour, which OSV advisories name it, and whether CISA KEV lists a CVE that one of those advisories already tied to it.

The OpenSSF Scorecard number and the public dependent count sit beside that line. They are not averaged into it. There is no score and no safe/unsafe badge.

```bash
npm install
npm test
npm start
```

Open [http://127.0.0.1:8080/?name=ms&version=2.1.3](http://127.0.0.1:8080/?name=ms&version=2.1.3).

`PORT`, `HOST`, and `FACTLINE_DB` override the listen address and the SQLite file. The default database is `factline.db` in the working directory. Nothing in the database is a copy of an install script or a package tarball.

## What a lookup does

The server reads the npm packument, asks OSV about that exact version, refreshes the KEV catalog when its copy is old, and reads the deps.dev dependent counts plus Scorecard when the version's own `repository` field is a github.com URL. A repeated lookup inside the cache window does not call those services again.

Ranges such as `^1.2.3` are rejected. A dist-tag such as `latest` is resolved, and the page address is rewritten to the exact version.

## What this refuses to do

- It does not download package tarballs and it does not run install scripts. A lifecycle hook is stored as a 160-character prefix plus the sha256 of the full command. The full command is discarded.
- It does not treat a KEV row as applying to a version unless OSV already named that CVE for the version. KEV has no affected range. If OSV does not answer, no KEV row is shown.
- It does not turn a missing Scorecard report into a zero.
- It does not describe the deps.dev count as a census of the web or of private repositories.
- It does not follow the npm changes feed. A homepage of "what just published" is a different system, described and rejected for this version in [docs/design.md](docs/design.md).

Node 22.13 or newer. The process uses the built-in `node:sqlite`. There is no native addon.
