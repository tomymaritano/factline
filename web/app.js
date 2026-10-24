const nameInput = document.querySelector("#name")
const versionInput = document.querySelector("#version")
const form = document.querySelector("#lookup")
const statusNode = document.querySelector("#status")
const result = document.querySelector("#result")
const subjectNode = document.querySelector("#subject")
const generatedNode = document.querySelector("#generated")
const noticesNode = document.querySelector("#notices")
const eventsNode = document.querySelector("#events")
const readingsNode = document.querySelector("#readings")
const sourcesNode = document.querySelector("#sources")
const recentNode = document.querySelector("#recent")

const LINK_PREFIXES = [
  "https://registry.npmjs.org/",
  "https://osv.dev/vulnerability/",
  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  "https://api.deps.dev/",
  "https://scorecard.dev/viewer/",
]

const ERRORS = {
  invalid_name: "Package names are lowercase npm names, with an optional scope.",
  invalid_version: "Use an exact version or a dist-tag. Ranges stay out.",
  not_found: "The registry has no such package or version.",
  registry_unavailable: "The registry did not answer, and there is no cached copy.",
  rate_limited: "Too many new lookups from this address. A page already cached on the server still opens.",
  internal: "Factline failed before it could build the timeline.",
}

form.addEventListener("submit", (event) => {
  event.preventDefault()
  const name = nameInput.value.trim()
  const version = versionInput.value.trim()
  const url = new URL(location.href)
  url.searchParams.set("name", name)
  url.searchParams.set("version", version)
  history.pushState(null, "", url)
  void load(name, version)
})

document.querySelector("#example").addEventListener("click", () => {
  nameInput.value = "ms"
  versionInput.value = "2.1.3"
  form.requestSubmit()
})

window.addEventListener("popstate", () => {
  void openFromAddress()
})

void openFromAddress()
void loadRecent()

async function openFromAddress() {
  const params = new URLSearchParams(location.search)
  const name = params.get("name") ?? ""
  const version = params.get("version") ?? ""
  nameInput.value = name
  versionInput.value = version
  if (name && version) await load(name, version)
  else {
    result.hidden = true
    statusNode.textContent = ""
  }
}

async function load(name, version) {
  statusNode.textContent = "Reading the public records."
  result.hidden = true
  const response = await fetch(`/api/v1/timeline?name=${encodeURIComponent(name)}&version=${encodeURIComponent(version)}`)
  const body = await response.json()
  if (!response.ok) {
    statusNode.textContent = ERRORS[body.error] ?? "The timeline did not load."
    await loadRecent()
    return
  }
  if (body.subject.resolvedFromTag) {
    const url = new URL(location.href)
    url.searchParams.set("name", body.subject.name)
    url.searchParams.set("version", body.subject.version)
    history.replaceState(null, "", url)
    versionInput.value = body.subject.version
  }
  statusNode.textContent = ""
  render(body)
  await loadRecent()
}

async function loadRecent() {
  recentNode.replaceChildren()
  const response = await fetch("/api/v1/recent")
  if (!response.ok) return
  const rows = await response.json()
  if (!Array.isArray(rows) || rows.length === 0) {
    recentNode.append(el("li", "", "No lookups yet from this server."))
    return
  }
  for (const row of rows) {
    const item = el("li")
    const link = el("a", "", `${row.name}@${row.version}`)
    link.href = `/?name=${encodeURIComponent(row.name)}&version=${encodeURIComponent(row.version)}`
    item.append(link, el("span", "meta", ` ${row.lookedUpAt}`))
    recentNode.append(item)
  }
}

function render(timeline) {
  result.hidden = false
  subjectNode.textContent = `${timeline.subject.name}@${timeline.subject.version}`
  generatedNode.textContent = `Generated ${timeline.generatedAt}`
  noticesNode.replaceChildren()
  for (const notice of timeline.notices) noticesNode.append(el("li", "", notice.text))

  eventsNode.replaceChildren()
  for (const fact of timeline.events) eventsNode.append(renderEvent(fact))

  readingsNode.replaceChildren()
  if (timeline.readings.length === 0) {
    readingsNode.append(el("p", "wording", "No repository or popularity reading for this version."))
  }
  for (const reading of timeline.readings) readingsNode.append(renderReading(reading))

  sourcesNode.replaceChildren()
  for (const source of timeline.sources) {
    const when = source.observedAt ? source.observedAt : "not observed"
    const stale = source.stale ? ", older than its refresh window" : ""
    sourcesNode.append(el("li", "", `${source.source}: ${source.state}, ${when}${stale}`))
  }
}

function renderEvent(fact) {
  const item = el("li", "event")
  const when = el("p", "when")
  when.textContent = fact.precision === "date" ? fact.occurredAt.slice(0, 10) : fact.occurredAt
  const card = el("article", "card")
  if (fact.kind === "version_published") card.append(...published(fact))
  if (fact.kind === "install_hooks") card.append(...hooks(fact))
  if (fact.kind === "publisher_window") card.append(...burst(fact))
  if (fact.kind === "osv") card.append(...osv(fact))
  if (fact.kind === "kev") card.append(...kev(fact))
  card.append(sourceLine(fact.sourceUrl, fact.observedAt, fact.stale))
  item.append(when, card)
  return item
}

function published(fact) {
  return [
    el("h3", "", "Published"),
    el("p", "", fact.publisher ? `Publisher ${fact.publisher}` : "No publisher name on this version."),
  ]
}

function hooks(fact) {
  const nodes = [el("h3", "", "Install hooks")]
  if (fact.baseline === "none") {
    nodes.push(el("p", "", "No earlier version is still in the registry. These hooks are listed, not compared."))
  } else {
    const line = el("p")
    line.textContent = fact.differs ? "Hooks differ from " : "Hooks match "
    line.append(document.createTextNode(fact.predecessor.version))
    if (fact.differs) line.className = "differs"
    nodes.push(line)
  }
  const list = el("ul")
  for (const hook of fact.hooks) {
    const row = el("li")
    row.append(el("span", "", `${hook.hook}: ${hook.change}`))
    if (hook.command) row.append(commandNote(hook.command))
    if (hook.previousCommand && hook.change === "modified") {
      row.append(el("span", "meta", " Previous prefix differs by hash."))
    }
    list.append(row)
  }
  nodes.push(list)
  return nodes
}

function commandNote(command) {
  const note = el("div", "hash")
  note.textContent = `${command.prefix}${command.truncated ? "…" : ""}`
  const hash = el("div", "hash")
  hash.textContent = command.sha256
  const wrap = el("div")
  wrap.append(note, hash)
  return wrap
}

function burst(fact) {
  const nodes = [
    el("h3", "", "Publisher window"),
    el(
      "p",
      "",
      `${fact.count} ${fact.count === 1 ? "version" : "versions"} by ${fact.publisher}, including this one.`,
    ),
    el(
      "p",
      "",
      `Same _npmUser.name, ${fact.windowMinutes} minutes either side, versions still in the packument. Notable means the count is at least ${fact.notableMinimum}. The count is the fact.`,
    ),
  ]
  if (fact.notable) nodes.push(el("p", "differs", "Notable"))
  const list = el("ul")
  for (const version of fact.versions) list.append(el("li", "meta", version))
  nodes.push(list)
  return nodes
}

function osv(fact) {
  const nodes = [el("h3", "", fact.id)]
  if (fact.malicious) nodes.push(el("p", "malicious", "Malicious-package record"))
  if (fact.summary) nodes.push(el("p", "", fact.summary))
  if (fact.aliases.length > 0) nodes.push(el("p", "meta", `Aliases ${fact.aliases.join(", ")}`))
  const ranges = el("ul")
  for (const range of fact.ranges) {
    const bits = range.events.map((event) => {
      const [key, value] = Object.entries(event)[0] ?? ["event", ""]
      return `${key} ${value}`
    })
    ranges.append(el("li", "", `${range.type}: ${bits.join(", ")}`))
  }
  if (fact.ranges.length > 0) nodes.push(ranges)
  if (fact.explicitVersionCount > 0) {
    nodes.push(el("p", "meta", `${fact.explicitVersionCount} explicit versions. Showing ${fact.explicitVersions.length}.`))
  }
  return nodes
}

function kev(fact) {
  return [
    el("h3", "", fact.cveId),
    el("p", "", fact.vulnerabilityName),
    el("p", "", `Required action: ${fact.requiredAction}`),
    el("p", "meta", `Due ${fact.dueDate}. Tied by ${fact.tiedBy.join(", ")}.`),
  ]
}

function renderReading(reading) {
  const block = el("section", "reading")
  if (reading.kind === "public_dependents") {
    block.append(
      el("h3", "", "Public dependents"),
      el("p", "count", String(reading.dependentCount)),
      el("p", "meta", `${reading.directDependentCount} direct, ${reading.indirectDependentCount} indirect`),
      el("p", "wording", reading.wording),
    )
  } else {
    block.append(
      el("h3", "", `Scorecard ${reading.score}`),
      el("p", "", reading.repo),
      el("p", "wording", "This is the repository Scorecard scanned, not the commit npm packed for this version."),
      el("p", "meta", `Report ${reading.reportedAt}`),
    )
    const list = el("ul")
    for (const check of reading.checks) list.append(el("li", "", `${check.name}: ${check.score}. ${check.reason}`))
    block.append(list)
  }
  block.append(sourceLine(reading.sourceUrl, reading.observedAt, reading.stale))
  return block
}

function sourceLine(url, observedAt, stale) {
  const line = el("p", "meta")
  link(line, url, "Source")
  line.append(document.createTextNode(` · observed ${observedAt}${stale ? " · stale" : ""}`))
  return line
}

function link(parent, href, text) {
  if (LINK_PREFIXES.some((prefix) => href.startsWith(prefix))) {
    const anchor = el("a", "", text)
    anchor.href = href
    anchor.rel = "noreferrer"
    parent.append(anchor)
    return
  }
  parent.append(document.createTextNode(text))
}

function el(tag, className, text) {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text !== undefined) node.textContent = text
  return node
}
