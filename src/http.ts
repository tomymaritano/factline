import { createServer, type IncomingMessage, type ServerResponse } from "node:http"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { LIMITS } from "./policy.ts"
import type { Fetcher } from "./readers/http.ts"
import { createService, type FactlineService } from "./service.ts"

const webRoot = fileURLToPath(new URL("../web/", import.meta.url))

const files: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.css": { file: "app.css", type: "text/css; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
}

export type RunningServer = {
  port: number
  close: () => Promise<void>
}

export function startServer(options: {
  port: number
  host?: string
  dbPath: string
  fetcher?: Fetcher
  now?: () => Date
}): Promise<RunningServer> {
  const service = createService({ dbPath: options.dbPath, fetcher: options.fetcher, now: options.now })
  const server = createServer((request, response) => {
    void handle(service, request, response)
  })
  const host = options.host ?? "127.0.0.1"
  return new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(options.port, host, () => {
      const address = server.address()
      const port = typeof address === "object" && address ? address.port : options.port
      resolve({
        port,
        close: () =>
          new Promise((done, fail) => {
            service.close()
            server.close((error) => (error ? fail(error) : done()))
          }),
      })
    })
  })
}

async function handle(service: FactlineService, request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? "/", "http://127.0.0.1")
  try {
    if (request.method !== "GET") return send(response, 405, { error: "method_not_allowed" })
    if (url.pathname === "/api/v1/timeline") return sendTimeline(service, request, response, url)
    if (url.pathname === "/api/v1/recent") return send(response, 200, service.recent(), "no-store")
    const file = files[url.pathname]
    if (!file) return send(response, 404, { error: "not_found" })
    response.writeHead(200, {
      "content-type": file.type,
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "cache-control": "no-cache",
    })
    response.end(readFileSync(join(webRoot, file.file)))
  } catch (error) {
    console.error(error instanceof Error ? error.message : "request failed")
    if (!response.headersSent) send(response, 500, { error: "internal" })
  }
}

async function sendTimeline(
  service: FactlineService,
  request: IncomingMessage,
  response: ServerResponse,
  url: URL,
): Promise<void> {
  const result = await service.timeline(
    url.searchParams.get("name") ?? "",
    url.searchParams.get("version") ?? "",
    request.socket.remoteAddress ?? "unknown",
  )
  if (result.status === 200) {
    send(response, 200, result.timeline, `public, max-age=${LIMITS.browserMaxAgeSeconds}`)
    return
  }
  send(response, result.status, { error: result.error }, "no-store")
}

function send(response: ServerResponse, status: number, body: unknown, cache = "no-store"): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": cache,
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  })
  response.end(JSON.stringify(body))
}
