import { serve } from "@hono/node-server"
import type { ServerType } from "@hono/node-server"
import { createApp } from "./routes.ts"
import type { Fetcher } from "./readers/http.ts"
import { createService } from "./service.ts"

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
  const app = createApp(() => service)
  let server: ServerType
  return new Promise((resolve, reject) => {
    server = serve(
      {
        fetch: app.fetch,
        port: options.port,
        hostname: options.host ?? "127.0.0.1",
      },
      (info) => {
        resolve({
          port: info.port,
          close: () =>
            new Promise((done, fail) => {
              service.close()
              server.close((error) => (error ? fail(error) : done()))
            }),
        })
      },
    )
    server.once("error", reject)
  })
}
