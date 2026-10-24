import { serve } from "@hono/node-server"
import { Hono } from "hono"
import { pathToFileURL } from "node:url"
import { createApp } from "./routes.ts"
import { createService, type FactlineService } from "./service.ts"

const port = Number(process.env.PORT ?? 8080)
const host = process.env.HOST ?? "127.0.0.1"

let service: FactlineService | undefined

function getService(): FactlineService {
  if (!service) {
    const dbPath = process.env.FACTLINE_DB ?? (process.env.VERCEL ? "/tmp/factline.db" : "factline.db")
    service = createService({ dbPath })
  }
  return service
}

const app: Hono = createApp(getService)
export default app

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href
if (isMain && !process.env.VERCEL) {
  serve({ fetch: app.fetch, port, hostname: host }, (info) => {
    console.log(`factline listening on http://${host}:${info.port}`)
  })
}
