import { startServer } from "./http.ts"

const port = Number(process.env.PORT ?? 8080)
const dbPath = process.env.FACTLINE_DB ?? "factline.db"
const host = process.env.HOST ?? "127.0.0.1"

const server = await startServer({ port, host, dbPath })
console.log(`factline listening on http://${host}:${server.port}`)
