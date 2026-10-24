export class UpstreamGate {
  private active = 0
  private queue: Array<() => void> = []
  private readonly max: number

  constructor(max: number) {
    this.max = max
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire()
    try {
      return await fn()
    } finally {
      this.release()
    }
  }

  private acquire(): Promise<void> {
    if (this.active < this.max) {
      this.active += 1
      return Promise.resolve()
    }
    return new Promise((resolve) => {
      this.queue.push(() => {
        this.active += 1
        resolve()
      })
    })
  }

  private release(): void {
    this.active -= 1
    const next = this.queue.shift()
    if (next) next()
  }
}

export class MissBudget {
  private hits = new Map<string, number[]>()
  private readonly limit: number
  private readonly windowMs: number

  constructor(limit: number, windowMs: number) {
    this.limit = limit
    this.windowMs = windowMs
  }

  allow(ip: string, nowMs: number): boolean {
    const start = nowMs - this.windowMs
    const recent = (this.hits.get(ip) ?? []).filter((hit) => hit > start)
    if (recent.length >= this.limit) {
      this.hits.set(ip, recent)
      return false
    }
    recent.push(nowMs)
    this.hits.set(ip, recent)
    return true
  }
}

export class SingleFlight {
  private flights = new Map<string, Promise<unknown>>()

  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const existing = this.flights.get(key)
    if (existing) return existing as Promise<T>
    const promise = fn().finally(() => {
      this.flights.delete(key)
    })
    this.flights.set(key, promise)
    return promise
  }
}
