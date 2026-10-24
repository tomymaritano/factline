import { createHash } from "node:crypto"
import type { ShortCommand } from "./types.ts"

export const COMMAND_PREFIX_CODE_POINTS = 160

export function projectCommand(value: unknown): ShortCommand | null {
  if (typeof value !== "string" || value.length === 0) return null
  const points = Array.from(value)
  const truncated = points.length > COMMAND_PREFIX_CODE_POINTS
  return {
    prefix: truncated ? points.slice(0, COMMAND_PREFIX_CODE_POINTS).join("") : value,
    truncated,
    sha256: createHash("sha256").update(value, "utf8").digest("hex"),
  }
}
