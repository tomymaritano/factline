import { HOOK_NAMES, type HookName, type HookSet, type ShortCommand } from "./types.ts"

export type HookChange = "added" | "removed" | "modified" | "unchanged"

export type HookDiffRow = {
  hook: HookName
  change: HookChange
  command: ShortCommand | null
  previousCommand: ShortCommand | null
}

export function diffHooks(
  current: HookSet,
  previous: HookSet | null,
): { baseline: "predecessor" | "none"; differs: boolean; hooks: HookDiffRow[] } {
  if (!previous) {
    return {
      baseline: "none",
      differs: false,
      hooks: HOOK_NAMES.map((hook) => ({
        hook,
        change: "unchanged" as const,
        command: current[hook],
        previousCommand: null,
      })),
    }
  }

  const hooks = HOOK_NAMES.map((hook) => {
    const command = current[hook]
    const previousCommand = previous[hook]
    let change: HookChange = "unchanged"
    if (!previousCommand && command) change = "added"
    else if (previousCommand && !command) change = "removed"
    else if (previousCommand && command && previousCommand.sha256 !== command.sha256) change = "modified"
    return { hook, change, command, previousCommand }
  })

  return {
    baseline: "predecessor",
    differs: hooks.some((hook) => hook.change !== "unchanged"),
    hooks,
  }
}
