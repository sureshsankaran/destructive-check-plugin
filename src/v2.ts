/**
 * OpenCode v2 plugin entrypoint.
 *
 * Full port of the v1 plugin to the OpenCode 2.x plugin API
 * (@opencode/plugin). Detection logic is shared with v1 through
 * ./detect.js — the only thing that changes is how hooks are registered
 * and how their payloads are shaped.
 *
 * v1 -> v2 hook mapping:
 *   "tool.execute.before" -> ctx.tool.hook("execute.before")
 *   "tool.execute.after"  -> ctx.tool.hook("execute.after")
 *   "permission.ask"      -> ctx.permission.hook("evaluate")
 *                            (set event.effect = "ask" — this is the direct
 *                             v2 equivalent of v1's output.status = "ask")
 */

import { Plugin } from "@opencode/plugin"
import {
  DESTRUCTIVE_PATTERNS,
  DANGEROUS_PATHS,
  checkCommand,
  getCategoryLabel,
  isDangerousPath,
  getStats,
  globalStats,
} from "./detect.js"

const PLUGIN_ID = "opencode-destructive-check"

function truncate(text: string, max = 100): string {
  return text.length > max ? text.slice(0, max) + "..." : text
}

function severityEmoji(severity: string): string {
  return severity === "critical" ? "🔴" : severity === "high" ? "🟠" : "🟡"
}

function isBashLikeAction(action: string): boolean {
  return action === "bash" || action === "command" || action === "shell" || action === "exec" || action === "execute"
}

function isFileOpAction(action: string): boolean {
  return action === "write" || action === "edit" || action === "delete" || action === "remove"
}

/**
 * Normalize a tool result output to a string for inspection.
 * In v2, result.output can be a string OR a structured object depending
 * on the tool — never assume it's a string, and never let normalization
 * throw inside a hook.
 */
function normalizeOutput(output: unknown): string {
  if (typeof output === "string") return output
  if (output === null || output === undefined) return ""
  try {
    return JSON.stringify(output)
  } catch {
    return String(output)
  }
}

export async function setup(ctx: Plugin.Context): Promise<void> {
  // Warn (only) before a tool runs when its input looks destructive.
  // Gating happens in permission.evaluate below — same split as v1.
  await ctx.tool.hook("execute.before", async (event) => {
    const stats = getStats(event.sessionID)
    stats.checked++
    globalStats.checked++

    const tool = event.tool.toLowerCase()
    const input = (event.input ?? {}) as Record<string, unknown>

    // Check bash/shell commands
    if (tool === "bash" || tool === "shell" || tool === "execute") {
      const command = typeof input.command === "string" ? input.command : ""
      if (command) {
        const match = checkCommand(command)
        if (match) {
          console.warn(
            `[destructive-check] Detected ${match.severity.toUpperCase()} destructive command - permission will be requested`,
          )
          console.warn(`  Category: ${match.category}`)
          console.warn(`  Command: ${truncate(match.command)}`)
        }
      }
    }

    // Check file write/delete operations
    if (tool === "write" || tool === "edit" || tool === "delete" || tool === "remove") {
      const filePath =
        (typeof input.filePath === "string" ? input.filePath : "") ||
        (typeof input.path === "string" ? input.path : "")
      if (filePath && isDangerousPath(filePath)) {
        console.warn(`[destructive-check] Dangerous file operation detected - permission will be requested`)
        console.warn(`  Tool: ${tool}`)
        console.warn(`  Path: ${filePath}`)
      }
    }

    // Check git operations via tool
    if (tool === "git") {
      const subcommand =
        (typeof input.subcommand === "string" ? input.subcommand : "") ||
        (typeof input.command === "string" ? input.command : "")
      const fullCommand = `git ${subcommand}`
      const match = checkCommand(fullCommand)
      if (match) {
        console.warn(`[destructive-check] Destructive git operation detected - permission will be requested`)
        console.warn(`  Severity: ${match.severity.toUpperCase()}`)
        console.warn(`  Command: ${fullCommand}`)
      }
    }
  })

  // Log-only after hook. Wrapped defensively: a logging hook must never
  // break tool execution, whatever shape result.output takes.
  await ctx.tool.hook("execute.after", async (event) => {
    try {
      const tool = event.tool.toLowerCase()
      if (tool !== "bash" && tool !== "shell") return
      if (event.status !== "completed") return

      const output = normalizeOutput(event.result?.output)
      if (
        output.includes("Permission denied") ||
        output.includes("Operation not permitted") ||
        output.includes("cannot remove") ||
        output.includes("rm: refusing")
      ) {
        console.log(`[destructive-check] Dangerous operation was blocked by system`)
      }
    } catch {
      // Never propagate from a logging hook.
    }
  })

  // Permission gate. This is the v2 equivalent of v1's "permission.ask":
  // instead of setting output.status = "ask", mutate event.effect = "ask".
  // event.message is surfaced in the permission prompt UI.
  await ctx.permission.hook("evaluate", async (event) => {
    const stats = getStats(event.sessionID)
    const action = (event.action ?? "").toLowerCase()
    const resources = Array.isArray(event.resources) ? event.resources : []

    const checkCommands = isBashLikeAction(action) || !isFileOpAction(action)
    const checkPaths = isFileOpAction(action) || !isBashLikeAction(action)

    for (const resource of resources) {
      if (typeof resource !== "string" || !resource) continue

      if (checkCommands) {
        const match = checkCommand(resource)
        if (match) {
          stats.permissionsRequested++
          globalStats.permissionsRequested++
          stats.lastMatch = match

          const emoji = severityEmoji(match.severity)
          const categoryLabel = getCategoryLabel(match.category)

          console.warn(`[destructive-check] ${emoji} ${match.severity.toUpperCase()} destructive command detected`)
          console.warn(`  Category: ${categoryLabel}`)
          console.warn(`  Command: ${truncate(resource)}`)
          console.warn(`  ⚠️  This operation could cause data loss or system damage!`)

          event.effect = "ask"
          event.message = `${emoji} ${match.severity.toUpperCase()}: ${categoryLabel} — ${truncate(resource)}`
          return
        }
      }

      if (checkPaths && isDangerousPath(resource)) {
        stats.permissionsRequested++
        globalStats.permissionsRequested++

        console.warn(`[destructive-check] 🔴 CRITICAL: Dangerous file operation detected`)
        console.warn(`  Operation: ${action}`)
        console.warn(`  Path: ${resource}`)
        console.warn(`  ⚠️  This operation could cause data loss or system damage!`)

        event.effect = "ask"
        event.message = `🔴 CRITICAL: Dangerous file operation (${action}) — ${truncate(resource)}`
        return
      }
    }
  })

  // Status tool (parity with the v1 "destructive-check-status" tool).
  await ctx.tool.transform((tools) => {
    tools.add({
      name: "destructive-check-status",
      description: "Get the status of the destructive command check plugin",
      input: { type: "object", properties: {}, additionalProperties: false },
      execute: async (_input, context) => {
        const stats = getStats(context.sessionID)
        const text = JSON.stringify(
          {
            enabled: true,
            api: "v2",
            session: {
              id: context.sessionID,
              ...stats,
            },
            global: globalStats,
            patterns: {
              categories: Object.keys(DESTRUCTIVE_PATTERNS),
              total: Object.values(DESTRUCTIVE_PATTERNS).flat().length,
            },
            dangerousPaths: DANGEROUS_PATHS.length,
          },
          null,
          2,
        )
        return { content: text }
      },
    })
  })
}

export default Plugin.define({
  id: PLUGIN_ID,
  setup,
})
