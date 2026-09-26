/**
 * OpenCode v1 plugin entrypoint.
 *
 * Preserves the behavior of the 1.x releases: detection runs through the
 * shared ./detect.js module, and the hooks registered are the classic v1
 * hooks ("tool.execute.before", "permission.ask", "tool.execute.after").
 */

import type { Plugin } from "@opencode-ai/plugin"
import {
  DESTRUCTIVE_PATTERNS,
  DANGEROUS_PATHS,
  checkCommand,
  getCategoryLabel,
  isDangerousPath,
  getStats,
  globalStats,
} from "./detect.js"

/**
 * Destructive Command Check Plugin
 */
async function destructiveCheck(_input: {
  client: any
  project: any
  worktree: string
  directory: string
  serverUrl: any
  $: any
}) {
  return {
    // Tool for checking plugin status
    tool: {
      "destructive-check-status": {
        description: "Get the status of the destructive command check plugin",
        args: {},
        async execute(_args: {}, ctx: { sessionID: string }) {
          const stats = getStats(ctx.sessionID)
          return JSON.stringify(
            {
              enabled: true,
              session: {
                id: ctx.sessionID,
                ...stats,
              },
              globalStats: globalStats,
              patterns: {
                categories: Object.keys(DESTRUCTIVE_PATTERNS),
                total: Object.values(DESTRUCTIVE_PATTERNS).flat().length,
              },
              dangerousPaths: DANGEROUS_PATHS.length,
            },
            null,
            2,
          )
        },
      },
    },

    // Check before any tool executes - logs warnings for awareness
    async ["tool.execute.before"](
      hookInput: { tool: string; sessionID: string; callID: string },
      output: { args: Record<string, unknown> },
    ): Promise<void> {
      const stats = getStats(hookInput.sessionID)
      stats.checked++
      globalStats.checked++

      const tool = hookInput.tool.toLowerCase()
      const args = output.args

      // Check bash/shell commands
      if (tool === "bash" || tool === "shell" || tool === "execute") {
        const command = (args?.command as string) || ""
        if (command) {
          const match = checkCommand(command)
          if (match) {
            console.warn(
              `[destructive-check] Detected ${match.severity.toUpperCase()} destructive command - permission will be requested`,
            )
            console.warn(`  Category: ${match.category}`)
            console.warn(`  Command: ${match.command.slice(0, 100)}${match.command.length > 100 ? "..." : ""}`)
          }
        }
      }

      // Check file write/delete operations
      if (tool === "write" || tool === "edit" || tool === "delete" || tool === "remove") {
        const filePath = (args?.filePath as string) || (args?.path as string) || ""
        if (filePath && isDangerousPath(filePath)) {
          console.warn(`[destructive-check] Dangerous file operation detected - permission will be requested`)
          console.warn(`  Tool: ${tool}`)
          console.warn(`  Path: ${filePath}`)
        }
      }

      // Check git operations via tool
      if (tool === "git") {
        const subcommand = (args?.subcommand as string) || (args?.command as string) || ""
        const fullCommand = `git ${subcommand}`
        const match = checkCommand(fullCommand)
        if (match) {
          console.warn(`[destructive-check] Destructive git operation detected - permission will be requested`)
          console.warn(`  Severity: ${match.severity.toUpperCase()}`)
          console.warn(`  Command: ${fullCommand}`)
        }
      }
    },

    // Permission hook to require user confirmation for destructive operations
    async ["permission.ask"](
      input: {
        id: string
        // Old permission system uses 'type', new system uses 'permission'
        type?: string
        permission?: string
        pattern?: string | string[]
        patterns?: string[]
        sessionID: string
        messageID?: string
        callID?: string
        title?: string
        metadata: Record<string, unknown>
        time?: { created: number }
      },
      output: { status: "ask" | "deny" | "allow"; metadata?: Record<string, unknown> },
    ): Promise<void> {
      const stats = getStats(input.sessionID)

      // Get permission type from either old or new system
      const permissionType = input.permission || input.type || ""

      // Check if this is a bash/command execution permission
      if (permissionType === "bash" || permissionType === "command" || permissionType === "shell") {
        // Get commands from patterns (new system) or metadata/title (old system)
        const patterns =
          input.patterns || (Array.isArray(input.pattern) ? input.pattern : input.pattern ? [input.pattern] : [])

        // Check each pattern individually for destructive commands
        for (const pattern of patterns) {
          const match = checkCommand(pattern)
          if (match) {
            stats.permissionsRequested++
            globalStats.permissionsRequested++
            stats.lastMatch = match

            // Add metadata to the permission request for UI display
            const severityEmoji = match.severity === "critical" ? "🔴" : match.severity === "high" ? "🟠" : "🟡"
            const categoryLabel = getCategoryLabel(match.category)

            // Enhance metadata with destructive command information
            if (!output.metadata) output.metadata = {}
            output.metadata.destructive = {
              severity: match.severity,
              category: match.category,
              categoryLabel,
              command: pattern,
              warning: `${severityEmoji} ${match.severity.toUpperCase()}: ${categoryLabel}`,
            }

            console.warn(
              `[destructive-check] ${severityEmoji} ${match.severity.toUpperCase()} destructive command detected`,
            )
            console.warn(`  Category: ${categoryLabel}`)
            console.warn(`  Command: ${pattern.slice(0, 100)}${pattern.length > 100 ? "..." : ""}`)
            console.warn(`  ⚠️  This operation could cause data loss or system damage!`)

            // Ask for permission for all severity levels
            output.status = "ask"
            return
          }
        }

        // Also check joined patterns and metadata as fallback
        const command = patterns.join(" ") || (input.metadata?.command as string) || input.title || ""
        if (command && patterns.length === 0) {
          const match = checkCommand(command)
          if (match) {
            stats.permissionsRequested++
            globalStats.permissionsRequested++
            stats.lastMatch = match

            // Add metadata to the permission request for UI display
            const severityEmoji = match.severity === "critical" ? "🔴" : match.severity === "high" ? "🟠" : "🟡"
            const categoryLabel = getCategoryLabel(match.category)

            // Enhance metadata with destructive command information
            if (!output.metadata) output.metadata = {}
            output.metadata.destructive = {
              severity: match.severity,
              category: match.category,
              categoryLabel,
              command,
              warning: `${severityEmoji} ${match.severity.toUpperCase()}: ${categoryLabel}`,
            }

            console.warn(
              `[destructive-check] ${severityEmoji} ${match.severity.toUpperCase()} destructive command detected`,
            )
            console.warn(`  Category: ${categoryLabel}`)
            console.warn(`  Command: ${command.slice(0, 100)}${command.length > 100 ? "..." : ""}`)
            console.warn(`  ⚠️  This operation could cause data loss or system damage!`)

            // Ask for permission for all severity levels
            output.status = "ask"
            return
          }
        }
      }

      // Check file operations
      if (permissionType === "write" || permissionType === "edit" || permissionType === "delete") {
        const patterns =
          input.patterns || (Array.isArray(input.pattern) ? input.pattern : input.pattern ? [input.pattern] : [])
        for (const p of patterns) {
          if (isDangerousPath(p)) {
            stats.permissionsRequested++
            globalStats.permissionsRequested++

            // Add metadata for dangerous file operations
            if (!output.metadata) output.metadata = {}
            output.metadata.destructive = {
              severity: "critical",
              category: "file",
              categoryLabel: "Dangerous File Operation",
              path: p,
              warning: "🔴 CRITICAL: Dangerous file operation",
            }

            console.warn(`[destructive-check] 🔴 CRITICAL: Dangerous file operation detected`)
            console.warn(`  Operation: ${permissionType}`)
            console.warn(`  Path: ${p}`)
            console.warn(`  ⚠️  This operation could cause data loss or system damage!`)

            // Ask for permission for dangerous file operations
            output.status = "ask"
            return
          }
        }
      }
    },

    // After tool execution - log results for destructive operations
    async ["tool.execute.after"](
      hookInput: { tool: string; sessionID: string; callID: string },
      result: { title: string; output: string; metadata: Record<string, unknown> },
    ): Promise<void> {
      const tool = hookInput.tool.toLowerCase()

      // Log completion of potentially dangerous operations
      if (tool === "bash" || tool === "shell") {
        const output = result.output || ""
        // Check for error messages that might indicate dangerous operation attempted
        if (
          output.includes("Permission denied") ||
          output.includes("Operation not permitted") ||
          output.includes("cannot remove") ||
          output.includes("rm: refusing")
        ) {
          console.log(`[destructive-check] Dangerous operation was blocked by system`)
        }
      }
    },
  }
}

export default destructiveCheck
