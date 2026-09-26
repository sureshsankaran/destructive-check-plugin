/**
 * Dual OpenCode v1 + v2 entrypoint.
 *
 * OpenCode picks the entrypoint it understands:
 * - OpenCode 1.18.29+ reads the object form and calls `server` (classic v1 API)
 * - OpenCode 2.x reads the object form and calls `setup` (@opencode/plugin API)
 *
 * Both entrypoints share the same detection logic in ./detect.js — only the
 * hook registration and payload shapes differ between generations.
 *
 * Minimum versions: OpenCode 1.18.29 for the v1 path, OpenCode 2.0.0 for v2.
 */

import v1Plugin from "./v1.js"
import { setup as v2Setup } from "./v2.js"

export { v1Plugin, v2Setup }
export { checkCommand, isDangerousPath, getSeverity, getCategoryLabel } from "./detect.js"
export type { DestructiveMatch, Stats } from "./detect.js"

export default {
  id: "opencode-destructive-check",
  /** OpenCode v1 (1.18.29+) entrypoint */
  server: v1Plugin,
  /** OpenCode 2.x entrypoint */
  setup: v2Setup,
}
