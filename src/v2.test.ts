/**
 * Wiring tests for the OpenCode v2 entrypoint (src/v2.ts).
 *
 * These verify the v2 hook *wiring* — that setup() registers the right
 * hooks and that the permission.evaluate handler (the v2 equivalent of
 * v1's permission.ask) gates destructive commands by setting
 * event.effect = "ask" — using a mock plugin context, without a running
 * OpenCode instance.
 */

import { describe, test, expect } from "bun:test"
import { setup } from "./v2.js"
import indexDefault from "./index.js"
import v1Plugin from "./v1.js"

type HookHandler = (event: any) => Promise<void> | void

function createMockContext() {
  const hooks: Record<string, HookHandler> = {}
  const addedTools: any[] = []
  const ctx: any = {
    tool: {
      hook: async (name: string, handler: HookHandler) => {
        hooks[`tool:${name}`] = handler
        return { dispose: async () => {} }
      },
      transform: async (cb: (tools: any) => void) => {
        cb({ add: (tool: any) => addedTools.push(tool) })
        return { dispose: async () => {} }
      },
    },
    permission: {
      hook: async (name: string, handler: HookHandler) => {
        hooks[`permission:${name}`] = handler
        return { dispose: async () => {} }
      },
    },
  }
  return { ctx, hooks, addedTools }
}

describe("v2 entrypoint shape", () => {
  test("default export is the dual v1+v2 definition", () => {
    expect((indexDefault as any).id).toBe("opencode-destructive-check")
    expect(typeof (indexDefault as any).server).toBe("function")
    expect(typeof (indexDefault as any).setup).toBe("function")
  })

  test("v1 server export is the classic plugin function", () => {
    expect(typeof v1Plugin).toBe("function")
    expect((indexDefault as any).server).toBe(v1Plugin)
  })

  test("setup registers all v2 hooks and the status tool", async () => {
    const { ctx, hooks, addedTools } = createMockContext()
    await setup(ctx)
    expect(typeof hooks["tool:execute.before"]).toBe("function")
    expect(typeof hooks["tool:execute.after"]).toBe("function")
    expect(typeof hooks["permission:evaluate"]).toBe("function")
    expect(addedTools.map((t) => t.name)).toContain("destructive-check-status")
  })
})

describe("permission.evaluate (v2 equivalent of permission.ask)", () => {
  test("asks on destructive bash command", async () => {
    const { ctx, hooks } = createMockContext()
    await setup(ctx)
    const event: any = {
      sessionID: "s1",
      action: "bash",
      resources: ["rm -rf / --no-preserve-root"],
      effect: "allow",
    }
    await hooks["permission:evaluate"](event)
    expect(event.effect).toBe("ask")
    expect(typeof event.message).toBe("string")
    expect(event.message.length).toBeGreaterThan(0)
  })

  test("leaves safe commands alone", async () => {
    const { ctx, hooks } = createMockContext()
    await setup(ctx)
    const event: any = {
      sessionID: "s1",
      action: "bash",
      resources: ["ls -la /tmp"],
      effect: "allow",
    }
    await hooks["permission:evaluate"](event)
    expect(event.effect).toBe("allow")
  })

  test("asks on dangerous file path for write actions", async () => {
    const { ctx, hooks } = createMockContext()
    await setup(ctx)
    const event: any = {
      sessionID: "s1",
      action: "write",
      resources: ["/etc/passwd"],
      effect: "allow",
    }
    await hooks["permission:evaluate"](event)
    expect(event.effect).toBe("ask")
  })

  test("asks on git push --force", async () => {
    const { ctx, hooks } = createMockContext()
    await setup(ctx)
    const event: any = {
      sessionID: "s1",
      action: "bash",
      resources: ["git push --force origin main"],
      effect: "allow",
    }
    await hooks["permission:evaluate"](event)
    expect(event.effect).toBe("ask")
  })
})

describe("execute.after output normalization", () => {
  test("does not throw when result.output is an object", async () => {
    const { ctx, hooks } = createMockContext()
    await setup(ctx)
    const event: any = {
      tool: "bash",
      sessionID: "s1",
      status: "completed",
      result: { output: { stdout: "ok", exitCode: 0 } },
    }
    await hooks["tool:execute.after"](event) // must not throw
  })

  test("handles missing result gracefully", async () => {
    const { ctx, hooks } = createMockContext()
    await setup(ctx)
    await hooks["tool:execute.after"]({ tool: "bash", sessionID: "s1", status: "completed" })
  })
})

describe("destructive-check-status tool (v2)", () => {
  test("returns JSON status for the session", async () => {
    const { ctx, addedTools } = createMockContext()
    await setup(ctx)
    const tool = addedTools.find((t) => t.name === "destructive-check-status")
    const result = await tool.execute({}, { sessionID: "s1" })
    const parsed = JSON.parse(result.content as string)
    expect(parsed.enabled).toBe(true)
    expect(parsed.api).toBe("v2")
    expect(parsed.session.id).toBe("s1")
    expect(parsed.patterns.total).toBeGreaterThan(0)
  })
})
