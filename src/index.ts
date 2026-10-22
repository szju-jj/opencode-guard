import { isAbsolute, join } from "node:path"
import { appendAudit } from "./audit.ts"
import { consumeApproval } from "./approvals.ts"
import { loadConfig } from "./config.ts"
import { define } from "./define.ts"
import { evaluateShellEnv, evaluateToolAfter, evaluateToolBefore } from "./engine.ts"
import type { GuardConfig, Verdict } from "./engine.ts"

export const APPROVALS_FILE = ".opencode/guard.approvals.json"

export interface GuardContext {
  directory: string
  config: GuardConfig
  auditPath: string | null
  approvalsPath: string
  session: string
}

export function createContext(directory: string, session = "local"): GuardContext {
  const config = loadConfig(directory)
  const auditPath = config.audit
    ? isAbsolute(config.audit)
      ? config.audit
      : join(directory, config.audit)
    : null
  return {
    directory,
    config,
    auditPath,
    approvalsPath: join(directory, APPROVALS_FILE),
    session
  }
}

function log(
  ctx: GuardContext,
  entry: {
    tool: string
    rule: string
    label: string
    intended: string
    decision: string
    severity: string
    target: string
    signals: string[]
  }
): void {
  if (!ctx.auditPath) return
  appendAudit(ctx.auditPath, { ...entry, session: ctx.session })
}

function formatBlock(verdict: Verdict): string {
  const head = `[guard:${verdict.rule}] ${verdict.label}`
  const body = verdict.target ? `${verdict.reason} | ${verdict.target}` : verdict.reason
  const hint =
    verdict.decision === "ask"
      ? `Approve once: npx opencode-guard approve ${verdict.rule}`
      : `Edit guard.yaml if this is intentional.`
  return `${head} — ${body}. ${hint}`
}

export function enforceBefore(ctx: GuardContext, tool: string, args: Record<string, any>): Verdict {
  const verdict = evaluateToolBefore(tool, args ?? {}, ctx.config)
  let decision = verdict.decision
  let note = ""

  if (decision === "ask" && consumeApproval(ctx.approvalsPath, verdict.rule)) {
    decision = "allow"
    note = " (one-time approval consumed)"
  }

  if (verdict.intended !== "allow" || decision !== "allow") {
    log(ctx, {
      tool,
      rule: verdict.rule,
      label: verdict.label,
      intended: verdict.intended,
      decision,
      severity: verdict.severity,
      target: verdict.target,
      signals: verdict.signals
    })
  }

  if (decision === "deny" || decision === "ask") {
    const error = new Error(formatBlock({ ...verdict, decision }))
    ;(error as Error & { verdict?: Verdict }).verdict = { ...verdict, decision }
    throw error
  }

  return { ...verdict, decision, reason: verdict.reason + note }
}

export function enforceAfter(ctx: GuardContext, tool: string, output: string): { output: string; changed: boolean } {
  const result = evaluateToolAfter(output)
  if (!result.changed) return { output, changed: false }

  log(ctx, {
    tool,
    rule: "G100",
    label: "secret leaked into tool output",
    intended: "redact",
    decision: "redact",
    severity: "high",
    target: tool + " <- " + result.hits.map((hit) => hit.label).join(", "),
    signals: result.hits.map((hit) => hit.id)
  })

  return { output: result.output, changed: true }
}

export const guardPlugin = define({
  id: "guard",
  async setup(context: Record<string, any>) {
    const directory = String(context.directory ?? process.cwd())
    const session = String(context.sessionID ?? "local")
    const ctx = createContext(directory, session)

    if (typeof context.tool?.hook === "function") {
      await context.tool.hook("execute.before", (event: any) => {
        enforceBefore(ctx, String(event.tool ?? ""), event.input ?? {})
      })

      await context.tool.hook("execute.after", (event: any) => {
        if (event.status !== "completed") return
        const raw = typeof event.result?.output === "string" ? event.result.output : ""
        if (!raw) return
        try {
          const result = enforceAfter(ctx, String(event.tool ?? ""), raw)
          if (result.changed && event.result) event.result.output = result.output
        } catch {
          return
        }
      })
    }

    if (typeof context.shell?.hook === "function") {
      await context.shell.hook("create.before", (event: any) => {
        const hardened = evaluateShellEnv(event.env ?? {}, ctx.config)
        event.env = hardened.env
      })
    }
  }
})

async function legacyServer(): Promise<Record<string, (input: any, output: any) => Promise<void>>> {
  const ctx = createContext(process.cwd(), "legacy")

  return {
    "tool.execute.before": async (input: any, output: any) => {
      enforceBefore(ctx, String(input?.tool ?? ""), output?.args ?? {})
    },
    "tool.execute.after": async (input: any, output: any) => {
      const raw = typeof output?.output === "string" ? output.output : ""
      if (!raw) return
      const result = enforceAfter(ctx, String(input?.tool ?? ""), raw)
      if (result.changed) output.output = result.output
    },
    "shell.env": async (_input: any, output: any) => {
      const hardened = evaluateShellEnv(output?.env ?? {}, ctx.config)
      output.env = hardened.env
    }
  }
}

// Dual export: OpenCode 2.x reads id + setup(), OpenCode 1.x calls server().
export default {
  ...guardPlugin,
  async server() {
    return legacyServer()
  }
}
