import { analyzeCommand } from "./command.ts"
import type { CommandAnalysis } from "./command.ts"
import { credentialPathHit, globToRegExp, isTemplatePath, normalizePath, redactSecrets, scanSecrets } from "./policy.ts"
import type { Decision, Severity } from "./policy.ts"

export interface GuardRules {
  read_credential: Decision
  credential_egress: Decision
  write_credential: Decision
  deny_path: Decision
  dangerous_flag: Decision
  destructive: Decision
}

export interface GuardConfig {
  mode: "learn" | "enforce"
  audit: string | null
  allowPaths: string[]
  extraDenyPaths: string[]
  egressAllow: string[]
  maskEnv: boolean
  rules: GuardRules
}

export interface Verdict {
  rule: string
  label: string
  intended: Decision
  decision: Decision
  severity: Severity
  reason: string
  target: string
  signals: string[]
}

export const DEFAULT_CONFIG: GuardConfig = {
  mode: "enforce",
  audit: ".opencode/guard-audit.jsonl",
  allowPaths: ["**/.env.example", "**/.env.sample", "**/.env.template"],
  extraDenyPaths: [],
  egressAllow: [],
  maskEnv: false,
  rules: {
    read_credential: "deny",
    credential_egress: "deny",
    write_credential: "deny",
    deny_path: "deny",
    dangerous_flag: "deny",
    destructive: "ask"
  }
}

const READ_TOOLS = new Set(["read", "grep", "glob", "list", "ls", "view", "open", "search"])
const WRITE_TOOLS = new Set(["write", "edit", "patch", "multiedit", "apply_patch", "create"])
const SHELL_TOOLS = new Set(["bash", "shell", "sh", "terminal"])
const PATH_KEYS = ["filePath", "file_path", "path", "file", "target", "destination", "pattern"]

function pickPaths(args: Record<string, unknown> | undefined): string[] {
  if (!args) return []
  const out: string[] = []
  for (const key of PATH_KEYS) {
    const value = args[key]
    if (typeof value === "string" && value.trim()) out.push(value.trim())
  }
  return out
}

function preview(text: string, limit = 160): string {
  const flat = text.replace(/\s+/g, " ").trim()
  const redacted = redactSecrets(flat).text
  return redacted.length > limit ? redacted.slice(0, limit) + "..." : redacted
}

function allow(reason: string, signals: string[] = []): Verdict {
  return {
    rule: "G000",
    label: "no rule matched",
    intended: "allow",
    decision: "allow",
    severity: "low",
    reason,
    target: "",
    signals
  }
}

function decide(
  cfg: GuardConfig,
  rule: string,
  label: string,
  intended: Decision,
  severity: Severity,
  reason: string,
  target: string,
  signals: string[]
): Verdict {
  const enforced = cfg.mode === "learn" && intended !== "allow" ? "allow" : intended
  const note = cfg.mode === "learn" && intended !== "allow" ? " (learn mode: not enforced)" : ""
  return {
    rule,
    label,
    intended,
    decision: enforced,
    severity,
    reason: reason + note,
    target,
    signals
  }
}

export function evaluateCommand(command: string, cfg: GuardConfig): Verdict {
  const analysis: CommandAnalysis = analyzeCommand(command)
  const target = preview(command)

  if (analysis.dangerousFlags.length > 0) {
    return decide(
      cfg,
      "G005",
      "dangerous permission bypass",
      cfg.rules.dangerous_flag,
      "critical",
      "flag bypasses the agent permission model: " + analysis.dangerousFlags.join(", "),
      target,
      analysis.signals
    )
  }

  const outsideHosts = analysis.egressHosts.filter((host) => {
    if (cfg.egressAllow.length === 0) return true
    return !cfg.egressAllow.some((allowed) => host === allowed || host.endsWith("." + allowed))
  })

  const exfil = (analysis.readsCredential || analysis.dumpsEnv || analysis.secretEnvRefs.length > 0) && analysis.egress
  const exfilOutside = exfil && (outsideHosts.length > 0 || analysis.egressHosts.length === 0)

  if (exfilOutside) {
    const why = analysis.readsCredential
      ? "reads " + analysis.credentialTargets.join(", ") + " and sends it out"
      : analysis.dumpsEnv
        ? "dumps the whole environment and sends it out"
        : "expands " + analysis.secretEnvRefs.join(", ") + " and sends it out"
    return decide(cfg, "G003", "credential exfiltration", cfg.rules.credential_egress, "critical", why, target, analysis.signals)
  }

  if (analysis.readsCredential) {
    return decide(
      cfg,
      "G004",
      "credential file access",
      cfg.rules.read_credential,
      "high",
      "touches " + analysis.credentialTargets.join(", ") + " without an outbound channel",
      target,
      analysis.signals
    )
  }

  if (analysis.dumpsEnv) {
    return decide(cfg, "G008", "environment dump", cfg.rules.read_credential, "high", "prints every environment variable to the context", target, analysis.signals)
  }

  if (exfil) {
    return decide(
      cfg,
      "G009",
      "egress to an allowlisted host",
      "allow",
      "medium",
      "credential-shaped data leaves toward a trusted destination: " + analysis.egressHosts.join(", "),
      target,
      analysis.signals
    )
  }

  if (analysis.destructive) {
    return decide(
      cfg,
      "G006",
      "destructive command",
      cfg.rules.destructive,
      "medium",
      analysis.destructiveReason ?? "destructive command",
      target,
      analysis.signals
    )
  }

  if (analysis.signals.includes("template-path")) {
    return decide(
      cfg,
      "G010",
      "template path allowlisted",
      "allow",
      "low",
      "only a template, never live credentials",
      target,
      analysis.signals
    )
  }

  return allow("command has no credential or egress signal", analysis.signals)
}

export function evaluateToolBefore(tool: string, args: Record<string, unknown> | undefined, cfg: GuardConfig): Verdict {
  const paths = pickPaths(args)

  if (SHELL_TOOLS.has(tool)) {
    const command = typeof args?.command === "string" ? args.command : ""
    if (!command) return allow("empty command")
    return evaluateCommand(command, cfg)
  }

  for (const candidate of paths) {
    const normalized = normalizePath(candidate)
    for (const glob of cfg.extraDenyPaths) {
      if (globToRegExp(glob).test(normalized)) {
        return decide(
          cfg,
          "G007",
          "deny-listed path",
          cfg.rules.deny_path,
          "high",
          "path matches extra_deny_paths rule: " + glob,
          preview(candidate),
          []
        )
      }
    }
  }

  if (READ_TOOLS.has(tool)) {
    for (const candidate of paths) {
      if (isTemplatePath(candidate)) {
        return decide(cfg, "G010", "template path allowlisted", "allow", "low", "only a template, never live credentials", preview(candidate), [])
      }
      const hit = credentialPathHit(candidate, cfg.allowPaths)
      if (hit) {
        return decide(
          cfg,
          "G001",
          "credential file read",
          cfg.rules.read_credential,
          "high",
          "tool " + tool + " targets " + hit.label,
          preview(candidate),
          ["credential-path:" + hit.id]
        )
      }
    }
  }

  if (WRITE_TOOLS.has(tool)) {
    for (const candidate of paths) {
      const hit = credentialPathHit(candidate, cfg.allowPaths)
      if (hit) {
        return decide(
          cfg,
          "G002",
          "credential file write",
          cfg.rules.write_credential,
          "critical",
          "tool " + tool + " would overwrite " + hit.label,
          preview(candidate),
          ["credential-path:" + hit.id]
        )
      }
    }
  }

  return allow("no rule matched", paths.length > 0 ? ["paths:" + paths.length] : [])
}

export interface RedactionResult {
  output: string
  hits: { id: string; label: string; preview: string }[]
  changed: boolean
}

export function evaluateToolAfter(output: string): RedactionResult {
  const hits = scanSecrets(output)
  if (hits.length === 0) return { output, hits, changed: false }
  const redacted = redactSecrets(output)
  return { output: redacted.text, hits, changed: redacted.text !== output }
}

export function evaluateShellEnv(env: Record<string, string>, cfg: GuardConfig): { env: Record<string, string>; masked: string[] } {
  const next: Record<string, string> = { ...env, GUARD_ACTIVE: "1" }
  const masked: string[] = []
  if (!cfg.maskEnv) return { env: next, masked }

  for (const key of Object.keys(next)) {
    if (/(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)$/i.test(key)) {
      next[key] = "[GUARDED:" + key + "]"
      masked.push(key)
    }
  }
  return { env: next, masked }
}
