import { basename, credentialPathHit, isTemplatePath, looksLikeRandomToken } from "./policy.ts"

export interface Segment {
  raw: string
  argv: string[]
}

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical"

export interface CommandAnalysis {
  segments: Segment[]
  readsCredential: boolean
  credentialTargets: string[]
  egress: boolean
  egressHosts: string[]
  secretEnvRefs: string[]
  dumpsEnv: boolean
  dangerousFlags: string[]
  destructive: boolean
  destructiveReason: string | null
  risk: RiskLevel
  signals: string[]
}

const EGRESS_BINS = new Set([
  "curl",
  "wget",
  "nc",
  "ncat",
  "netcat",
  "ssh",
  "scp",
  "sftp",
  "ftp",
  "telnet",
  "socat",
  "rsync",
  "http",
  "https",
  "xh",
  "httpie",
  "aria2c"
])

const ENV_DUMP_BINS = new Set(["env", "printenv", "set"])

const DANGEROUS_FLAGS = [
  "--dangerously-skip-permissions",
  "--dangerously-bypass-approvals-and-sandbox",
  "--yolo",
  "--trust-all-tools",
  "--no-sandbox"
]

const SECRET_ENV_NAME = /(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|AUTH)/i

const DESTRUCTIVE: { re: RegExp; reason: string }[] = [
  {
    re: /\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(?:\/\s*$|\/\*|~(?:\/\S*)?\s*$|\*|\.\.)/,
    reason: "recursive delete of root, home or glob"
  },
  { re: /\bdrop\s+(?:table|database|schema)\b/i, reason: "SQL drop statement" },
  { re: /\bgit\s+push\b[^\n]*--force(?!-with-lease)/, reason: "force push" },
  { re: /\bmkfs(?:\.\w+)?\b/, reason: "filesystem format" },
  { re: /\bdd\s+[^\n]*of=\/dev\//, reason: "raw disk write" }
]

export function splitSegments(command: string): string[] {
  const out: string[] = []
  let buf = ""
  let quote: string | null = null

  for (let i = 0; i < command.length; i++) {
    const c = command[i]
    if (quote) {
      buf += c
      if (c === "\\" && quote === '"') {
        buf += command[++i] ?? ""
        continue
      }
      if (c === quote) quote = null
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      buf += c
      continue
    }
    if (c === "\\") {
      buf += c + (command[++i] ?? "")
      continue
    }
    if (c === "\n" || c === ";" || c === "|") {
      out.push(buf)
      buf = ""
      continue
    }
    if (c === "&" && command[i + 1] === "&") {
      out.push(buf)
      buf = ""
      i++
      continue
    }
    buf += c
  }
  out.push(buf)
  return out.map((s) => s.trim()).filter(Boolean)
}

export function tokenize(segment: string): string[] {
  const argv: string[] = []
  let buf = ""
  let quote: string | null = null
  let started = false

  for (let i = 0; i < segment.length; i++) {
    const c = segment[i]
    if (quote) {
      if (c === "\\" && quote === '"') {
        buf += segment[++i] ?? ""
        continue
      }
      if (c === quote) {
        quote = null
        continue
      }
      buf += c
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      started = true
      continue
    }
    if (c === "\\") {
      buf += segment[++i] ?? ""
      started = true
      continue
    }
    if (/\s/.test(c)) {
      if (buf || started) {
        argv.push(buf)
        buf = ""
        started = false
      }
      continue
    }
    buf += c
    started = true
  }
  if (buf || started) argv.push(buf)
  return argv
}

function cleanToken(token: string): string {
  return token.replace(/^[("'`]+/, "").replace(/[)"'`;,]+$/, "")
}

function extractHost(token: string): string | null {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) {
    try {
      return new URL(token).hostname
    } catch {
      return null
    }
  }
  const m = token.match(/^(?:[\w.-]+@)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?/i)
  return m ? m[1] : null
}

export function analyzeCommand(command: string): CommandAnalysis {
  const segments: Segment[] = splitSegments(command).map((raw) => ({ raw, argv: tokenize(raw) }))

  const credentialTargets: string[] = []
  const egressHosts: string[] = []
  const secretEnvRefs: string[] = []
  const dangerousFlags: string[] = []
  const signals: string[] = []

  let readsCredential = false
  let egress = false
  let dumpsEnv = false

  for (const segment of segments) {
    const argv = segment.argv
    if (argv.length === 0) continue
    const bin = basename(argv[0])

    if (EGRESS_BINS.has(bin)) {
      egress = true
      for (const arg of argv.slice(1)) {
        const host = extractHost(cleanToken(arg))
        if (host && !egressHosts.includes(host)) egressHosts.push(host)
      }
    }

    if (bin === "git" && argv.includes("push") && !argv.includes("--dry-run")) {
      egress = true
      if (!egressHosts.includes("git")) egressHosts.push("git")
    }
    if ((bin === "npm" && argv.includes("publish")) || (bin === "pip" && argv.includes("upload"))) {
      egress = true
      if (!egressHosts.includes("registry")) egressHosts.push("registry")
    }

    if (ENV_DUMP_BINS.has(bin) && argv.length === 1) {
      dumpsEnv = true
      signals.push("env-dump")
    }

    for (const flag of argv) {
      if (DANGEROUS_FLAGS.includes(flag)) dangerousFlags.push(flag)
    }

    for (const rawToken of argv) {
      const token = cleanToken(rawToken)
      if (!token) continue

      const candidate = token.startsWith("@") ? token.slice(1) : token
      const hit = credentialPathHit(candidate)
      if (hit && !credentialTargets.includes(hit.id)) {
        readsCredential = true
        credentialTargets.push(hit.id)
        signals.push("credential-path:" + hit.id)
      }

      const envRefPattern = /\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g
      let envRef: RegExpExecArray | null
      while ((envRef = envRefPattern.exec(token)) !== null) {
        const name = envRef[1]
        if (!SECRET_ENV_NAME.test(name)) continue
        if (!secretEnvRefs.includes(name)) {
          secretEnvRefs.push(name)
          signals.push("secret-env:" + name)
        }
      }

      if (looksLikeRandomToken(token)) {
        signals.push("high-entropy-literal")
      }

      if (isTemplatePath(token)) {
        signals.push("template-path")
      }
    }
  }

  let destructiveReason: string | null = null
  for (const rule of DESTRUCTIVE) {
    if (rule.re.test(command)) {
      destructiveReason = rule.reason
      signals.push("destructive")
      break
    }
  }

  const exfilNow = (readsCredential || dumpsEnv || secretEnvRefs.length > 0) && egress

  let risk: RiskLevel = "none"
  if (exfilNow || dangerousFlags.length > 0) risk = "critical"
  else if (readsCredential || dumpsEnv) risk = "high"
  else if (destructiveReason) risk = "medium"
  else if (egress) risk = "low"

  return {
    segments,
    readsCredential,
    credentialTargets,
    egress,
    egressHosts,
    secretEnvRefs,
    dumpsEnv,
    dangerousFlags,
    destructive: destructiveReason !== null,
    destructiveReason,
    risk,
    signals: Array.from(new Set(signals))
  }
}
