import { createHash } from "node:crypto"
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs"
import { dirname } from "node:path"

export interface AuditEntry {
  ts: string
  seq: number
  session: string
  tool: string
  rule: string
  label: string
  intended: string
  decision: string
  severity: string
  target: string
  digest: string
  signals: string[]
}

export interface AuditRecord extends AuditEntry {
  prev: string
  hash: string
}

const GENESIS = "genesis"
const cache = new Map<string, { seq: number; hash: string }>()

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex")
}

function canonical(entry: AuditEntry): string {
  return [
    entry.ts,
    entry.seq,
    entry.session,
    entry.tool,
    entry.rule,
    entry.intended,
    entry.decision,
    entry.severity,
    entry.target,
    entry.digest,
    entry.signals.join(",")
  ].join("|")
}

function loadState(path: string): { seq: number; hash: string } {
  const cached = cache.get(path)
  if (cached) return cached
  if (!existsSync(path)) {
    const fresh = { seq: 0, hash: GENESIS }
    cache.set(path, fresh)
    return fresh
  }
  const lines = readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean)
  if (lines.length === 0) {
    const fresh = { seq: 0, hash: GENESIS }
    cache.set(path, fresh)
    return fresh
  }
  try {
    const last = JSON.parse(lines[lines.length - 1]) as AuditRecord
    const state = { seq: last.seq ?? lines.length, hash: last.hash ?? GENESIS }
    cache.set(path, state)
    return state
  } catch {
    const state = { seq: lines.length, hash: GENESIS }
    cache.set(path, state)
    return state
  }
}

export function appendAudit(path: string, entry: Omit<AuditEntry, "ts" | "seq" | "digest"> & { digest?: string }): AuditRecord | null {
  try {
    const state = loadState(path)
    const seq = state.seq + 1
    const record: AuditEntry = {
      ts: new Date().toISOString(),
      seq,
      session: entry.session,
      tool: entry.tool,
      rule: entry.rule,
      label: entry.label,
      intended: entry.intended,
      decision: entry.decision,
      severity: entry.severity,
      target: entry.target,
      digest: entry.digest ?? sha256(entry.target),
      signals: entry.signals ?? []
    }
    const hash = sha256(state.hash + "|" + canonical(record))
    const line: AuditRecord = { ...record, prev: state.hash, hash }
    mkdirSync(dirname(path), { recursive: true })
    appendFileSync(path, JSON.stringify(line) + "\n", "utf8")
    cache.set(path, { seq, hash })
    return line
  } catch {
    return null
  }
}

export interface VerifyResult {
  ok: boolean
  count: number
  brokenAt: number | null
  reason: string | null
}

export function verifyChain(path: string): VerifyResult {
  if (!existsSync(path)) return { ok: true, count: 0, brokenAt: null, reason: "audit file does not exist yet" }
  const lines = readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean)
  let prev = GENESIS
  for (let i = 0; i < lines.length; i++) {
    let record: AuditRecord
    try {
      record = JSON.parse(lines[i]) as AuditRecord
    } catch {
      return { ok: false, count: lines.length, brokenAt: i + 1, reason: "line is not valid JSON" }
    }
    if (record.prev !== prev) {
      return { ok: false, count: lines.length, brokenAt: i + 1, reason: "prev hash does not match previous record" }
    }
    const { prev: _prev, hash, ...rest } = record
    const expected = sha256(prev + "|" + canonical(rest as AuditEntry))
    if (expected !== hash) {
      return { ok: false, count: lines.length, brokenAt: i + 1, reason: "record hash does not match content" }
    }
    prev = hash
  }
  return { ok: true, count: lines.length, brokenAt: null, reason: null }
}

export function summarize(path: string): {
  total: number
  blocked: number
  asked: number
  redacted: number
  allowed: number
  byRule: Record<string, number>
} {
  const result = { total: 0, blocked: 0, asked: 0, redacted: 0, allowed: 0, byRule: {} as Record<string, number> }
  if (!existsSync(path)) return result
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    if (!line.trim()) continue
    try {
      const record = JSON.parse(line) as AuditRecord
      result.total++
      if (record.decision === "deny") result.blocked++
      else if (record.decision === "ask") result.asked++
      else if (record.decision === "redact") result.redacted++
      else result.allowed++
      result.byRule[record.rule] = (result.byRule[record.rule] ?? 0) + 1
    } catch {
      continue
    }
  }
  return result
}
