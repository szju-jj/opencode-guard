import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { dirname } from "node:path"

export interface Approval {
  rule: string
  uses: number
  expires: number
  note?: string
}

const DEFAULT_TTL_MS = 10 * 60_000

function read(path: string): Approval[] {
  if (!existsSync(path)) return []
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"))
    if (!Array.isArray(parsed)) return []
    const now = Date.now()
    return parsed.filter((item): item is Approval => {
      return Boolean(item) && typeof item.rule === "string" && typeof item.uses === "number" && item.expires > now
    })
  } catch {
    return []
  }
}

function write(path: string, approvals: Approval[]): void {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(approvals, null, 2) + "\n", "utf8")
}

export function grantApproval(path: string, rule: string, uses = 1, ttlMs = DEFAULT_TTL_MS): Approval {
  const approvals = read(path)
  const existing = approvals.find((item) => item.rule === rule)
  const expires = Date.now() + ttlMs
  if (existing) {
    existing.uses += uses
    existing.expires = expires
    write(path, approvals)
    return existing
  }
  const approval: Approval = { rule, uses, expires }
  approvals.push(approval)
  write(path, approvals)
  return approval
}

export function consumeApproval(path: string, rule: string): boolean {
  const approvals = read(path)
  const target = approvals.find((item) => item.rule === rule && item.uses > 0)
  if (!target) return false
  target.uses -= 1
  write(
    path,
    approvals.filter((item) => item.uses > 0)
  )
  return true
}

export function listApprovals(path: string): Approval[] {
  return read(path)
}
