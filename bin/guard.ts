#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { summarize, verifyChain } from "../src/audit.ts"
import { createContext } from "../src/index.ts"
import { grantApproval, listApprovals } from "../src/approvals.ts"

const argv = process.argv.slice(2)
const command = argv[0] ?? "help"
const cwd = process.cwd()
const ctx = createContext(cwd)
const auditPath = ctx.auditPath ?? join(cwd, ".opencode", "guard-audit.jsonl")

const paint = (code: number, text: string): string => (process.stdout.isTTY ? `\x1b[${code}m${text}\x1b[0m` : text)
const red = (t: string) => paint(31, t)
const green = (t: string) => paint(32, t)
const yellow = (t: string) => paint(33, t)
const dim = (t: string) => paint(90, t)
const bold = (t: string) => paint(1, t)

function printVerify(): void {
  const result = verifyChain(auditPath)
  console.log(bold("audit chain"))
  console.log("  file    " + auditPath)
  console.log("  records " + result.count)
  if (result.ok) {
    console.log("  status  " + green("intact") + dim(result.reason ? ` (${result.reason})` : ""))
    return
  }
  console.log("  status  " + red("TAMPERED") + ` at record #${result.brokenAt}: ${result.reason}`)
  process.exitCode = 1
}

function printReport(): void {
  const stats = summarize(auditPath)
  console.log(bold("guard report"))
  console.log(
    "  total " +
      stats.total +
      "  " +
      red("blocked " + stats.blocked) +
      "  " +
      yellow("asked " + stats.asked) +
      "  " +
      yellow("redacted " + stats.redacted) +
      "  " +
      green("allowed " + stats.allowed)
  )
  const rules = Object.entries(stats.byRule).sort((a, b) => b[1] - a[1])
  for (const [rule, count] of rules) console.log("  " + rule.padEnd(6) + String(count).padStart(4))
  if (!existsSync(auditPath)) return
  const lines = readFileSync(auditPath, "utf8").split(/\r?\n/).filter(Boolean).slice(-8)
  if (lines.length === 0) return
  console.log(bold("\nlast events"))
  for (const line of lines) {
    try {
      const record = JSON.parse(line) as Record<string, any>
      const mark =
        record.decision === "deny"
          ? red("DENY  ")
          : record.decision === "ask"
            ? yellow("ASK   ")
            : record.decision === "redact"
              ? yellow("REDACT")
              : green("ALLOW ")
      console.log(`  ${mark} ${String(record.rule).padEnd(5)} ${String(record.tool).padEnd(6)} ${dim(String(record.target).slice(0, 70))}`)
    } catch {
      console.log("  " + red("unreadable record"))
    }
  }
}

function printApprove(): void {
  const rule = argv[1]
  if (!rule || !/^G\d{3}$/.test(rule)) {
    console.log("usage: opencode-guard approve <RULE_ID> [--uses N] [--ttl SECONDS]")
    process.exitCode = 1
    return
  }
  const usesIndex = argv.indexOf("--uses")
  const ttlIndex = argv.indexOf("--ttl")
  const uses = usesIndex > -1 ? Number(argv[usesIndex + 1]) || 1 : 1
  const ttl = ttlIndex > -1 ? (Number(argv[ttlIndex + 1]) || 600) * 1000 : undefined
  const approval = grantApproval(ctx.approvalsPath, rule, uses, ttl)
  const minutes = Math.max(1, Math.round((approval.expires - Date.now()) / 60000))
  console.log(green("approved") + ` ${rule} x${approval.uses}, expires in ${minutes} min`)
  console.log(dim("  " + ctx.approvalsPath))
}

function printApprovals(): void {
  const list = listApprovals(ctx.approvalsPath)
  if (list.length === 0) {
    console.log(dim("no active approvals"))
    return
  }
  for (const item of list) {
    const minutes = Math.max(1, Math.round((item.expires - Date.now()) / 60000))
    console.log(`  ${item.rule}  uses=${item.uses}  expires in ${minutes} min`)
  }
}

function printHelp(): void {
  console.log(bold("opencode-guard"))
  console.log("  verify              check the audit hash chain")
  console.log("  report              summarize decisions and show recent events")
  console.log("  approve <RULE>      allow one more occurrence of an ask-level rule")
  console.log("  approvals           list active one-time approvals")
  console.log(dim("\n  config: guard.yaml in " + cwd))
}

switch (command) {
  case "verify":
    printVerify()
    break
  case "report":
    printReport()
    break
  case "approve":
    printApprove()
    break
  case "approvals":
    printApprovals()
    break
  default:
    printHelp()
}
