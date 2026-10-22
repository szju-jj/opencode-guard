import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { DEFAULT_CONFIG } from "./engine.ts"
import type { GuardConfig } from "./engine.ts"
import type { Decision } from "./policy.ts"

const DECISIONS = new Set<Decision>(["allow", "ask", "deny"])
const RULE_KEYS = new Set(Object.keys(DEFAULT_CONFIG.rules))

function stripComment(line: string): string {
  let quote: string | null = null
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote) {
      if (c === quote) quote = null
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      continue
    }
    if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i)
  }
  return line
}

function unquote(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length >= 2) {
    const first = trimmed[0]
    const last = trimmed[trimmed.length - 1]
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) return trimmed.slice(1, -1)
  }
  return trimmed
}

// Deliberately small YAML subset: top-level scalars, block lists, and one
// level of nested maps. That is all guard.yaml needs, and it keeps the
// package dependency-free.
export function parseSimpleYaml(source: string): Record<string, any> {
  const root: Record<string, any> = {}
  let blockKey: string | null = null

  for (const rawLine of source.split(/\r?\n/)) {
    const line = stripComment(rawLine)
    if (!line.trim()) continue

    const indent = line.match(/^ */)?.[0].length ?? 0
    const text = line.trim()

    if (text.startsWith("- ")) {
      if (!blockKey) continue
      if (!Array.isArray(root[blockKey])) root[blockKey] = []
      root[blockKey].push(unquote(text.slice(2)))
      continue
    }

    const match = text.match(/^([\w.-]+):\s*(.*)$/)
    if (!match) continue
    const key = match[1]
    const value = match[2]

    if (indent === 0) {
      blockKey = key
      if (value.trim() === "") {
        if (root[key] === null || typeof root[key] !== "object") root[key] = {}
      } else {
        root[key] = unquote(value)
      }
      continue
    }

    if (!blockKey) continue
    const parent = root[blockKey]
    if (parent && typeof parent === "object" && !Array.isArray(parent)) {
      parent[key] = unquote(value)
    }
  }

  return root
}

export function loadConfig(directory: string, explicitPath?: string): GuardConfig {
  const config: GuardConfig = structuredClone(DEFAULT_CONFIG)
  const path = explicitPath ?? join(directory, "guard.yaml")
  if (!existsSync(path)) return config

  const parsed = parseSimpleYaml(readFileSync(path, "utf8"))

  if (parsed.mode === "learn" || parsed.mode === "enforce") config.mode = parsed.mode
  if (typeof parsed.audit === "string") config.audit = parsed.audit
  if (parsed.audit === null) config.audit = null
  if (Array.isArray(parsed.allow_paths)) config.allowPaths = parsed.allow_paths.map(String)
  if (Array.isArray(parsed.extra_deny_paths)) config.extraDenyPaths = parsed.extra_deny_paths.map(String)
  if (Array.isArray(parsed.egress_allow)) config.egressAllow = parsed.egress_allow.map(String)
  if (typeof parsed.mask_env === "string") config.maskEnv = parsed.mask_env === "true"

  if (parsed.rules && typeof parsed.rules === "object") {
    for (const [key, value] of Object.entries(parsed.rules)) {
      if (!RULE_KEYS.has(key)) continue
      if (typeof value !== "string" || !DECISIONS.has(value as Decision)) continue
      config.rules[key as keyof GuardConfig["rules"]] = value as Decision
    }
  }

  return config
}
