export type Decision = "allow" | "ask" | "deny"
export type Severity = "low" | "medium" | "high" | "critical"

export interface RuleHit {
  id: string
  label: string
}

const TEMPLATE_SUFFIX = /\.(example|sample|template|dist|md|txt)$/i

export function normalizePath(input: string): string {
  let p = input.trim().replace(/\\/g, "/")
  p = p.replace(/^\.\//, "")
  const home = process.env.HOME ?? process.env.USERPROFILE ?? ""
  if (home && p.startsWith(home)) p = p.slice(home.length)
  if (p.startsWith("~/")) p = p.slice(1)
  return p
}

export function basename(input: string): string {
  const p = normalizePath(input)
  const i = p.lastIndexOf("/")
  return i === -1 ? p : p.slice(i + 1)
}

export function isTemplatePath(filePath: string): boolean {
  const base = basename(filePath)
  return /\.env\.(?:example|sample|template|dist)$/i.test(base) || /\.(?:example|sample|template)$/i.test(base)
}

export function globToRegExp(glob: string): RegExp {
  let out = ""
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]
    if (c === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") {
          out += "(?:.*/)?"
          i += 2
        } else {
          out += ".*"
          i += 1
        }
      } else {
        out += "[^/]*"
      }
    } else if (c === "?") {
      out += "[^/]"
    } else if ("\\^$+{}()|[]".includes(c)) {
      out += "\\" + c
    } else {
      out += c
    }
  }
  return new RegExp("^" + out + "$")
}

export const CREDENTIAL_PATHS: RuleHit[] = [
  { id: "env-file", label: ".env file" },
  { id: "npmrc", label: ".npmrc (registry token)" },
  { id: "pypirc", label: ".pypirc (registry token)" },
  { id: "netrc", label: ".netrc" },
  { id: "git-credentials", label: "stored git credentials" },
  { id: "aws-credentials", label: "AWS credentials file" },
  { id: "aws-config", label: "AWS config (SSO cache)" },
  { id: "ssh-private-key", label: "SSH private key" },
  { id: "private-key-file", label: "private key / keystore" },
  { id: "service-account", label: "service account JSON" },
  { id: "kubeconfig", label: "kubeconfig" },
  { id: "docker-config", label: "docker registry auth" },
  { id: "terraform-state", label: "terraform state" },
  { id: "gcloud-adc", label: "gcloud application default credentials" },
  { id: "azure-profile", label: "azure CLI token cache" },
  { id: "gh-hosts", label: "GitHub CLI token store" },
  { id: "opencode-auth", label: "OpenCode provider keys" },
  { id: "codex-auth", label: "Codex auth file" },
  { id: "pgpass", label: "postgres password file" },
  { id: "mycnf", label: "mysql client config" },
  { id: "s3cfg", label: "s3cmd config" },
  { id: "boto", label: "boto config" },
  { id: "htpasswd", label: "htpasswd file" },
  { id: "wp-config", label: "WordPress config" }
]

const CREDENTIAL_MATCHERS: { id: string; re: RegExp }[] = [
  { id: "env-file", re: /(?:^|\/)\.env(?:\.[\w-]+)?$/i },
  { id: "npmrc", re: /(?:^|\/)\.npmrc$/i },
  { id: "pypirc", re: /(?:^|\/)\.pypirc$/i },
  { id: "netrc", re: /(?:^|\/)\.netrc$/i },
  { id: "git-credentials", re: /(?:^|\/)\.git-credentials$/i },
  { id: "aws-credentials", re: /(?:^|\/)\.aws\/credentials$/i },
  { id: "aws-config", re: /(?:^|\/)\.aws\/config$/i },
  { id: "ssh-private-key", re: /(?:^|\/)\.ssh\/(?:id_[^/]+|[^/]+_(?:rsa|ed25519|ecdsa|dsa))$/i },
  { id: "private-key-file", re: /\.(?:pem|p12|pfx|key|keystore|jks)$/i },
  { id: "service-account", re: /(?:^|\/)service[-_]?account[^/]*\.json$/i },
  { id: "kubeconfig", re: /(?:^|\/)\.kube\/config$/i },
  { id: "docker-config", re: /(?:^|\/)\.docker\/config\.json$/i },
  { id: "terraform-state", re: /\.tfstate(?:\.backup)?$/i },
  { id: "gcloud-adc", re: /(?:^|\/)\.config\/gcloud\/application_default_credentials\.json$/i },
  { id: "azure-profile", re: /(?:^|\/)\.azure\/(?:[^/]+\.json|[^/]+)$/i },
  { id: "gh-hosts", re: /(?:^|\/)\.config\/gh\/hosts\.ya?ml$/i },
  { id: "opencode-auth", re: /(?:^|\/)(?:\.config|\.local\/share)\/opencode\/auth\.json$/i },
  { id: "codex-auth", re: /(?:^|\/)\.codex\/auth\.json$/i },
  { id: "pgpass", re: /(?:^|\/)\.pgpass$/i },
  { id: "mycnf", re: /(?:^|\/)\.my\.cnf$/i },
  { id: "s3cfg", re: /(?:^|\/)\.s3cfg$/i },
  { id: "boto", re: /(?:^|\/)\.boto$/i },
  { id: "htpasswd", re: /(?:^|\/)\.htpasswd$/i },
  { id: "wp-config", re: /(?:^|\/)wp-config\.php$/i }
]

export function credentialPathHit(filePath: string, allowPaths: string[] = []): RuleHit | null {
  if (!filePath) return null
  const normalized = normalizePath(filePath)
  const base = basename(filePath)
  if (!base || TEMPLATE_SUFFIX.test(base)) return null
  for (const glob of allowPaths) {
    const re = globToRegExp(glob)
    if (re.test(normalized) || re.test(base)) return null
  }
  for (const m of CREDENTIAL_MATCHERS) {
    if (m.re.test(normalized) || m.re.test(base)) {
      const meta = CREDENTIAL_PATHS.find((p) => p.id === m.id)
      return { id: m.id, label: meta ? meta.label : m.id }
    }
  }
  return null
}

export const SECRET_RULES: { id: string; label: string; re: RegExp }[] = [
  { id: "aws-access-key", label: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "github-token", label: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: "gitlab-token", label: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { id: "openai-key", label: "OpenAI / Anthropic key", re: /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: "slack-token", label: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: "google-api-key", label: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "stripe-key", label: "Stripe key", re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g },
  { id: "huggingface-token", label: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { id: "supabase-token", label: "Supabase token", re: /\bsbp_[a-f0-9]{40}\b/g },
  { id: "digitalocean-token", label: "DigitalOcean token", re: /\bdop_v1_[a-f0-9]{64}\b/g },
  { id: "shopify-token", label: "Shopify access token", re: /\bshpat_[a-f0-9]{32}\b/g },
  { id: "sendgrid-key", label: "SendGrid key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: "mailgun-key", label: "Mailgun key", re: /\bkey-[0-9a-f]{32}\b/g },
  { id: "twilio-key", label: "Twilio key", re: /\bSK[0-9a-f]{32}\b/g },
  { id: "telegram-bot", label: "Telegram bot token", re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { id: "discord-webhook", label: "Discord webhook", re: /discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,}/g },
  { id: "notion-token", label: "Notion integration token", re: /\bsecret_[A-Za-z0-9]{43}\b/g },
  { id: "linear-token", label: "Linear API key", re: /\blin_api_[A-Za-z0-9]{40}\b/g },
  { id: "pypi-token", label: "PyPI token", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g },
  { id: "private-key-block", label: "private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: "jwt", label: "JWT", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g }
]

export function scanSecrets(text: string): { id: string; label: string; preview: string }[] {
  const found: { id: string; label: string; preview: string }[] = []
  for (const rule of SECRET_RULES) {
    rule.re.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = rule.re.exec(text)) !== null) {
      const value = m[0]
      found.push({ id: rule.id, label: rule.label, preview: value.slice(0, 4) + "..." + value.slice(-4) })
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++
    }
  }
  return found
}

export function redactSecrets(text: string): { text: string; hits: string[] } {
  let out = text
  const hits: string[] = []
  for (const rule of SECRET_RULES) {
    rule.re.lastIndex = 0
    out = out.replace(rule.re, () => {
      hits.push(rule.id)
      return "[REDACTED:" + rule.id + "]"
    })
  }
  return { text: out, hits }
}

export function shannonEntropy(value: string): number {
  if (!value) return 0
  const counts = new Map<string, number>()
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / value.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

export function looksLikeRandomToken(value: string): boolean {
  if (value.length < 32) return false
  if (!/^[A-Za-z0-9+/=_-]+$/.test(value)) return false
  if (!/[0-9]/.test(value) || !/[A-Za-z]/.test(value)) return false
  return shannonEntropy(value) >= 4.2
}
