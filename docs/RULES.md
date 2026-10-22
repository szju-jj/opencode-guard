# Rule reference

Every tool call passes through the same four steps:

```
tool call
   -> path rules        (is the target a credential file?)
   -> command analysis  (what does the shell line actually do?)
   -> co-occurrence     (credential source AND outbound channel?)
   -> decision          (allow / ask / deny)  -> audit
```

A call that matches no rule is allowed and not logged. Everything else writes
one audit record.

## Rules

| ID | Fires on | Default | Tuning key |
| --- | --- | --- | --- |
| `G001` | `read` / `grep` / `glob` targeting a credential file | deny | `read_credential` |
| `G002` | `write` / `edit` / `patch` overwriting a credential file | deny | `write_credential` |
| `G003` | one command that both reaches a credential source and has an outbound channel | deny | `credential_egress` |
| `G004` | `cat .env` and friends, no egress | deny | `read_credential` |
| `G005` | `--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools` | deny | `dangerous_flag` |
| `G006` | `rm -rf ~`, `rm -rf /`, `DROP TABLE`, `git push --force`, `mkfs`, `dd of=/dev/` | ask | `destructive` |
| `G007` | any path listed under `extra_deny_paths` | deny | `deny_path` |
| `G008` | bare `env` / `printenv` / `set` | deny | `read_credential` |
| `G009` | secret env var leaving toward a host on `egress_allow` | allow + log | — |
| `G010` | `.env.example`, `.env.sample`, `*.template` | allow | — |
| `G100` | a secret already present in the tool output | redact | — |

`G003` is the only rule that inspects two things at once. That is deliberate:
any single-signal version of it produces enough false positives to get the tool
uninstalled within a day.

## Credential paths (24 classes)

Credential files are matched on the basename or on the normalised path, so they
are caught whether the agent uses a relative or absolute path.

**Local dev** `.env` and every `.env.*` variant, `.npmrc`, `.pypirc`, `.netrc`,
`.git-credentials`, `.htpasswd`

**Cloud** `.aws/credentials`, `.aws/config`, `.config/gcloud/application_default_credentials.json`,
`.azure/*`, `.config/gh/hosts.yml`, `service-account*.json`, `kubeconfig`,
`.docker/config.json`, `.s3cfg`, `.boto`

**Keys** `.ssh/id_*`, `*_rsa`, `*_ed25519`, `*.pem`, `*.p12`, `*.pfx`, `*.key`,
`*.keystore`, `*.jks`

**Data stores** `.pgpass`, `.my.cnf`, `wp-config.php`, `*.tfstate`

**Agents** `.config/opencode/auth.json`, `.codex/auth.json`

Anything ending in `.example` / `.sample` / `.template` / `.dist` is exempt —
those are templates, never live credentials.

## Secret patterns (21 formats)

Matched against tool output for `G100`, and used to redact command previews in
the audit log. The value itself is never stored: the log keeps a SHA-256 digest.

AWS access key, GitHub, GitLab, OpenAI / Anthropic, Slack, Google API, Stripe,
Hugging Face, Supabase, DigitalOcean, Shopify, SendGrid, Mailgun, Twilio,
Telegram bot, Discord webhook, Notion, Linear, PyPI, private key blocks, JWT.

Adding a format is one line in `SECRET_RULES` in `src/policy.ts`. Adding a
credential path is one regex in `CREDENTIAL_MATCHERS` plus one entry in
`CREDENTIAL_PATHS`.

## Decisions

| Value | Behaviour | Use when |
| --- | --- | --- |
| `deny` | call is blocked, error returned to the agent | the action has no legitimate use |
| `ask` | call is blocked until `opencode-guard approve <RULE>` grants a single use | real work needs it occasionally |
| `allow` | call proceeds and is logged if any signal fired | you want visibility without friction |

`deny` is never approvable. That is the whole difference between the two levels:
one is a wall, the other is a speed bump.

## Tuning

Start in `mode: learn`. Every rule still fires and is audited, nothing is
blocked. After a week, look at the audit:

```bash
node bin/guard.ts report
```

If a rule has zero hits, leave it alone. If it has hits you keep approving,
either move it to `allow` or widen `allow_paths`. If it has hits you are glad
about, keep it at `deny`.

## Known limits

- **Not a sandbox.** A determined agent can still exfiltrate through a tool this
  guard does not hook.
- **Shell parsing is heuristic.** Command substitution (`$(...)`), here-docs and
  encoded payloads are detected by pattern, not by evaluation. Unparsable
  commands fail open and are logged.
- **No DLP for binary files.** Only text output is scanned.
- **Per call, not per session.** There is no state machine tracking "this agent
  has been doing suspicious things for ten minutes".
