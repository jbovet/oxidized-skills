# oxidized-skills

Security auditing for AI agent skills. A Rust CLI tool that scans skill directories for dangerous patterns, prompt injection, supply chain risks, and more.

## Features

- **Bash dangerous pattern scanner** — 19 regex rules across 8 categories (RCE, credential exfiltration, destructive ops, reverse shells, privilege escalation, unsafe variable expansion, outbound network)
- **Prompt injection scanner** — 19 patterns detecting instruction override, role manipulation, jailbreak attempts, data exfiltration, code injection, system prompt extraction, delimiter injection, fictional framing, and priority override; automatically skips benign boilerplate files (LICENSE, CHANGELOG, NOTICE, AUTHORS, etc.)
- **Frontmatter auditor** — 15 rules validating `SKILL.md` structure: missing file, reserved brand names, XML injection in fields, name format, field length limits, vague names, body length, Windows paths, third-person description, trigger context, time-sensitive content, and unscoped `Bash` in `allowed-tools`
- **Package install auditor** — Detects `npm install`, `bun add`, `pip install` without explicit registry, unpinned `@latest` versions, and unapproved registries
- **Shell script linting** — shellcheck wrapper, automatically skipped when tool is not installed
- **Secret scanning** — gitleaks wrapper, automatically skipped when tool is not installed
- **Static analysis** — semgrep wrapper with 30-second timeout (gracefully skips when network is blocked or tool is unavailable)
- **Collection directory support** — `audit-all` audits every skill in a directory at once with a summary table; `audit` detects collection directories and shows helpful hints
- **Multiple output formats** — Pretty terminal, JSON, and SARIF 2.1.0 (compatible with GitHub Code Scanning)
- **Suppression system** — Inline `# audit:ignore` (or `# oxidized-skills:ignore`) trailing comments and `.oxidized-skills-ignore` file with ticket tracking
- **Configurable allowlists** — Registry allowlist enforced for `pkg/F3-registry`; domain allowlist enforced for `bash/CAT-H1` (outbound HTTP to approved domains is suppressed)
- **Parallel scanning** — Uses rayon for concurrent scanning across all scanners
- **Zero runtime dependencies** — Core scanners are pure Rust regex, no external tools required
- **Single binary** — Static binary, easy to integrate into CI/CD pipelines

## Quick Start

### Build from source

```bash
cargo build --release
./target/release/oxidized-skills audit ./path/to/skill
```

### Install from crates.io

```bash
cargo install oxidized-skills
```

## Usage

### Audit a single skill directory

```bash
# Pretty terminal output (default)
oxidized-skills audit ./my-skill

# JSON output
oxidized-skills audit ./my-skill --format json

# SARIF output (for GitHub Code Scanning)
oxidized-skills audit ./my-skill --format sarif --output report.sarif

# Strict mode (warnings become errors)
oxidized-skills audit ./my-skill --strict

# Custom config
oxidized-skills audit ./my-skill --config ./my-config.toml
```

### Audit all skills in a collection directory

```bash
# Audits every subdirectory that contains a SKILL.md, then prints a summary
oxidized-skills audit-all ~/skills

# JSON output per skill
oxidized-skills audit-all ~/skills --format json

# Strict mode across all skills
oxidized-skills audit-all ~/skills --strict
```

If you accidentally run `audit` on a collection directory, the tool detects it and shows a helpful error with the correct commands to run.

### Other commands

```bash
# Check which external tools are available
oxidized-skills check-tools

# List all built-in rules
oxidized-skills list-rules

# Get details about a specific rule
oxidized-skills explain bash/CAT-A1
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Audit passed (all skills passed) |
| 1 | Audit failed (errors found, or warnings in strict mode) |
| 2 | Runtime error (bad config, missing path, collection dir passed to `audit`, etc.) |

## Scanners

### Core scanners (no external tools required)

| Scanner | What it checks |
|---------|---------------|
| `bash_patterns` | 19 regex rules for dangerous shell patterns |
| `prompt` | 19 patterns for prompt injection in SKILL.md |
| `package_install` | Package manager calls without pinned registry |
| `frontmatter` | 15 rules for SKILL.md structure and allowed-tools safety |

### External tool wrappers (auto-skipped when tool not on PATH)

| Scanner | Tool required | What it checks | Notes |
|---------|--------------|----------------|-------|
| `shellcheck` | `shellcheck` | Shell script linting | |
| `secrets` | `gitleaks` | Hardcoded secrets and credentials | |
| `semgrep` | `semgrep` | Static analysis rules | |

Run `oxidized-skills check-tools` to see which external tools are available in your environment.

## Built-in Rules

### Bash Patterns (Categories A-H)

| Rule | Severity | Description |
|------|----------|-------------|
| `bash/CAT-A1` | Error | Pipe to shell (RCE) |
| `bash/CAT-A2` | Error | eval of dynamic content |
| `bash/CAT-A3` | Error | Source from URL |
| `bash/CAT-A4` | Error | Download to temp then execute |
| `bash/CAT-B1` | Error | Access to `$HOME/.ssh/` or `~/.ssh/` |
| `bash/CAT-B2` | Error | Access to `$HOME/.aws/` or `~/.aws/` |
| `bash/CAT-B3` | Error | Access to `$HOME/.kube/config` or `~/.kube/config` |
| `bash/CAT-B4` | Error | Env var (`$VAR` or `${VAR}`) sent as HTTP POST body |
| `bash/CAT-B5` | Error | env output piped to network tool |
| `bash/CAT-C1` | Error | rm -rf on home/root directory |
| `bash/CAT-C2` | Error | dd disk wipe |
| `bash/CAT-D1` | Error | Netcat reverse shell |
| `bash/CAT-D2` | Error | Bash /dev/tcp reverse shell |
| `bash/CAT-D3` | Error | Python socket reverse shell |
| `bash/CAT-E1` | Warning | sudo shell escalation |
| `bash/CAT-E2` | Warning | SUID bit escalation |
| `bash/CAT-G1` | Warning | rm -rf with unquoted variable (including at end of line) |
| `bash/CAT-G2` | Warning | Shell invoked with variable arg |
| `bash/CAT-H1` | Info | Outbound HTTP call detected |
| `bash/read-error` | Info | Shell file could not be read (check permissions / encoding) |

### Prompt Injection (19 patterns)

| Rule | Severity | Description |
|------|----------|-------------|
| `prompt/override-ignore` | Error | "ignore previous instructions" |
| `prompt/override-disregard` | Error | "disregard previous instructions" |
| `prompt/override-forget` | Error | "forget everything you know" |
| `prompt/override-priority` | Warning | Priority override keywords (OVERRIDE:, NEW TASK:) |
| `prompt/role-escalation` | Error | Assigns admin/root identity |
| `prompt/role-impersonation` | Warning | "pretend to be a different AI" |
| `prompt/restrictions-bypass` | Error | "act without restrictions" |
| `prompt/jailbreak-dan` | Error | DAN / "do anything now" mode |
| `prompt/jailbreak-devmode` | Error | Developer mode activation |
| `prompt/jailbreak-bypass` | Error | Safety/security filter bypass |
| `prompt/jailbreak-fiction` | Warning | Fictional/hypothetical framing jailbreak |
| `prompt/exfil-send` | Warning | Send data to external endpoint |
| `prompt/exfil-read` | Warning | Read passwords/secrets/tokens |
| `prompt/exfil-sysPrompt` | Error | System prompt extraction attempt |
| `prompt/inject-execute` | Error | Arbitrary code execution instruction |
| `prompt/inject-unvalidated` | Error | Run without validation instruction |
| `prompt/inject-delimiter` | Error | Model context delimiter injection |
| `prompt/perm-delete-all` | Warning | Mass deletion instruction (`rm -rf /`, `delete all`, `rm *`) |
| `prompt/perm-sudo` | Warning | Privilege escalation (sudo/root) |

### Frontmatter (15 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| `frontmatter/missing-skill-md` | Error | SKILL.md not found in skill root |
| `frontmatter/xml-in-frontmatter` | Error | XML/HTML angle brackets or HTML entities (`&lt;`, `&#60;`, etc.) in `name` or `description` field |
| `frontmatter/name-reserved-word` | Error | Name contains reserved word `claude` or `anthropic` |
| `frontmatter/readme-in-skill` | Warning | README.md present — use the description field instead |
| `frontmatter/invalid-name-format` | Warning | Name has uppercase letters, spaces, or underscores |
| `frontmatter/name-too-long` | Warning | Name exceeds 64 characters |
| `frontmatter/name-too-vague` | Warning | Name uses a vague generic term (helper, utils, tools, data, files, documents) |
| `frontmatter/description-missing` | Warning | Description field absent or empty |
| `frontmatter/description-too-long` | Warning | Description exceeds 1024 characters |
| `frontmatter/description-not-third-person` | Warning | Description uses first or second person instead of third person |
| `frontmatter/skill-body-too-long` | Warning | SKILL.md exceeds 500 lines |
| `frontmatter/windows-path` | Warning | Windows-style backslash path in SKILL.md — use forward slashes |
| `frontmatter/bare-bash-tool` | Warning | Unscoped `Bash` in `allowed-tools` grants unrestricted shell access |
| `frontmatter/description-no-trigger` | Info | Description doesn't include "when to use" trigger context |
| `frontmatter/time-sensitive-content` | Warning | Body contains date-based conditional that will become stale (e.g. "before 2025") |

### Package Install (5 rules)

| Rule | Severity | Description |
|------|----------|-------------|
| `pkg/F1-npm` | Warning | npm install without --registry |
| `pkg/F1-bun` | Warning | bun add without --registry |
| `pkg/F1-pip` | Warning | pip install without --index-url |
| `pkg/F2-unpinned` | Warning | @latest unpinned version |
| `pkg/F3-registry` | Warning | Unapproved registry URL |

## Configuration

### `oxidized-skills.toml`

Place in your project root or pass via `--config`:

```toml
[allowlist]
# Registries checked against pkg/F3-registry findings
registries = [
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
]

# Domains approved for outbound HTTP — bash/CAT-H1 is suppressed for these (exact match or subdomain)
domains = [
    "registry.npmjs.org",
    "npmjs.org",
    "github.com",
    "githubusercontent.com",
    "pypi.org",
]

[strict]
enabled = false

[scanners]
shellcheck = true
semgrep = true
secrets = true
prompt = true
bash_patterns = true
package_install = true
frontmatter = true
```

### `.oxidized-skills-ignore`

Place in the skill directory to suppress specific findings:

```toml
[[suppress]]
rule = "bash/CAT-H1"
file = "scripts/install.sh"
reason = "Approved download from official registry"
ticket = "PROJ-1234"

[[suppress]]
rule = "bash/CAT-D2"
file = "scripts/debug.sh"
lines = "156-174"
reason = "Perl portable timeout uses bash /dev/tcp, not a reverse shell"
ticket = "PROJ-5678"
```

### Inline suppression

Add `# audit:ignore` or `# oxidized-skills:ignore` as a **trailing comment** on any line in a shell script:

```bash
curl https://approved-source.example.com/tool.tar.gz -o /tmp/tool.tar.gz  # audit:ignore
wget https://approved-source.example.com/tool.tar.gz                       # oxidized-skills:ignore
```

> **Note:** The marker must appear as a real trailing shell comment. A suppression string inside a quoted argument (e.g. `echo "# audit:ignore" | bash`) is **not** treated as a suppression.

## Docker

### Dev image (local use — recommended for Apple Silicon)

`Dockerfile.dev` builds natively on any architecture (amd64 or arm64) — no cross-compilation, no musl. It includes all external scanners for full local coverage.

```bash
just docker-dev-build                         # build once
just docker-dev ~/skills/agent-browser # audit a single skill
just docker-dev-all ~/skills           # audit all skills
```

Or with plain Docker:

```bash
docker build -f Dockerfile.dev -t oxidized-skills:dev .
docker run --rm -v ~/skills:/skills:ro oxidized-skills:dev audit-all /skills
```

### Release images

Three image variants are published to GitHub Container Registry on every release.

| Image | Base | External tools | Size | Tag |
|-------|------|----------------|------|-----|
| slim | `scratch` | None (core scanners only) | ~8 MB | `:slim`, `:latest`, `:<version>` |
| full | `python:3.12-slim` | `shellcheck` + `gitleaks` + `semgrep` | ~245 MB | `:full`, `:<version>-full` |

> The `full` image includes `semgrep`, which fetches rules from `semgrep.dev` on first run. In network-restricted environments it will time out after 30 s and be skipped gracefully. To pre-cache rules, mount a local semgrep config with `-v ./semgrep.yml:/semgrep.yml -e SEMGREP_RULES=/semgrep.yml`.

### Important: mount your skills directory

The container has no access to your host filesystem unless you explicitly mount it with `-v`.
Always mount the skill (or skills collection) as a volume and pass the **container path** to the command:

```
-v /host/path:/container/path:ro
```

### Pull and run

```bash
# ── slim image (core scanners only) ──────────────────────────────────────────
docker pull ghcr.io/jbovet/oxidized-skills:slim

# Audit a single skill directory
docker run --rm \
  -v /path/to/skill:/skill:ro \
  ghcr.io/jbovet/oxidized-skills:slim audit /skill

# Audit all skills in a collection directory
docker run --rm \
  -v ~/skills:/skills:ro \
  ghcr.io/jbovet/oxidized-skills:slim audit-all /skills

# ── full image (shellcheck + gitleaks) ───────────────────────────────────────
docker pull ghcr.io/jbovet/oxidized-skills:full

docker run --rm \
  -v /path/to/skill:/skill:ro \
  ghcr.io/jbovet/oxidized-skills:full audit /skill

docker run --rm \
  -v ~/skills:/skills:ro \
  ghcr.io/jbovet/oxidized-skills:full audit-all /skills

```

> **Common mistake:** `docker run oxidized-skills audit ~/skills` will fail with
> `Error: path does not exist` — the container cannot see your home directory.
> Always use `-v ~/skills:/skills:ro` and pass `/skills` as the argument.

### Write SARIF output to a file

```bash
docker run --rm \
  -v /path/to/skill:/skill:ro \
  -v "$(pwd)":/out \
  ghcr.io/jbovet/oxidized-skills:full \
  audit /skill --format sarif --output /out/report.sarif
```

### Build locally

```bash
just docker-build       # slim (~10 MB, scratch base)
just docker-build-full  # full (~245MB MB, debian-slim + shellcheck + gitleaks)
just docker-build-all   # all three

# Run against a local skill directory
just docker-run ./my-skill        # slim
just docker-run-full ./my-skill   # includes semgrep

# Run against a collection directory
just docker-run-all ~/skills
```

### Use in CI (GitHub Actions)

```yaml
- name: Audit skills
  run: |
    docker run --rm \
      -v ${{ github.workspace }}/skills:/skills:ro \
      ghcr.io/jbovet/oxidized-skills:full audit-all /skills
```

## Development

Requires [just](https://github.com/casey/just).

```bash
just          # fmt → lint → test
just fmt      # cargo fmt (fix in place)
just lint     # cargo clippy -- -D warnings
just test     # cargo test
just ci       # fmt-check + lint + test (mirrors CI)
```

### Pre-commit hook

```bash
just install-hooks
```

Installs `.githooks/pre-commit` into `.git/hooks/`, which runs `fmt-check`, `clippy`, and `cargo test` on every commit.

## License

MIT
