---
name: auditing-skills
description: Scans AI agent skill directories for dangerous bash patterns, prompt injection, supply chain risks, and SKILL.md structure violations. Use when reviewing or validating a skill before deployment.
allowed-tools:
  - Bash(oxidized-skills)
  - Read
  - Glob
---

# Security Auditing for Agent Skills

Run `oxidized-skills audit <path>` to scan a skill directory. The tool checks shell scripts, SKILL.md frontmatter, prompt injection vectors, and package install patterns.

## Quick start

```bash
oxidized-skills audit ./path/to/skill
```

## Output formats

```bash
# Human-readable terminal output (default)
oxidized-skills audit ./skill

# Machine-readable JSON
oxidized-skills audit ./skill --format json

# SARIF 2.1.0 for GitHub Code Scanning
oxidized-skills audit ./skill --format sarif --output report.sarif
```

## Strict mode

Treat warnings as errors (exit code 1 on any warning):

```bash
oxidized-skills audit ./skill --strict
```

## Custom configuration

```bash
oxidized-skills audit ./skill --config ./oxidized-skills.toml
```

## Utility commands

```bash
# Check which external tools are available (shellcheck, gitleaks, semgrep)
oxidized-skills check-tools

# List all built-in rules with severity and description
oxidized-skills list-rules

# Explain a specific rule with remediation guidance
oxidized-skills explain bash/CAT-A1
```

## Interpreting results

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Audit passed |
| 1 | Audit failed (errors found, or warnings in strict mode) |
| 2 | Runtime error (bad config, missing path) |

Severity levels:

| Level | Meaning |
|-------|---------|
| Error | Must fix before deployment |
| Warning | Should fix, becomes error in strict mode |
| Info | Informational, no action required |

## Scanner coverage

Core scanners (no external tools required):

- **bash_patterns** — 19 regex rules for RCE, credential exfiltration, destructive ops, reverse shells, privilege escalation
- **prompt** — 19 patterns for instruction override, role manipulation, jailbreak attempts, data exfiltration
- **frontmatter** — 15 rules for SKILL.md structure, name format, description quality, allowed-tools safety
- **package_install** — package manager calls without pinned registry, unpinned versions

External tool wrappers (auto-skipped when not installed):

- **shellcheck** — shell script linting
- **secrets** — hardcoded secrets via gitleaks
- **semgrep** — static analysis rules
