# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-02-27

### Added
- **Feature**: Enhanced audit output with indication of disabled/missing scanners.
- **Infrastructure**: Added `dependabot.yml` and updated CI for multi-OS testing.
- **Docs**: Added support guidelines and expanded auditing skills documentation.

### Changed
- **Optimization**: Significant performance improvements for Semgrep scanner using local rules and configuration.

### Fixed
- **Fix**: Resolved `Default` trait lints and Semgrep configuration loading errors.

### Added

- **Bash pattern scanner** — 19 regex rules across 8 categories (RCE, credential exfiltration, destructive ops, reverse shells, privilege escalation, unsafe variable expansion, outbound network)
- **Prompt injection scanner** — 19 patterns for instruction override, role manipulation, jailbreak attempts, data exfiltration, code injection, system prompt extraction, delimiter injection, fictional framing, and priority override; auto-skips benign boilerplate files
- **Frontmatter auditor** — 15 rules validating `SKILL.md` structure: missing file, reserved brand names, XML injection, name format, field length limits, vague names, body length, Windows paths, third-person description, trigger context, time-sensitive content, and unscoped `Bash` in `allowed-tools`
- **Package install auditor** — detects `npm install`, `bun add`, `pip install` without explicit registry, unpinned `@latest` versions, and unapproved registries
- **Shell script linting** — `shellcheck` wrapper, auto-skipped when tool is not installed
- **Secret scanning** — `gitleaks` wrapper, auto-skipped when tool is not installed
- **Static analysis** — `semgrep` wrapper with 30-second timeout, gracefully skips when network is blocked or tool unavailable
- **`audit-all` command** — audits every skill in a collection directory with a summary table
- **Multiple output formats** — pretty terminal, JSON, and SARIF 2.1.0 (compatible with GitHub Code Scanning)
- **Suppression system** — inline `# audit:ignore` trailing comments and `.oxidized-skills-ignore` file with ticket tracking
- **Configurable allowlists** — registry allowlist for `pkg/F3-registry`; domain allowlist for `bash/CAT-H1`
- **`list-rules` command** — lists all built-in rules with severity and description
- **`explain` command** — shows details and remediation guidance for a specific rule
- **`check-tools` command** — reports which external tools are available on PATH
- **Parallel scanning** — concurrent scanner execution via `rayon`
- **Docker images** — slim (~8 MB, scratch base) and full (~245 MB, includes shellcheck + gitleaks + semgrep) variants published to GHCR
- **CI/CD** — GitHub Actions workflows for CI (test + lint + fmt) and release (binaries + Docker images)

[Unreleased]: https://github.com/jbovet/oxidized-skills/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jbovet/oxidized-skills/releases/tag/v0.1.1
[0.1.0]: https://github.com/jbovet/oxidized-skills/releases/tag/v0.1.0
